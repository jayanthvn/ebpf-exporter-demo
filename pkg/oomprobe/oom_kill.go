package oomprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dropbox/goebpf"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	docker_client "docker.io/go-docker"
	docker_types "docker.io/go-docker/api/types"
)

var (
	ErrProgramNotFound        = errors.New("program not found")
	ErrMapNotFound            = errors.New("map not found")
	kubernetesCounterVec      *prometheus.CounterVec
	prometheusContainerLabels = map[string]string{
		"io.kubernetes.container.name": "container_name",
		"io.kubernetes.pod.namespace":  "namespace",
		"io.kubernetes.pod.name":       "pod_name",
	}
	metricsAddr string
)

func init() {

	flag.StringVar(&metricsAddr, "listen-address", ":9102", "The address to listen on for HTTP requests.")
}

type Event_t struct {
	FPid  uint32
	TPid  uint32
	FComm [16]byte
	TComm [16]byte
}

type Program struct {
	bpf goebpf.System
	pe  *goebpf.PerfEvents
	wg  sync.WaitGroup
}

type DmesgLog struct {
	Uid         string
	ContainerID string
	Message     string
}

func AttachOOMProbe(log logr.Logger) {

	log.Info("Starting bpf exporter")
	if err := goebpf.CleanupProbes(); err != nil {
		log.Error(err, "Failed so cleanup probes")
	}

	p, err := LoadProgram("/oom_kill.elf")
	if err != nil {
		log.Error(err, "LoadProgram() failed")
	}
	//p.ShowInfo(log)

	if err := p.AttachProbes(log); err != nil {
		log.Error(err, "AttachProbes() failed")
	}
	defer p.DetachProbes()

	// Start prometheus
	var labels []string
	for _, label := range prometheusContainerLabels {
		labels = append(labels, strings.Replace(label, ".", "_", -1))
	}
	kubernetesCounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "log_pod_oomkill",
		Help: "Extract metrics for OOMKilled pods",
	}, labels)

	prometheus.MustRegister(kubernetesCounterVec)

	go func() {
		log.Info("Kprobe: OOMKill Starting prometheus metrics")
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(metricsAddr, nil)
	}()

	// wait until Ctrl+C pressed
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	<-ctrlC

	log.Info("Kprobe", "Event(s) Received", p.pe.EventsReceived)
	log.Info("Kprobe", "Event(s) lost (e.g. small buffer, delays in processing)", p.pe.EventsLost)
}

func LoadProgram(filename string) (*Program, error) {

	bpf := goebpf.NewDefaultEbpfSystem()

	if err := bpf.LoadElf(filename); err != nil {
		return nil, err
	}

	for _, prog := range bpf.GetPrograms() {
		if err := prog.Load(); err != nil {
			return nil, err
		}
	}

	return &Program{bpf: bpf}, nil
}

func (p *Program) startPerfEvents(events <-chan []byte, log logr.Logger) {
	p.wg.Add(1)
	go func(events <-chan []byte) {
		defer p.wg.Done()

		dockerClient, err := docker_client.NewEnvClient()
		if err != nil {
			log.Error(err, "Failed to create docker client")
			return
		}
		dockerClient.NegotiateAPIVersion(context.Background())

		defaultPattern := `^oom-kill.+,task_memcg=\/kubepods(?:\.slice)?\/.+\/(?:kubepods-burstable-)?pod(\w+[-_]\w+[-_]\w+[-_]\w+[-_]\w+)(?:\.slice)?\/([a-f0-9]+)`
		dmesgRE := regexp.MustCompile(defaultPattern)

		pidPattern := `pid=(\d+)`
		pidRE := regexp.MustCompile(pidPattern)

		for {

			if b, ok := <-events; ok {

				var ev Event_t
				buf := bytes.NewBuffer(b)
				if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
					log.Error(err, "Failed to read buf")
					continue
				}

				tokens := bytes.Split(buf.Bytes(), []byte{0x00})
				var args []string
				for _, arg := range tokens {
					if len(arg) > 0 {
						args = append(args, string(arg))
					}
				}

				var desc string
				if len(args) > 0 {
					desc = args[0]
				}
				if len(args) > 2 {
					desc += " " + strings.Join(args[2:], " ")
				}

				log.Info("Kprobe", "Got OOM kill called from process PID", ev.FPid)
				log.Info("Kprobe", "Got OOM kill for process PID", ev.TPid)
				log.Info("Kprobe", "FCOMM", goebpf.NullTerminatedStringToString(ev.FComm[:]))
				log.Info("Kprobe", "TCOMM", goebpf.NullTerminatedStringToString(ev.TComm[:]))

				//Sleep for few seconds for logs to be present in dmesg
				time.Sleep(2 * time.Second)
				//var logs []DmesgLog

				pidOOM := ev.TPid
				cmd := exec.Command("dmesg")
				output, err := cmd.Output()
				if err != nil {
					log.Error(err, "Error running dmesg command")
					return
				}
				for _, line := range strings.Split(string(output), "\n") {
					fields := strings.Fields(line)
					//log.Infof( "Fields len %d -> %s", len(fields), line)
					if len(fields) < 3 {
						continue
					}
					if matches := dmesgRE.FindStringSubmatch(strings.Join(fields[2:], " ")); matches != nil {
						log.Info("Kprobe", "Found OOM killed UID ", matches[1])
						log.Info("Kprobe", "Container ID ", matches[2])
						//podUID := matches[1]
						containerID := matches[2]

						if containerID != "" {
							if pidmatches := pidRE.FindStringSubmatch(strings.Join(fields[2:], "")); pidmatches != nil {
								//log.Infof("Found PID - %s and %s", pidmatches[0], pidmatches[1])
								pidStr := strconv.FormatUint(uint64(pidOOM), 10)

								//result1 := pidmatches[1] == pidStr
								//log.Infof("Result 1: ", result1)
								//log.Infof("Printing %s %s", pidmatches[1], pidStr)

								if pidmatches[1] == pidStr {
									//log.Infof("Found matching PID %s %s", pidmatches[1], pidStr)
									container, err := getContainer(containerID, dockerClient)
									if err != nil {
										log.Error(err, "Could not get containerID  for pod")
									} else {
										labels := make(map[string]string)
										for k, v := range container.Config.Labels {
											switch k {
											case "io.kubernetes.pod.name":
												log.Info("Kprobe", "Key ", k)
												log.Info("Kprobe", "Value ", v)
												labels[k] = v
											case "io.kubernetes.pod.namespace":
												log.Info("Kprobe", "Key ", k)
												log.Info("Kprobe", "Value ", v)
												labels[k] = v
											case "io.kubernetes.container.name":
												log.Info("Kprobe", "Key ", k)
												log.Info("Kprobe", "Value ", v)
												labels[k] = v
											}
										}
										if len(labels) == 3 {
											prometheusCount(labels, log)
										}
									}
								} else {
									log.Info("PID doesnt match")
								}
							}

						}
					}
				}
			} else {
				break
			}
		}
	}(events)
}

func prometheusCount(containerLabels map[string]string, log logr.Logger) {
	var counter prometheus.Counter
	var err error

	var labels map[string]string
	labels = make(map[string]string)
	for key, label := range prometheusContainerLabels {
		labels[label] = containerLabels[key]
	}

	log.Info("Prometheus", "Labels:", labels)
	counter, err = kubernetesCounterVec.GetMetricWith(labels)

	if err != nil {
		log.Error(err, "Prometheus getMetrics failed")
	} else {
		counter.Add(1)
	}
}

func getContainer(containerID string, cli *docker_client.Client) (docker_types.ContainerJSON, error) {
	container, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return docker_types.ContainerJSON{}, err
	}
	return container, nil

}

func (p *Program) stopPerfEvents() {
	p.pe.Stop()
	p.wg.Wait()
}

func (p *Program) AttachProbes(log logr.Logger) error {

	for _, prog := range p.bpf.GetPrograms() {
		if err := prog.Attach(nil); err != nil {
			return err
		}
	}

	m := p.bpf.GetMapByName("events")
	if m == nil {
		return ErrMapNotFound
	}

	var err error
	p.pe, err = goebpf.NewPerfEvents(m)
	if err != nil {
		return err
	}
	events, err := p.pe.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		return err
	}

	p.wg = sync.WaitGroup{}
	p.startPerfEvents(events, log)

	return nil
}

func (p *Program) DetachProbes() error {
	p.stopPerfEvents()
	for _, prog := range p.bpf.GetPrograms() {
		prog.Detach()
		prog.Close()
	}
	return nil
}

/*
func (p *Program) ShowInfo(log logr.Logger) {
	log.Info("Maps:")
	for _, item := range p.bpf.GetMaps() {
		m := item.(*goebpf.EbpfMap)
		log.Infof("\t%s: %v, Fd %v\n", m.Name, m.Type, m.GetFd())
	}
	log.Infof("Programs:")
	for _, prog := range p.bpf.GetPrograms() {
		log.Infof("\t%s: %v (%s), size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSection(), prog.GetSize(), prog.GetLicense(),
		)
	}
}
*/
