package pidtracking

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	awsgoebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
	awsperfcgo "github.com/jayanthvn/pure-gobpf/pkg/ebpf_perf_cgo"
	goebpfelfparser "github.com/jayanthvn/pure-gobpf/pkg/elfparser"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ErrProgramNotFound        = errors.New("program not found")
	ErrMapNotFound            = errors.New("map not found")
	kubernetesCounterVec      *prometheus.GaugeVec
	prometheusContainerLabels = map[string]string{
		"io.kubernetes.hostname": "host_name",
	}
	metricsAddr string
)

const (
	PID_TID_CREATE = 0
	PID_TID_DELETE = 1
)

func init() {

	flag.StringVar(&metricsAddr, "listen-address", ":9103", "The address to listen on for HTTP requests.")
}

type Event_t struct {
	Pid  uint32
	Type uint32
}

type Program struct {
	bpfParser *goebpfelfparser.BPFParser
	pe        *awsperfcgo.PerfEvents
	wg        sync.WaitGroup
}

func AttachPidProbe(log logr.Logger) {
	var bpfParser *goebpfelfparser.BPFParser
	bpfParser, err := goebpfelfparser.LoadBpfFile("/pid_tracking.elf")
	if err != nil {
		log.Info("Kprobe", "LoadElf() failed: ", err)
	}

	p := Program{bpfParser: bpfParser}
	for _, pgmData := range bpfParser.ElfContext.Section["tracepoint"].Programs {

		subSystemName := pgmData.SubSystem
		eventName := pgmData.SubProgType
		err := awsgoebpf.TracepointAttach(pgmData.ProgFD, subSystemName, eventName)
		if err != nil {
			log.Info("Tracepoint", "Failed to attach tracepointprobe ", err)
		}

	}

	// Start prometheus

	var labels []string
	for _, label := range prometheusContainerLabels {
		labels = append(labels, strings.Replace(label, ".", "_", -1))
	}
	kubernetesCounterVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pid_usage",
		Help: "pid usage per node",
	}, labels)

	prometheus.MustRegister(kubernetesCounterVec)

	go func() {
		log.Info("TC: pid start/end Starting prometheus metrics")
		http.Handle("/pidmetrics", promhttp.Handler())
		http.ListenAndServe(metricsAddr, nil)
	}()

	if mapToUpdate, ok := bpfParser.ElfContext.Maps["events_pid"]; ok {
		var err error
		p.pe, err = awsperfcgo.NewPerfEvents(int(mapToUpdate.MapFD), bpfParser.BpfMapAPIs)
		if err != nil {
			return
		}
		events, err := p.pe.StartForAllProcessesAndCPUs(4096)
		if err != nil {
			return
		}

		// start event listeners
		p.wg = sync.WaitGroup{}
		p.startPerfEvents(events, log)

	}
	// wait until Ctrl+C pressed
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	<-ctrlC

	log.Info("Kprobe", "Event(s) Received", p.pe.EventsReceived)
	log.Info("Kprobe", "Event(s) lost (e.g. small buffer, delays in processing)", p.pe.EventsLost)

}

func (p *Program) startPerfEvents(events <-chan []byte, log logr.Logger) {
	p.wg.Add(1)
	go func(events <-chan []byte) {
		defer p.wg.Done()

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

				log.Info("Kprobe", "Got PID", ev.Pid)
				log.Info("Kprobe", "Got PID type", ev.Type)
				labels := make(map[string]string)
				labels["io.kubernetes.hostname"] = os.Getenv("MY_NODE_NAME")
				prometheusCount(labels, ev.Type, log)
			} else {
				break
			}
		}
	}(events)
}

func prometheusCount(containerLabels map[string]string, counterType uint32, log logr.Logger) {
	var value prometheus.Gauge
	var err error

	var labels map[string]string
	labels = make(map[string]string)
	for key, label := range prometheusContainerLabels {
		labels[label] = containerLabels[key]
	}

	log.Info("Prometheus", "Labels:", labels)
	value, err = kubernetesCounterVec.GetMetricWith(labels)

	if err != nil {
		log.Error(err, "Prometheus getMetrics failed")
	} else {
		if counterType == PID_TID_CREATE {
			value.Inc()
		} else if counterType == PID_TID_DELETE {
			value.Dec()
		}
	}
}
