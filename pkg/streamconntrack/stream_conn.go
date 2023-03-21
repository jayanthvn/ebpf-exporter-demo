package streamconntrack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	awsgoebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
	awsperfcgo "github.com/jayanthvn/pure-gobpf/pkg/ebpf_perf_cgo"
	goebpfelfparser "github.com/jayanthvn/pure-gobpf/pkg/elfparser"
)

type Program struct {
	bpfParser *goebpfelfparser.BPFParser
	pe        *awsperfcgo.PerfEvents
	wg        sync.WaitGroup
}

var (
	ErrProgramNotFound = errors.New("program not found")
	ErrMapNotFound     = errors.New("map not found")
)

// Publisher publishes log entries to a remote endpoint
type Publisher struct {
	conn net.Conn
}

// NewPublisher creates a new Publisher instance
func NewPublisher(endpoint string, log logr.Logger) *Publisher {
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		log.Error(err, "NewPub")
	}
	return &Publisher{conn}
}

// Publish reads log entries from the file and sends them to the remote endpoint
func (p *Publisher) Publish(file *os.File, log logr.Logger) {
	defer p.conn.Close()

	buffer := make([]byte, 1024)
	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Error(err, "Publish failed")
		}
		p.conn.Write(buffer[:n])
	}
}

func AttachKprobegoBPF(log logr.Logger) {

	var bpfParser *goebpfelfparser.BPFParser
	bpfParser, err := goebpfelfparser.LoadBpfFile("/conn_track.elf")
	if err != nil {
		log.Info("Kprobe", "LoadElf() failed: ", err)
	}

	p := Program{bpfParser: bpfParser}

	for _, pgmData := range bpfParser.ElfContext.Section["kprobe"].Programs {
		//log.Info("Kprobe","Kprobe -> PgmName %s : ProgFD %d PinPath %s ProgType %s ProgSubType %s", pgmName, pgmData.ProgFD, pgmData.PinPath, pgmData.ProgType, pgmData.SubProgType)
		funcName := pgmData.SubProgType
		eventName := funcName + "__goebpf"
		log.Info("kprobe", "prog FD ", pgmData.ProgFD)
		log.Info("kprobe", "Func name ", funcName)
		log.Info("kprobe", "eventName", eventName)
		err := awsgoebpf.KprobeAttach(pgmData.ProgFD, eventName, funcName)
		if err != nil {
			log.Info("Kprobe", "Failed to attach kprobe ", err)
			err := awsgoebpf.KprobeDetach(eventName)
			if err != nil {
				log.Info("Cleaned up kprobes")
			}
		}

	}
	for _, pgmData := range bpfParser.ElfContext.Section["tracepoint"].Programs {
		//log.Info("Kprobe","Kprobe -> PgmName %s : ProgFD %d PinPath %s ProgType %s ProgSubType %s", pgmName, pgmData.ProgFD, pgmData.PinPath, pgmData.ProgType, pgmData.SubProgType)

		subSystemName := pgmData.SubSystem
		eventName := pgmData.SubProgType
		err := awsgoebpf.TracepointAttach(pgmData.ProgFD, subSystemName, eventName)
		if err != nil {
			log.Info("Tracepoint", "Failed to attach tracepointprobe ", err)
		}

	}

	if mapToUpdate, ok := bpfParser.ElfContext.Maps["events_conn"]; ok {
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
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	<-ctrlC
}

func (p *Program) startPerfEvents(events <-chan []byte, log logr.Logger) {
	p.wg.Add(1)
	go func(events <-chan []byte) {
		defer p.wg.Done()

		// print header
		log.Info("\nEVENTS\n\n")
		for {

			// receive exec events
			if b, ok := <-events; ok {

				// parse proc info
				var ev uint32
				buf := bytes.NewBuffer(b)
				if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
					log.Info("kprobe", "error: %v\n", err)
					continue
				}

				// parse args
				tokens := bytes.Split(buf.Bytes(), []byte{0x00})
				var args []string
				for _, arg := range tokens {
					if len(arg) > 0 {
						args = append(args, string(arg))
					}
				}

				// build display strings
				var desc string
				if len(args) > 0 {
					desc = args[0]
				}
				if len(args) > 2 {
					desc += " " + strings.Join(args[2:], " ")
				}

				// display process execution event
				/*
					fmt.Printf("%s  %-16s  %-6d %-6d %-6d\n",
						goebpf.NullTerminatedStringToString(ev.FComm[:]),
						goebpf.NullTerminatedStringToString(ev.TComm[:]),
						ev.FPid, ev.TPid, ev.Pages)
				*/
				log.Info("kprobe", "%d", ev)

			} else {
				break
			}
		}
	}(events)
}

func (p *Program) stopPerfEvents() {
	p.pe.Stop()
	p.wg.Wait()
}

func streamLogs(log logr.Logger) {
	logFile := "/host/var/log/aws-routed-eni/myapp.log"
	log.Info("Starting log forwarder...")

	// Open the log file
	file, err := os.Open(logFile)
	if err != nil {
		log.Error(err, "Stream logs")
	}
	defer file.Close()

	// Publish the logs to a local port
	publisher := NewPublisher("localhost:24224", log)
	go publisher.Publish(file, log)

	// Listen for log queries on a container port
	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		logFile, err := os.Open(logFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer logFile.Close()

		// Send the log contents to the client
		_, err = io.Copy(w, logFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	log.Info("Listening for log queries on port 8080...")
	http.ListenAndServe(":8080", nil)
}
