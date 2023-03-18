package streamconntrack

import (
	"bytes"
	//"context"
	"encoding/binary"
	"errors"
	//"flag"
	"io"
	"net"
	"net/http"
	//"net/http"
	"os"
	//"os/exec"
	"os/signal"
	//"regexp"
	//"strconv"
	"strings"
	"sync"
	//"time"

	//"github.com/dropbox/goebpf"
	"github.com/go-logr/logr"
	awsgoebpf "github.com/jayanthvn/pure-gobpf/pkg/ebpf"
	//awsperf "github.com/jayanthvn/pure-gobpf/pkg/ebpf_perf"
	awsperfcgo "github.com/jayanthvn/pure-gobpf/pkg/ebpf_perf_cgo"
	goebpfelfparser "github.com/jayanthvn/pure-gobpf/pkg/elfparser"
)

type Program struct {
	bpfParser *goebpfelfparser.BPFParser
	pe        *awsperfcgo.PerfEvents
	wg        sync.WaitGroup
}

/*
	type Event_t struct {
		Saddr uint32
		Daddr uint32
		//Sport   uint16
		//Dport   uint16
		//Verdict uint32
	}

	type Program struct {
		bpf goebpf.System
		pe  *goebpf.PerfEvents
		wg  sync.WaitGroup
	}
*/
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

	if mapToUpdate, ok := bpfParser.ElfContext.Maps["events_conn"]; ok {
		/*
			perfReader, err := awsperf.InitPerfBuffer(int(mapToUpdate.MapFD), bpfParser.BpfMapAPIs)
			if err != nil {
				log.Info("Failed to init perf buffer")
				return
			}
			//defer perfReader.Close()
			log.Info("Waiting for events..")

			for {
				record, err := perfReader.Read()
				if err != nil {
					if errors.Is(err, awsperf.ErrClosed) {
						log.Info("Received signal, exiting..")
						return
					}
					log.Info("Kprobe", "reading from reader: %s", err)
					continue
				}

				log.Info("Kprobe", "Record:", record)
			}*/
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

/*
func AttachStreamProbe(log logr.Logger) {

	log.Info("Starting bpf exporter")
	if err := goebpf.CleanupProbes(); err != nil {
		log.Error(err, "Failed so cleanup probes")
	}

	p, err := LoadProgram("/conn_track.elf", log)
	if err != nil {
		log.Error(err, "LoadProgram() failed")
	}
	//p.ShowInfo(log)

	if err := p.AttachProbes(log); err != nil {
		log.Error(err, "AttachProbes() failed")
	}
	defer p.DetachProbes()


	// wait until Ctrl+C pressed
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	<-ctrlC

	log.Info("Kprobe", "Event(s) Received", p.pe.EventsReceived)
	log.Info("Kprobe", "Event(s) lost (e.g. small buffer, delays in processing)", p.pe.EventsLost)
}
*/

/*
func LoadProgram(filename string, log logr.Logger) (*Program, error) {

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

				log.Info("Kprobe", "SADDR", ev.Saddr)
				log.Info("Kprobe", "DADDR", ev.Daddr)
				//log.Info("Kprobe", "SPORT", ev.Sport)
				//log.Info("Kprobe", "DPORT", ev.Dport)
				//log.Info("Kprobe", "Verdict", ev.Verdict)
				//streamLogs(log)

			} else {
				break
			}
		}
	}(events)
}
*/

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

/*
func (p *Program) stopPerfEvents() {
	p.pe.Stop()
	p.wg.Wait()
}

func (p *Program) AttachProbes(log logr.Logger) error {

	for _, prog := range p.bpf.GetPrograms() {
		if err := prog.Attach(nil); err != nil {
			log.Info("Kprobe", "Failed", err)
			return err
		}
	}
	log.Info("Kprobe attached")

	m := p.bpf.GetMapByName("events_conn")
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
*/
