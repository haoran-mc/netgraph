package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/haoran-mc/netgraph/ngnet"
)

var (
	device = flag.String("i", "", "Device to capture, auto select one if no device provided")
	bpf    = flag.String("bpf", "", "Set berkeley packet filter")

	outputHTTP = flag.String("o", "", "Write HTTP request/response to file")

	bindingPort = flag.Int("p", 9000, "Web server port. If the port is set to '0', the server will not run.")
	saveEvent   = flag.Bool("s", false, "Save HTTP event in server")

	verbose = flag.Bool("v", true, "Show more message")
)

// NGHTTPEventHandler handle HTTP events
type NGHTTPEventHandler interface {
	PushEvent(interface{})
	Wait()
}

var handlers []NGHTTPEventHandler

func init() {
	flag.Parse()
	if !*verbose {
		log.SetOutput(io.Discard)
	}
}

func initEventHandlers() {
	if *bindingPort != 0 {
		addr := fmt.Sprintf(":%d", *bindingPort)
		ngserver := NewNGServer(addr, *saveEvent)
		ngserver.Serve()
		handlers = append(handlers, ngserver)
	}

	if *outputHTTP != "" {
		p := NewEventPrinter(*outputHTTP)
		handlers = append(handlers, p)
	}
}

func packetSource() *gopacket.PacketSource {
	handle, err := pcap.OpenLive(*device, 1024*1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatalln(err)
	}
	if *bpf != "" {
		if err = handle.SetBPFFilter(*bpf); err != nil {
			log.Fatalln("Failed to set BPF filter:", err)
		}
	}
	log.Printf("open live on device \"%s\", bpf \"%s\"\n", *device, *bpf)
	return gopacket.NewPacketSource(handle, handle.LinkType())
}

func runNGNet(packetSource *gopacket.PacketSource, eventChan chan<- interface{}) {
	streamFactory := ngnet.NewHTTPStreamFactory(eventChan)
	pool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(pool)

	var count uint
	ticker := time.Tick(time.Minute)
	var lastPacketTimestamp time.Time

LOOP:
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				break LOOP
			}

			count++
			netLayer := packet.NetworkLayer()
			if netLayer == nil {
				continue
			}
			transLayer := packet.TransportLayer()
			if transLayer == nil {
				continue
			}
			tcp, _ := transLayer.(*layers.TCP)
			if tcp == nil {
				continue
			}

			assembler.AssembleWithTimestamp(
				netLayer.NetworkFlow(),
				tcp,
				packet.Metadata().CaptureInfo.Timestamp)

			lastPacketTimestamp = packet.Metadata().CaptureInfo.Timestamp
		case <-ticker:
			assembler.FlushOlderThan(lastPacketTimestamp.Add(time.Minute * -2))
		}
	}

	assembler.FlushAll()
	log.Println("Read pcap file complete")
	streamFactory.Wait()
	log.Println("Parse complete, packet count: ", count)

	close(eventChan)
}

// EventPrinter print HTTP events to file or stdout
type EventPrinter struct {
	file *os.File
}

// NewEventPrinter creates EventPrinter
func NewEventPrinter(name string) *EventPrinter {
	p := new(EventPrinter)
	var err error
	if name == "stdout" {
		p.file = os.Stdout
	} else {
		p.file, err = os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0755)
		if err != nil {
			log.Fatalln("Cannot open file ", name)
		}
	}

	return p
}

func (p *EventPrinter) printHTTPRequestEvent(req ngnet.HTTPRequestEvent) {
	fmt.Fprintf(p.file, "[%s] #%d Request %s->%s\r\n",
		req.Start.Format("2006-01-02 15:04:05.000"), req.StreamSeq, req.ClientAddr, req.ServerAddr)
	fmt.Fprintf(p.file, "%s %s %s\r\n", req.Method, req.URI, req.Version)
	for _, h := range req.Headers {
		fmt.Fprintf(p.file, "%s: %s\r\n", h.Name, h.Value)
	}

	fmt.Fprintf(p.file, "\r\ncontent(%d)", len(req.Body))
	if len(req.Body) > 0 {
		fmt.Fprintf(p.file, "%s", req.Body)
	}
	fmt.Fprintf(p.file, "\r\n\r\n")
}

func (p *EventPrinter) printHTTPResponseEvent(resp ngnet.HTTPResponseEvent) {
	fmt.Fprintf(p.file, "[%s] #%d Response %s<-%s\r\n",
		resp.Start.Format("2006-01-02 15:04:05.000"), resp.StreamSeq, resp.ClientAddr, resp.ServerAddr)
	fmt.Fprintf(p.file, "%s %d %s\r\n", resp.Version, resp.Code, resp.Reason)
	for _, h := range resp.Headers {
		fmt.Fprintf(p.file, "%s: %s\r\n", h.Name, h.Value)
	}

	fmt.Fprintf(p.file, "\r\ncontent(%d)", len(resp.Body))
	if len(resp.Body) > 0 {
		fmt.Fprintf(p.file, "%s", resp.Body)
	}
	fmt.Fprintf(p.file, "\r\n\r\n")
}

// PushEvent implements the function of interface NGHTTPEventHandler
func (p *EventPrinter) PushEvent(e interface{}) {
	switch v := e.(type) {
	case ngnet.HTTPRequestEvent:
		p.printHTTPRequestEvent(v)
	case ngnet.HTTPResponseEvent:
		p.printHTTPResponseEvent(v)
	default:
		log.Printf("Unknown event: %v", e)
	}
}

// Wait implements the function of interface NGHTTPEventHandler
func (p *EventPrinter) Wait() {}

func runEventHandler(eventChan <-chan interface{}) {
	for e := range eventChan {
		if e == nil {
			break
		}
		for _, h := range handlers {
			h.PushEvent(e)
		}
	}

	for _, h := range handlers {
		h.Wait()
	}
}

/*
   create client.go
*/
//go:generate python embed_html.py

func main() {
	initEventHandlers()
	eventChan := make(chan interface{}, 1024)
	go runNGNet(packetSource(), eventChan)
	runEventHandler(eventChan)
}
