package xdp

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type tracer struct {
	bpfObjects *BpfObjects
	links []*link.Link
	ringbuf *ringbuf.Reader
}

func (t *tracer) Close() error {
	if t.bpfObjects != nil {
		t.bpfObjects.Close()
		t.bpfObjects = nil
	}

	for _, link := range t.links {
		(*link).Close()
	}

	t.links = nil

	if t.ringbuf != nil {
		t.ringbuf.Close()
	}

	return nil
}

// this is analogous to C++ std::move()
func move(t *tracer) tracer {
	ret := tracer {
		bpfObjects: t.bpfObjects,
		links: t.links,
		ringbuf: t.ringbuf,
	}

	t.bpfObjects = nil
	t.links = nil
	t.ringbuf = nil

	return ret
}

func newTracer() (*tracer, error) {
	objects := BpfObjects{}

	if err := LoadBpfObjects(&objects, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}

		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	tracer := tracer { bpfObjects: &objects }
	defer tracer.Close()

	ifaces := ifacesToAttach()

	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no interfaces to attach")
	}

	log := log()

	for i := range ifaces {
		link, err := link.AttachXDP(link.XDPOptions{
			Program: tracer.bpfObjects.BpfPrograms.DnsResponseTracker,
			Interface: ifaces[i].Index,
		})

		if err != nil {
			log.Debug("failed to attach XDP program to interface",
				"interface", ifaces[i].Name, "error", err)
			continue
		}

		log.Debug("attached to interface", "interface", ifaces[i].Name)

		tracer.links = append(tracer.links, &link)
	}

	if len(tracer.links) == 0 {
		return nil, fmt.Errorf("No interfaces found")
	}

	var err error

	tracer.ringbuf, err = ringbuf.NewReader(tracer.bpfObjects.RingBuffer)

	if err != nil {
		return nil, fmt.Errorf("creating ringbuffer reader: %w", err)
	}

	ret := move(&tracer)
	return &ret, nil
}

func ifacesToAttach() []net.Interface {
	ifaces, err := net.Interfaces()

	if len(ifaces) == 0  || err != nil {
		return nil
	}

	ret := make([]net.Interface, 0, len(ifaces))

	for i := range ifaces {
		if !isVirtualInterface(ifaces[i].Name) {
			ret = append(ret, ifaces[i])
		}
	}

	return ret
}

func isVirtualInterface(name string) bool {
	virtualPatterns := []string{
		"br-",     // Docker bridge interfaces
		"veth",    // Docker virtual Ethernet interfaces
		"docker",  // Docker default bridge
		"lo",      // Loopback interface
	}

	for _, pattern := range virtualPatterns {
		if strings.HasPrefix(name, pattern) {
			return true
		}
	}

	return false
}
