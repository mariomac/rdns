package addrinfo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 -type dns_entry_t Bpf ../../../bpf/src/addrinfo.c -- -I../../../bpf/include

func log() *slog.Logger {
	return slog.With(
		slog.String("component", "addrinfo.Tracer"),
	)
}

type tracer struct {
	bpfObjects BpfObjects
	uprobe     link.Link
	uretprobe  link.Link
}

func (t *tracer) register() error {
	log := log()
	// Allow the current process to lock memory for eBPF resources.
	log.Debug("Registering eBPF tracer")
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warn("removing mem lock", "error", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	log.Debug("loading BPF objects")
	if err := LoadBpfObjects(&t.bpfObjects, nil); err != nil {
		verr := &ebpf.VerifierError{}
		if !errors.As(err, &verr) {
			return fmt.Errorf("loading BPF objects: %w", err)
		}
		return fmt.Errorf("loading BPF objects: %w, %s", err, strings.Join(verr.Log, "\n"))
	}

	log.Debug("registering uprobes")
	// TODO: replace
	arch := "x86_64-linux-gnu"
	if runtime.GOARCH == "arm64" {
		arch = "aarch64-linux-gnu"
	}
	exec, err := link.OpenExecutable("/usr/lib/" + arch + "/libc.so.6")
	if err != nil {
		return fmt.Errorf("opening executable: %w", err)
	}
	t.uprobe, err = exec.Uprobe("getaddrinfo", t.bpfObjects.UprobeGetaddrinfo, nil)
	if err != nil {
		return fmt.Errorf("registering uprobe: %w", err)
	}
	t.uretprobe, err = exec.Uretprobe("getaddrinfo", t.bpfObjects.UretprobeGetaddrinfo, nil)

	return nil
}

func (t *tracer) Close() error {
	var errs []string
	if t.uprobe != nil {
		if err := t.uprobe.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := t.bpfObjects.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("closing BPF resources: '%s'", strings.Join(errs, "', '"))
	}
	return nil
}

func Trace() (func(), error) {
	log := log()
	t := tracer{}
	if err := t.register(); err != nil {
		return nil, fmt.Errorf("registering eBPF tracer: %w", err)
	}
	log.Debug("creating ringbuf reader")
	rd, err := ringbuf.NewReader(t.bpfObjects.Resolved)
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}
	return func() {
		defer t.Close()
		// TODO: set proper context-based cancellation
		log.Debug("reading ringbuf events")
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Debug("Received signal, exiting..")
					return
				}
				log.Error("reading from ringbuf", err)
				continue
			}
			input := bytes.NewBuffer(record.RawSample)
			dnsEntry := BpfDnsEntryT{}
			if err := binary.Read(input, binary.LittleEndian, &dnsEntry); err != nil {
				log.Error("reading ringbuf event", "error", err)
				continue
			}
			fmt.Printf("%s -> %v\n", string(dnsEntry.Name[:]), dnsEntry.Ip[:4])
		}
	}, nil
}
