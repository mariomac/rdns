package xdp

import (
	"context"
	"log/slog"
	"slices"

	"github.com/mariomac/pipes/pipe"

	"github.com/mariomac/rdns/pkg/config"
	"github.com/mariomac/rdns/pkg/store"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../bpf/src/rdns.c -- -I../../../bpf/include

func log() *slog.Logger {
	return slog.With("component", "xdp.PacketResolver")
}

func PacketResolverProvider(ctx context.Context, cfg *config.Config) pipe.StartProvider[store.DNSEntry] {
	return func() (pipe.StartFunc[store.DNSEntry], error) {
		log := log()
		if !slices.Contains(cfg.Resolvers, config.ResolverPacket) {
			log.Debug("packet resolver is not enabled, ignoring this stage")
			return pipe.IgnoreStart[store.DNSEntry](), nil
		}

		// todo: instantiate here the eBPF tracer and return any possible error

		return func(out chan<- store.DNSEntry) {
			log.Debug("listening to packet resolver")
			// TODO: forward here any new DNS entry received from the eBPF tracer
			// (check addrInfo as example)
		}, nil
	}
}
