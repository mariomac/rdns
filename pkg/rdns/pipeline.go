package rdns

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mariomac/pipes/pipe"

	"github.com/mariomac/rdns/pkg/config"
	"github.com/mariomac/rdns/pkg/ebpf/addrinfo"
	"github.com/mariomac/rdns/pkg/ebpf/xdp"
	"github.com/mariomac/rdns/pkg/query"
	"github.com/mariomac/rdns/pkg/store"
)

type Pipeline struct {
	packetResolver      pipe.Start[store.DNSEntry]
	getAddrInfoResolver pipe.Start[store.DNSEntry]
	store               pipe.Final[store.DNSEntry]
}

func (p *Pipeline) Packet() *pipe.Start[store.DNSEntry]      { return &p.packetResolver }
func (p *Pipeline) GetAddrInfo() *pipe.Start[store.DNSEntry] { return &p.getAddrInfoResolver }
func (p *Pipeline) Store() *pipe.Final[store.DNSEntry]       { return &p.store }

func (p *Pipeline) Connect() {
	p.packetResolver.SendTo(p.store)
	p.getAddrInfoResolver.SendTo(p.store)
}

func Run(ctx context.Context, cfg *config.Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	store := selectStore(ctx, cfg)

	builder := pipe.NewBuilder(&Pipeline{})
	pipe.AddStartProvider(builder, (*Pipeline).Packet, xdp.PacketResolverProvider(ctx, cfg))
	pipe.AddStartProvider(builder, (*Pipeline).GetAddrInfo, addrinfo.AddrInfoProvider(ctx, cfg))
	pipe.AddFinal(builder, (*Pipeline).Store, store.PipelineStage)

	run, err := builder.Build()
	if err != nil {
		return fmt.Errorf("building pipeline: %w", err)
	}

	go func() {
		slog.Info("starting HTTP server", "port", cfg.HttpPort)
		if err := query.HttpJsonServer(store, cfg.HttpPort); err != nil {
			slog.Error("running HTTP server. Exiting", "error", err)
			cancel()
		}
	}()

	run.Start()
	<-run.Done()
	return nil
}

type storage interface {
	PipelineStage(in <-chan store.DNSEntry)
	GetHostnames(ip string) []string
}

func selectStore(ctx context.Context, cfg *config.Config) storage {
	if cfg.RedisAddress != "" {
		return store.NewRedis(ctx, cfg.RedisAddress, cfg.RedisUser, cfg.RedisPassword)
	}
	return store.NewInMemory()
}
