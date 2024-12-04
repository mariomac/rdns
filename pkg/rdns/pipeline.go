package rdns

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pipe"

	"github.com/mariomac/rdns/pkg/config"
	"github.com/mariomac/rdns/pkg/ebpf/addrinfo"
	"github.com/mariomac/rdns/pkg/ebpf/xdp"
	"github.com/mariomac/rdns/pkg/store"
)

type Pipeline struct {
	packetResolver      pipe.Start[store.DNSEntry]
	getAddrInfoResolver pipe.Start[store.DNSEntry]
	inMemoryStore       pipe.Final[store.DNSEntry]
}

func (p *Pipeline) Packet() *pipe.Start[store.DNSEntry]        { return &p.packetResolver }
func (p *Pipeline) GetAddrInfo() *pipe.Start[store.DNSEntry]   { return &p.getAddrInfoResolver }
func (p *Pipeline) InMemoryStore() *pipe.Final[store.DNSEntry] { return &p.inMemoryStore }

func (p *Pipeline) Connect() {
	p.packetResolver.SendTo(p.inMemoryStore)
	p.getAddrInfoResolver.SendTo(p.inMemoryStore)
}

func Run(ctx context.Context, cfg *config.Config) error {
	store := store.NewInMemory()

	builder := pipe.NewBuilder(&Pipeline{})
	pipe.AddStartProvider(builder, (*Pipeline).Packet, xdp.PacketResolverProvider(ctx, cfg))
	pipe.AddStartProvider(builder, (*Pipeline).GetAddrInfo, addrinfo.AddrInfoProvider(ctx, cfg))
	pipe.AddFinal(builder, (*Pipeline).InMemoryStore, store.PipelineStage)

	run, err := builder.Build()
	if err != nil {
		return fmt.Errorf("building pipeline: %w", err)
	}
	run.Start()
	<-run.Done()
	return nil
}
