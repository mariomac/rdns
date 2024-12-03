package main

import (
	"log/slog"
	"os"

	"github.com/mariomac/rdns/pkg/ebpf/addrinfo"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	if fn, err := addrinfo.Trace(); err != nil {
		panic(err)
	} else {
		fn()
	}
}
