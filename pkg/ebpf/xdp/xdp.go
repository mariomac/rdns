package xdp

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../bpf/src/rdns.c -- -I../../../bpf/include

func TraceDNS() error {

	//TODO:
	//bpfObjects := BpfObjects{}
	//if err := LoadBpfObjects(&bpfObjects, nil); err != nil {
	//	return fmt.Errorf("loading BPF objects: %w", err)
	//}
	//
	//// Load the BPF program
	//prog := BpfObjects.BpfLoadObject("dns", false)
	//if prog == nil {
	//	panic("Failed to load BPF program")
	//}
	//
	//// Attach the BPF program to the XDP hook
	//if err := AttachXdp(prog, "lo"); err != nil {
	//	panic(err)
	//}
}