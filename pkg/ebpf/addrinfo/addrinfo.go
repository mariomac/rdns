package addrinfo

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../bpf/src/addrinfo.c -- -I../../../bpf/include
