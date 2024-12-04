# Build the autoinstrumenter binary
FROM golang:1.23 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /opt/app-root

COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile
COPY LICENSE LICENSE

# Build
RUN make compile

# Create final image from minimal + built binary
FROM ubuntu:22.04

LABEL maintainer="Grafana Labs <hello@grafana.com>"

WORKDIR /

COPY --from=builder /opt/app-root/bin/rdns .
COPY --from=builder /opt/app-root/LICENSE .

ENTRYPOINT [ "/rdns" ]