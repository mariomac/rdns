# RDNS

An eBPF-based reverse DNS building.

It intercepts name resolution responses at different levels and builds a reverse DNS, allowing you to
query hostnames by IP addresses that have been previously resolved in your host.

## How to compile and run

CLI:
```
make compile
RDNS_LOG_LEVEL=debug sudo -E ./bin/rdns
```

Docker:
```
docker build -t docker.io/mariomac/rdns:dev .
docker run --network=host -it --privileged -e RDNS_LOG_LEVEL=debug -p 8080:8080 docker.io/mariomac/rdns:dev
```

(`--network=host` is only required if you are using the `packet` resolver).

## How to query

Generate some DNS traffic:

```
ping -c 1 macias.info
ping -c 1 www.macias.info
```

Query the reverse DNS via HTTP:

```
curl http://localhost:8080/51.68.34.104
{"hostnames":["macias.info","www.macias.info"],"ip":"51.68.34.104"}
```

(If you are running it in Docker for Mac, you will need to generate the DNS requests inside a container).