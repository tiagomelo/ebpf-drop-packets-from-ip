.PHONY: help
## help: shows this help message
help:
	@ echo "Usage: make [target]\n"
	@ sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

.PHONY: generate
## generate: generate the eBPF code
generate:
	@ go generate

.PHONY: build
## build: build the application
build:
	@ go build -o ebpfdrop

.PHONY: run
## run: run the application
run: generate build
	@ if [ -z "$(BLOCKED_IP)" ]; then echo >&2 please set blocked ip via the variable BLOCKED_IP; exit 2; fi
	@ sudo ./ebpfdrop $(BLOCKED_IP) $(INTERFACE)

.PHONY: trace-pipe
## trace-pipe: trace the eBPF program
trace-pipe:
	@ sudo bpftool prog tracelog pipe


