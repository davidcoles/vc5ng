# To use this code as a standalone example:
# Copy the go file and the Makefile to a new directory
# Initialise a go module in the new directory
# (eg.: go mod init balancer && go mod tidy)
# Run make. Done.

# If you already have libbpf installed elsewhere on your system then,
# after inialsing the moudule, you can simply:
# CGO_CFLAGS=-I/path/to/libbpf CGO_LDFLAGS=-L/path/to/libbpf go build

BPFVER ?= v0.6.1
LIBBPF ?= $(PWD)/libbpf/src

export CGO_CFLAGS  = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF)

default: libbpf/src/libbpf.a balancer

balancer:
	go build -race -o $@


config.yaml:
	cp config.sample.yaml $@

config.json: config.pl config.yaml
	./config.pl config.yaml >$@- && mv $@- $@

clean:
	rm -f balancer config.json

distclean: clean
	rm -rf libbpf

libbpf:
	git clone -b $(BPFVER) https://github.com/libbpf/libbpf

libbpf/src/libbpf.a: libbpf
	cd libbpf/src && $(MAKE)
