# To use this code as a standalone example:
# Copy the go file and the Makefile to a new directory
# Initialise a go module in the new directory
# (eg.: go mod init balancer && go mod tidy)
# Run make. Done.

# If you already have libbpf installed elsewhere on your system then,
# after inialsing the moudule, you can simply:
# CGO_CFLAGS=-I/path/to/libbpf CGO_LDFLAGS=-L/path/to/libbpf go build

LIBBPF := /usr/local/lib/libbpf/src/

export CGO_CFLAGS  = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF)

build:
	go build -race -o main cmd/main.go

config.json: config.pl config.yaml
	./config.pl config.yaml >$@- && mv $@- $@

wc:
	wc *.go mon/*.go

clean:
	rm -f config.json
