# If you already have libbpf installed elsewhere on your system then
# specify the path like so:
# CGO_CFLAGS=-I/path/to/libbpf CGO_LDFLAGS=-L/path/to/libbpf go build

BPFVER ?= v1.3.0
LIBBPF ?= $(PWD)/libbpf/src

export CGO_CFLAGS  ?= -I$(LIBBPF)
export CGO_LDFLAGS ?= -L$(LIBBPF)

default: libbpf/src/libbpf.a vc5

vc5: *.go static/*
	go build -race -o $@

config.yaml:
	cp config.sample.yaml $@

config.json: config.pl config.yaml
	./config.pl config.yaml >$@- && mv $@- $@

clean:
	rm -f vc5 config.json

distclean: clean
	rm -rf libbpf

libbpf:
	git clone -b $(BPFVER) https://github.com/libbpf/libbpf

libbpf/src/libbpf.a: libbpf
	cd libbpf/src && $(MAKE)

test:
	if grep '^replace github.com/davidcoles/xvs' go.mod; then false; fi
