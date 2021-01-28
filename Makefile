all: ditto

ditto: _build
	go build -o _build/ditto cmd/ditto/*.go

install: ditto
	cp _build/ditto /usr/bin/
	chmod a+x /usr/bin/ditto

test:
	go test -short ./...

_build:
	mkdir -p _build

clean:
	rm -rf _build
