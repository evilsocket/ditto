all: ditto

ditto: _build
	@go build -o _build/ditto cmd/ditto/*.go

install: ditto
	@cp _build/ditto /usr/bin/
	@chmod a+x /usr/bin/ditto

test:
	@go test -short ./...

_build:
	@mkdir -p _build

docker:
	@docker build -t evilsocket/ditto:latest .

docker_push: docker
	@docker push evilsocket/ditto:latest

clean:
	@rm -rf _build
