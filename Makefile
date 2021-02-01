all: ditto

ditto: _build
	@go build -o _build/ditto cmd/ditto/*.go

test:
	@go test -short ./...

_build:
	@mkdir -p _build

install:
	@go install ./cmd/ditto
	@cp service.sh "$GOPATH/bin/ditto-service"

docker:
	@docker build -t evilsocket/ditto:latest .

docker_push: docker
	@docker push evilsocket/ditto:latest

clean:
	@rm -rf _build
