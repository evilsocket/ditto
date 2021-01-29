Ditto is a small tool that accepts a domain name as input and generates all its variants for an [homograph attack](https://en.wikipedia.org/wiki/IDN_homograph_attack) as output, checking which ones are available and which are already registered.

## Using with Docker

The [image on docker hub](https://hub.docker.com/r/evilsocket/ditto) is updated on every push, you can just:

    docker run evilsocket/ditto:latest -h

## Compiling from sources

Compiling from sources requires the go compiler, this will install the binary in `$GOPATH/bin`:

    # make sure go modules are used
    GO111MODULE=on go get github.com/evilsocket/ditto/cmd/ditto

## Usage

To only transform a string:

    ditto -string google

For a domain:

    ditto -domain facebook.com

Only show available domains:

    ditto -domain facebook.com -available

Only show registered domains:

    ditto -domain facebook.com -registered

Only show registered domains that resolve to an IP:
    
    ditto -domain facebook.com -live

Show WHOIS information:

    ditto -domain facebook.com -live -whois

Save to CSV file with extended WHOIS information:

    ditto -domain facebook.com -whois -csv output.csv

For more options:
    
    ditto -help

## License

Released under the GPL3 license.
