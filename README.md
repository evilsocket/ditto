Ditto is a small tool that accepts a domain name as input and generates all its variants for an [homograph attack](https://en.wikipedia.org/wiki/IDN_homograph_attack) as output, checking which ones are available and which are already registered.

**Work in progress**

## Install

Compiling from sources (requires the go compiler, will install the binary in $GOPATH/bin):

    # make sure go modules are used
    GO111MODULE=on go get github.com/evilsocket/ditto/cmd/ditto

Using docker:

    cd /path/to/this/repo
    docker build -t ditto:latest .
    docker run ditto:latest -domain abc.com

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
