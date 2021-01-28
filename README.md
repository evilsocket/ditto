Ditto is a small tool that accepts a domain name as input and generates all its variants for an [homograph attack]
(https://en.wikipedia.org/wiki/IDN_homograph_attack) as output, checking which ones are available and which are already registered.

**Work in progress**

## Usage

For the moment there are no binary releases and building from sources is the only way (requires the go compiler, 
will install the binary in $GOPATH/bin):

    # make sure go modules are used
    GO111MODULE=on go get github.com/evilsocket/ditto/cmd/ditto

Then:

    ditto -domain facebook.com

For more options:
    
    uro -help

## License

Released under the GPL3 license.
