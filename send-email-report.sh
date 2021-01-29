#!/bin/bash

# ./test-report.sh {{.Domain}} {{.ChangesFile}}

sendmail -F "ditto report for $1" -it <<END_MESSAGE
To: evilsocket@gmail.com
Subject: Domain changes for "$1"

Domain changes for "$1":

$(cat $2)
END_MESSAGE
