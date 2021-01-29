#!/bin/bash

# send-email-report.sh {{.Domain}} {{.ChangesFile}} your@gmail.com

sendmail -F "ditto report for $1" -it <<END_MESSAGE
To: $3
Subject: Domain changes for "$1"

Domain changes for "$1":

$(cat $2)
END_MESSAGE
