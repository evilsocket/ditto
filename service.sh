#!/bin/bash

OUTPUT="$HOME/ditto_data/$1"

echo "starting monitor on $1 with email $2 (saving on $OUTPUT) ..."

ditto -domain "$1" \
   -monitor 1h \
   -changes "$OUTPUT" \
   -keep-changes \
   -ignore-ip-changes \
   -ignore-host-changes \
   -trigger "/usr/bin/send-email-report.sh {{.Domain}} {{.ChangesFile}} $2"
