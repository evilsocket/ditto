#!/bin/bash

echo "starting monitor on $1 with email $2 ..."
ditto -domain "$1" \
   -monitor 1h \
   -changes "$HOME/ditto_data/$1" \
   -keep-changes \
   -ignore-ip-changes \
   -ignore-host-changes \
   -trigger "/usr/bin/send-email-report.sh {{.Domain}} {{.ChangesFile}} $2"
