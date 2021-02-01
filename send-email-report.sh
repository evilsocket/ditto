#!/bin/bash

# send-email-report.sh {{.Domain}} {{.ChangesFile}} your@gmail.com

sendmail -F "ditto report for $1" -it <<END_MESSAGE
From: ditto.$1@$HOSTNAME
To: $3
Subject: Domain changes for "$1"
Content-Type: text/html
Content-Transfer-Encoding: 7BIT
Content-Disposition: inline
MIME-Version: 1.0

<strong>Domain changes for "$1":</strong>

<pre>
<code>
  $(cat $2)
</code>
</pre>
END_MESSAGE
