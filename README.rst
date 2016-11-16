
scan the tor network for CVE-2016-5696
--------------------------------------


words of warning
````````````````
please do not carelessly use this tool.
better not to use it unless you know what you are doing.

multiple entities scanning the the same tor relay concurrently
will report incorrect results. it's a global counter so that means
each machine only has one of them.


extract connecting information from a Tor consensus
```````````````````````````````````````````````````

Firstly download a tor consensus.
To make this scan reproducible I have downloaded a consensus file from collector::

  wget https://collector.torproject.org/recent/relay-descriptors/consensuses/2016-11-16-04-00-00-consensus


Massage into the format our scanner expects, (host port)::

  cat 2016-11-16-04-00-00-consensus | grep '^r '| awk '{print $7" "$8}' > probe_consensus


prepare scanner host iptables
`````````````````````````````

Before scanning the iptables must be configured to drop RST packets so that scapy
can manage the TCP connections without the kernel interfering::

  iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP


run the scanner
```````````````

run::

  ./rfc5961_probe.py < probe-consensus > probe.output

The code is rather unpolished; currently the scanner tool writes comma seperated output.
However connection timeouts are not in CSV formation... So you'll have to filter that
before analyzing.


acknowledgements
````````````````

- Thanks to Least Authority for supporting my research of this topic.
- This scanner was inspired by Proof of Concept code for CVE-2016-5696 https://github.com/violentshell/rover
- Thanks to Leif Ryge for helping me write the scanner and for data analysis.



