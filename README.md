# nagios-check_bind-zone

BASH/shell script to check DNS-Zone consistency regarding officially registered domains to be used as a quick helper on the CLI as well as in monitoring (nagios/icinga) to check if:

- DNS Servers registered with the respective domain registry according to the WHOIS-output are also NS records in the Zone
- If the zone can be resolved and if the hostname of the SOA nameserver is resolvable (glue records/ A records for NS)
- if all DNS-Servers are around ...
- If all servers in a zone serve the same serial number e.g. if all ns of a zone are in sync

WARING:

Many TLDs have their very own Syntax on how to return WHOIS-data . Parsing for this specific stuff is so far very limited to the 
domainnames I have in use myself - but this should be easily extendable to new formats
