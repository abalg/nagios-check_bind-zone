# nagios-check_bind-zone

BASH/shell script to check DNS-Zone consistency regarding officially registered domains to be used as a quick helper on the CLI as well as in monitoring (nagios/icinga) to check if:

- DNS Servers registered with the respective domain registry according to the WHOIS-output are also NS records in the Zone
- If the zone can be resolved and if the hostname of the SOA nameserver is resolvable (glue records/ A records for NS)
- if all DNS-Servers are around ...
- If all servers in a zone serve the same serial number e.g. if all ns of a zone are in sync

The check_script reads DNS zones from BIND-Config files (named.conf) (CAUTION: included files are not yet parsed) or accepts them as parameters on the commandline

Basicalyy every TLD has their very own Syntax on how to return WHOIS-Data. Parsing for this stuff is so far very limited to the 
domainnames I have in use myself - but this should be quite easily extendable to new formats.

Currently only the Following TLDs are explicitly handled
 
 - .com/.net/.org
 - .at
 - .de
 - .ch/.li
 - .me
 - .uk
 - .sk
 - .biz
 
 
 
 ## INSTALLATION
 
 copy the script and "whois-servers.txt" to any directory or the nagios/nrpe plugins directory.
 
### SELinux:

If selinux is set to enforcing nagios/nrpe cannot run this script unless you extend the policy like this:

``` 
setenforce 0 
restorecon -Rv /usr/lib64/nagios/plugins/
```

Now execute the check through nagios/nrpe until it runs successfully, then run:
```
tail -n 10000 -f /var/log/audit/audit.log | grep check_bind-zones  | audit2allow -M check_bind-zones 
semodule -i check_bind-zones.pp 
setenforce 1 
```


 ## Usage

```
Usage: check_bind-zones.sh [ -h ] [ -s whois_server ] [ -n external_dnsserver_ip ] [ -w warndays -c critical_days
          {[ -d domain_name ]} || { -f bind-config [ -x exclude_domain ]  }

  -c days          : Number of days until expiry to return as critical alarm (default 7)
  -d domain        : Domain to analyze (interactive mode) (repeat for multiple domains)
  -f domain file   : Named.conf where zones are read from (includes not yet processed)
  -h               : Print this screen
  -n               : Define an IP or hostname of an external nameserver for an 'Outside'-View
  -s whois server  : Custom whois sever to query for information
  -v                             : Be more verbose (repeat for even more verbosity)
  -w days          : Number of days until expiry to return as warning (default 30)
  -x domain name   : Exclude domainname from checks (together with -f) (repeat for multiple domains)

```
