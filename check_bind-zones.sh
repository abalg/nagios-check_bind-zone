#!/bin/bash 
#
# Author: Andreas Balg < andreas.balg at wuerth-itensis dot com >
# 
# Current Version: 0.1
#
# Purpose:
#  domain-check checks to see if a domain has expired. domain-check
#  can be run in interactive and batch mode, and provides faciltities 
#  to alarm if a domain is about to expire.
#
#  Output and return codes are compatible to be used directly as nagios/icinga
#  checks or use it on the console as CLI tool
#
# Requirements:
#   Requires whois, dig, date, cut and awk commands
#
# Installation:
#   Copy the shell script to a suitable location
#
# Location of system binaries

AWK=$(command -v awk)
DIG=$(command -v dig)
WHOIS=$(command -v whois)
DATE=$(command -v date)
CUT=$(command -v cut)

# Place to stash temporary files
WHOISCACHE="/var/tmp/whoiscache"

# Give IP of an external DNS-Server for an "ouside" view
EXTDNS=""  # can be set with option -n on commandline as well
BINDCONF="/var/named/chroot/etc/named.conf"  # option -f or this default
WHOISSERVERSFILE="whois-servers.txt"         # Filename/Pathname for list of
                                             # Top-Level Domains and their Whois-Servers

COUNT=0
WARNS=0
CRITS=0
UNKNOWNS=0
OKS=0

#############################################################################
# Purpose: Convert a date from MONTH-DAY-YEAR to Julian format
# Acknowledgements: Code was adapted from examples in the book
#                   "Shell Scripting Recipes: A Problem-Solution Approach"
#                   ( ISBN 1590594711 )
# Arguments:
#   $1 -> ReturnCode 
#   $2 -> ERROR Message for STDOUT
#############################################################################
errorout() {
     (>&2 echo "$2")
     exit $1
}

#############################################################################
# Purpose: Convert a date from MONTH-DAY-YEAR to Julian format
# Acknowledgements: Code was adapted from examples in the book
#                   "Shell Scripting Recipes: A Problem-Solution Approach"
#                   ( ISBN 1590594711 )
# Arguments:
#   $1 -> Month (e.g., 06)
#   $2 -> Day   (e.g., 08)
#   $3 -> Year  (e.g., 2006)
#############################################################################
date2julian() {
    if [ "${1} != "" ] && [ "${2} != ""  ] && [ "${3}" != "" ]
    then
         ## Since leap years add aday at the end of February, 
         ## calculations are done from 1 March 0000 (a fictional year)
         d2j_tmpmonth=$((12 * ${3} + ${1} - 3))
        
          ## If it is not yet March, the year is changed to the previous year
          d2j_tmpyear=$(( ${d2j_tmpmonth} / 12))
        
          ## The number of days from 1 March 0000 is calculated
          ## and the number of days from 1 Jan. 4713BC is added 
          echo $(( (734 * ${d2j_tmpmonth} + 15) / 24 -  2 * ${d2j_tmpyear} + ${d2j_tmpyear}/4
                        - ${d2j_tmpyear}/100 + ${d2j_tmpyear}/400 + $2 + 1721119 ))
    else
          echo 0
    fi
}

#############################################################################
# Purpose: Convert a string month into an integer representation
# Arguments:
#   $1 -> Month name (e.g., Sep)
#############################################################################
getmonth() {
       LOWER=`tolower $1`
              
       case ${LOWER} in
             jan) echo 1 ;;
             feb) echo 2 ;;
             mar) echo 3 ;;
             apr) echo 4 ;;
             may) echo 5 ;;
             jun) echo 6 ;;
             jul) echo 7 ;;
             aug) echo 8 ;;
             sep) echo 9 ;;
             oct) echo 10 ;;
             nov) echo 11 ;;
             dec) echo 12 ;;
               *) echo  0 ;;
       esac
}

#############################################################################
# Purpose: Calculate the number of seconds between two dates
# Arguments:
#   $1 -> Date #1
#   $2 -> Date #2
#############################################################################
date_diff() {
        if [ "${1}" != "" ] &&  [ "${2}" != "" ]
        then
                echo $(expr ${2} - ${1})
        else
                echo 0
        fi
}

##################################################################
# Purpose: Converts a string to lower case
# Arguments:
#   $1 -> String to convert to lower case
##################################################################
tolower() {
     LOWER=`echo ${1} | tr [A-Z] [a-z]`
     echo $LOWER
}

month_to_name() {

	case $1 in
     	1|01) tmonth=jan ;;
     	2|02) tmonth=feb ;;
        3|03) tmonth=mar ;;
        4|04) tmonth=apr ;;
        5|05) tmonth=may ;;
        6|06) tmonth=jun ;;
        7|07) tmonth=jul ;;
        8|08) tmonth=aug ;;
        9|09) tmonth=sep ;;
        10)tmonth=oct ;;
        11) tmonth=nov ;;
        12) tmonth=dec ;;
        *) tmonth=0 ;;
    esac
    echo $tmonth
}


##################################################################
# Purpose: Calculate the age of a file (in days) 
# Arguments:
#   $1 -> Path/Filename
##################################################################
fileage () {

		local FILENAME=$1

		local FILEDATE=$(stat -c%y $FILENAME)
      	local tyear=$(echo ${FILEDATE} | cut -d'-' -f1)
        local tmon=$(echo ${FILEDATE} | cut -d'-' -f2)
        local tday=$(echo ${FILEDATE} | cut -d'-' -f3 | cut -d' ' -f1)
        FILEDATE="$tday-$tmon-$tyear"

	    # Convert the date to seconds, and get the diff between NOW and the expiration date
	    local FILEJULIAN=$(date2julian $((10#$tmon)) ${tday#0} ${tyear})
	    local FILEAGE=$(date_diff ${NOWJULIAN} ${FILEJULIAN})

	    echo $FILEAGE
}



##################################################################
# Purpose:
# Retrieve Informations about a domain from its registry using 
# 'whois' and cache the output in a local file for aconfigurable time 
# as many (eg. SWITCH / .ch)  are limitting the number of requests per 
# day 
#
# whois-servers can be defined per .TLD in a local file 
#
# Arguments:
#   $1 -> domainname.tld
##################################################################
whois () {
	
	local DOMAIN=$1
	local CACHEFILE="$WHOISCACHE/$DOMAIN"

    TLDTYPE="`echo ${DOMAIN} | cut -d '.' -f3 | tr '[A-Z]' '[a-z]'`" 
    if [ "${TLDTYPE}"  == "" ];
    then
	    TLDTYPE="`echo ${DOMAIN} | cut -d '.' -f2 | tr '[A-Z]' '[a-z]'`" 
    fi  	

	# first check if a cached whois result with age <24h is already available
	if [[ (-r "$CACHEFILE") && ( "$(fileage $CACHEFILE)" == "0" ) ]];then

		cat $CACHEFILE

	else 
	   	# create new cache file
	    # check if we know about a valid known WHOIS Server for the TLD or return default
	    if [ -n $WHOIS_SERVER ]; then
	    	WHOIS_SERVER=$( cat $WHOISSERVERSFILE | awk -F" " "/^$TLDTYPE / { print \$2 }" )
			${WHOIS} -h ${WHOIS_SERVER} ${DOMAIN} > ${CACHEFILE}
		else
			${WHOIS} ${DOMAIN} > ${CACHEFILE}
		fi
	
		cat $CACHEFILE
	fi
}

##################################################################
# Purpose:
# Check consistency of DNS zones by comparing WHOIS-Data and
# records queried from the master or any configurable external DNS
# 
# Arguments:
#   $1 -> domainname.tld
##################################################################

check_zone () {
    
    local REGISTRAR=""
    local WHOISDNS
    local DNSNS
    local WHOIS_SERVER="$FIXEDWHOIS_SERVER"
    local WHOISNSERVERS
    local DNSNSERVERS
    local SKIPEXP=0
    local SKIPADNS=0
    local SKIPNSREC=0
    local SKIPSERIAL=0
    local NOTOK=0


     # Save the domain since set will trip up the ordering
    local DOMAIN=$(tolower ${1})

    FOUNDEXCLUDE=`echo ${EXCLUDEDOMS[*]} | grep "\b$DOMAIN\b"`
	if [ "${FOUNDEXCLUDE}" != "" ]; then
		return
	fi

	# Extract TLD from Domainname 
    TLDTYPE="`echo ${DOMAIN} | cut -d '.' -f3 | tr '[A-Z]' '[a-z]'`" 
    if [ "${TLDTYPE}"  == "" ];
    then
	    TLDTYPE="`echo ${DOMAIN} | cut -d '.' -f2 | tr '[A-Z]' '[a-z]'`" 
    fi  	

    # Find Registrar first
	##################################################################################

    # .at
	if [ "${TLDTYPE}" == "at" ]; then # 
        if [ "$(whois $DOMAIN | ${AWK}  '/registrant:/ { print $1 }')" ]; then
        REGISTRAR="At-NIC"
    	fi
    
    # .ch
	elif [ "${TLDTYPE}" == "ch" ]; then # for .ch domain
        REGISTRAR="$(whois $DOMAIN | ${AWK}  '/Registrar:/{while(getline && $0 != ""){ print $0}}')"
    
    # .de
	elif [ "${TLDTYPE}" == "de" ]; then # for .de domain
        if [ "$(whois $DOMAIN | ${AWK}  '/Status:/ { print $1 }')" != "free" ]; then
        REGISTRAR="DeNIC"
    	fi
    # .uk
   	elif [ "${TLDTYPE}" == "uk" ]; then # for .uk domain
    	REGISTRAR=`whois $DOMAIN | ${AWK} -F: '/Registrar:/ && $0 != ""  { getline; REGISTRAR=substr($0,2) } END { print REGISTRAR }'`

    # .cn
   	elif [ "${TLDTYPE}" == "cn" ]; then # for .uk domain
    	REGISTRAR=`whois $DOMAIN | ${AWK} '/Sponsoring Registrar:/ && $3 != "" { print $3 }'`

    # .sk
    elif [ "${TLDTYPE}" == "sk" ]; then
        REGISTRAR=`whois $DOMAIN | ${AWK} '/Tech-name/ && $2 != "" { print $2 }'`

    # .com/.net/.org/.edu  # anything else
    else
    	REGISTRAR=`whois $DOMAIN | ${AWK} -F: '/Registrar:/ && $2 != ""  { print substr($2,2) }'`
    fi
    
    if [ "${REGISTRAR}" = "" ]; then # If the Registrar is NULL, then we didn't get any data
        if [[ `whois $DOMAIN | ${AWK} '/No match for |NOT FOUND|Status: free|No matching record|We do not have an entry/'` ]];
        then 
            prints ${DOMAIN} "WARNING" "Domain unregistered/available"
            SKIPEXP=1
            SKIPADNS=1
        else
            prints ${DOMAIN} "UNKNOWN" "Status Unknown"
            SKIPEXP=1
        fi
    fi
    
    # Check EXPIRY  
    ##################################################################################
    # The whois Expiration data should resemble the following: "Expiration Date: 09-may-2008"

    if [ "${TLDTYPE}" == "at" ]; then 
 	 		SKIPEXP=1 # Skip Check for expiry of Domain registration
 			WHOISDNS=( $( whois $DOMAIN | ${AWK} '/nserver:/ { print $2}') )
 
    elif [ "${TLDTYPE}" == "ch" ]; then 
 	 		SKIPEXP=1 # Skip Check for expiry of Domain registration
 			WHOISDNS=( $( whois $DOMAIN | ${AWK} '/Name servers:/{while(getline && $0 != ""){ print $1}}') )
 			
	elif [ "${TLDTYPE}" == "de" ]; then 
  	 		SKIPEXP=1 # Skip Check for expiry of Domain registration
 			WHOISDNS=( $( whois $DOMAIN | ${AWK} '/Nserver:/ { print $2}') )

    elif [ "${TLDTYPE}" == "me" ]; then 
            tdomdate=`whois $DOMAIN | awk '/Registry Expiry Date:/ { print substr($4,1,10) } '`
            tyear=`echo ${tdomdate} | cut -d'-' -f1`
            tmon=$(month_to_name `echo ${tdomdate} | cut -d'-' -f2`)
            tday=`echo ${tdomdate} | cut -d'-' -f3`
            DOMAINDATE=`echo $tday-$tmonth-$tyear`
            WHOISDNS=( $( whois $DOMAIN | ${AWK} '/Name Server:/ { print $3}'))

	elif [ "${TLDTYPE}" == "biz" ]; then 
            DOMAINDATE=`whois $DOMAIN | awk '/Domain Expiration Date:/ { print $6"-"$5"-"$9 }'`
            WHOISDNS=( $( whois $DOMAIN | ${AWK} '/Name Server:/ { print $3}'))
	
	elif [ "${TLDTYPE}" == "uk" ]; then 
            SKIPEXP=1 # Skip Check for expiry of Domain registration
            WHOISDNS=( $( whois $DOMAIN | ${AWK} '/Name servers:/ {while($0 !~ "^[[:space:]]*$") { getline; print $1}}') )

    elif [ "${TLDTYPE}" == "cn" ]; then 
            tdomdate=`whois $DOMAIN | awk '/Expiration Time:/ { print $3 }'`
            tyear=`echo ${tdomdate} | cut -d'-' -f1`
            tmon=$(month_to_name `echo ${tdomdate} | cut -d'-' -f2`)
            tday=`echo ${tdomdate} | cut -d'-' -f3`
            DOMAINDATE=`echo $tday-$tmon-$tyear`
   			WHOISDNS=( $( whois $DOMAIN | ${AWK} '/Name Server:/ { print $3 }'))         
    
    elif [ "${TLDTYPE}" == "sk" ]; then 
            tdomdate=`whois $DOMAIN | awk '/Valid-date/ { print $NF }'`
            tyear=`echo ${tdomdate} | cut -d'-' -f1`
            tmon=$(month_to_name `echo ${tdomdate} | cut -d'-' -f2`)
            tday=`echo ${tdomdate} | cut -d'-' -f3`
            DOMAINDATE=`echo $tday-$tmon-$tyear`
            WHOISDNS=( $( whois $DOMAIN | ${AWK} '/dns_name/ { print $2 }') )

    
    elif [ "${TLDTYPE}" == "sg" ]; then # for .sg
        	DOMAINDATE=`whois $DOMAIN | ${AWK} '/Expiration/ { print $(NF-1) }'`
            WHOISDNS=( $( whois $DOMAIN | ${AWK} '/Name Servers:/ {while($0 !~ "^[[:space:]]*$") { getline; print $1}}' ) )        	

    else # .com, .net, .org, .cbn, .edu  and may work with others as well
            tdomdate=`whois $DOMAIN | awk '/Registry Expiry Date:/ { print substr($4,1,10) } '`
            tyear=`echo ${tdomdate} | cut -d'-' -f1`
            tmon=$(month_to_name `echo ${tdomdate} | cut -d'-' -f2`)
            tday=`echo ${tdomdate} | cut -d'-' -f3`
            DOMAINDATE=`echo $tday-$tmon-$tyear`
	    	WHOISDNS=( $( whois $DOMAIN | ${AWK} '/Name Server:/ { print $3 }'))
    fi

    # CHECK 1
    # Check Expiry of registration (if not SKIPPED)
    ##################################################################################
    if [ $SKIPEXP == 0 ]; then
	    # Whois data should be in the following format: "13-feb-2006"
	    
	    OLDIFS=$IFS
	    IFS="-"
	    set -- ${DOMAINDATE}
	    MONTH=$(getmonth ${2})
	    IFS=$OLDIFS

	    # Convert the date to seconds, and get the diff between NOW and the expiration date
	    DOMAINJULIAN=$(date2julian ${MONTH} ${1#0} ${3})
	    DOMAINDIFF=$(date_diff ${NOWJULIAN} ${DOMAINJULIAN})

	    if [ ${DOMAINDIFF} -lt 0 ]
	    then
	   		prints ${DOMAIN} "CRITICAL" "Domain expired since ${DOMAINDATE} days ${DOMAINDIFF} ${REGISTRAR}"
	    elif [[ ${DOMAINDIFF} -lt ${WARNDAYS} ]]; then
	        prints ${DOMAIN} "WARNING" "Expiring in ${DOMAINDIFF} days ${REGISTRAR}"
	    fi
	fi

	# CHECK 2
	# Check Zone Setup and NSrecords
	##################################################################################
	# - check if NS records in zone match servers according to WHOIS
	# - check if all servers in whois are resolvable/reachable 
	# - check if the zone is known to each DNS in WHOIS
	# - check if serials are the same on every server

    if [ $SKIPADNS == 0 ]; then

    	local DNSMASTER
    	local DNSMASTER_IP

    	# Part of a Regex to match valid IPv4
	   	iprx='([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'

    	# Use the SOA/Master DNS as authority if no IP is given for an 'outside'-view
    	if [[ -n $EXTDNS ]]; then
    		DNSMASTER=${EXTDNS}
			
			if [[ "$EXTDNS" =~ ^$iprx\.$iprx\.$iprx\.$iprx$ ]]; then
 			    DNSMASTER_IP="${EXTDNS}"
    		else
    			DNSMASTER_IP=$( $DIG A ${DNSMASTER%\.} +short ) 
    		fi	   	    		
    	else
    		DNSMASTER=$( $DIG SOA $DOMAIN \+short | $AWK '{print $1}' )
    		DNSMASTER_IP=$( $DIG A ${DNSMASTER%\.} \+short ) 
    	fi
    	local DNSMASTER_SERIAL=$( $DIG SOA $DOMAIN \@${DNSMASTER%\.} \+short | $AWK '{print $3}' )
    	local DNSMASTER_NSRECS=( $( $DIG NS $DOMAIN \@${DNSMASTER%\.} \+short) )
    	

    	if [ -z $DNSMASTER_IP ]; then
    		 prints ${DOMAIN} "CRITICAL" "DNS hostname '${DNSMASTER#\.}' does not resolve"
    	fi

	   	# 2.0 Compare WHOIS DNS Entries and NS-records in ZONE
	   	local NEW_NSRECS=()
	   	# # first standardize hostnames strings:
	   	# # convert Arrays to Lower Case and strip off trailing dots for 
	   	# # "diff" using 'uniq'
	
	   	for line in "${DNSMASTER_NSRECS[@]}"; do
	   	 	line=$( tolower "${line%\.}" )
	   	 	NEW_NSRECS=( ${NEW_NSRECS[@]} "${line//$'\r'/}" )
	   	done
	   	DNSMASTER_NSRECS=(${NEW_NSRECS[@]})
	   	
	    NEW_NSRECS=()
	   	for line in "${WHOISDNS[@]}"; do
	   	 	line=$( tolower "${line%\.}" )
	   	 	NEW_NSRECS=( ${NEW_NSRECS[@]} "${line//$'\r'/}" )
	   	done
	   	WHOISDNS=(${NEW_NSRECS[@]})

	  	local DNSDIFF=$( echo ${WHOISDNS[@]} ${DNSMASTER_NSRECS[@]} | tr ' ' '\n' | sort | uniq -u )
	   	if [[  $DNSDIFF ]]; then
	   		prints $DOMAIN "WARNING" "DNS in 'whois' differs from NS records in Zone" 
	   		NOTOK=1
	   	fi 

	   	

	   	for dnsserver in "${WHOISDNS[@]}"; do
	   		
	   		# clean special chars (e.g. .com Domains)
	   		dnsserver=${dnsserver//$'\r'/}
	   		
			# choose external DNS or autodetected master DNS in Zone
			if [[ "$EXTDNS" =~ ^$iprx\.$iprx\.$iprx\.$iprx$ ]]; then
 			    dnsserver_ip="${EXTDNS}"
    		else
    			dnsserver_ip=$( $DIG A ${dnsserver%\.} +short ) 
    		fi	   		
	   		
	   		# 2.1 # check if DNS-Server-name is resolvable	
	   		if [[ -n "$dnsserver_ip" ]]; then
	   			# 2.2 # check if zone serials match with master
	   			if [[ "$($DIG SOA $DOMAIN \@$dnsserver_ip +short | awk '{print $3}')" != "${DNSMASTER_SERIAL}" ]]; then
	   				prints $DOMAIN "WARNING" "Serial on $dnsserver differs from MASTER ($DNSMASTER)" && NOTOK=1
	   			fi
	   		else 
	   			 prints ${DOMAIN} "CRITICAL" "DNS hostname '${dnsserver%\.}' does not resolve" 
	   		fi
	   		# 2.3 # check if NS record for this DNS-Server exists in ZONE
	    done
  	fi

	# Finally return "Ok" if all checks passed so far
	##################################################################################
    if [[ $NOTOK == 0 ]]; then
    	prints ${DOMAIN} "OK" "passed all checks"
    fi
}

####################################################
# Purpose: Print a heading with the relevant columns
# Arguments:
#   None
####################################################
print_heading() {
        if [ "${QUIET}" != "TRUE" ]
        then
                printf "%-40s %.38s\n" "Domain" "Status"
                echo "---------------------------------------- --------------------------------------" 
        fi
}

#####################################################################
# Purpose: Add a line with status and Text to an array sorted by status
# Arguments:

#   $1 -> Domain
#   $2 -> Status (OK, WARNING, CRITICAL or UNKNOWN)
#   $3 -> Statustext of domain (e.g., Domain registration expired)

#   prints marbet-china.com "WARNING" "Expiring 16-aug-2017 '35 TECHNOLOGY CO., LTD"
#   prints ${DOMAIN} "OK" "All checks valid"

#####################################################################
prints() {

	local STRING="$(printf "%-40s %s" "$1" "$3")\n"

	NOTOK=1
	case "$2" 
	in
			OK)
				OKOUTPUT="$OKOUTPUT $STRING"
				OKS=$((++OKS))
				;;
			
			WARNING)
				WARNOUTPUT="$WARNOUTPUT $STRING"
				WARNS=$((++WARNS))
				;;

			CRITICAL)
				CRITOUTPUT="$CRITOUTPUT $STRING"
				CRITS=$((++CRITS))
				;;

			*)
				UNKNOUTPUT="$UNKNOUTPUT $STRING"
				UNKNOWNS=$((++UNKNOWNS))
	esac
}

##########################################
# Purpose: Describe how the script works
# Arguments:
#   None
##########################################
usage() {
        echo "Usage: $0 [ -h ] [ -s whois_server ] [ -n external_dnsserver_ip ]"
        echo "          {[ -d domain_name ]} || { -f bind-config [ -x exclude_domain ]  } "
        echo 
        echo "  -d domain        : Domain to analyze (interactive mode) (repeat for multiple domains)"
        echo "  -f domain file   : named.conf where zones are read from (includes not yet processed)"
        echo "  -h               : Print this screen"
        echo "  -n               : Define an IP or hostname of an external DNS for an 'Outside'-View"
        echo "  -s whois server  : custom Whois sever to query for information"
        echo "  -x domain name   : exclude domainname from checks (together with -f) (repeat for multiple domains)"
        echo 
}

### Evaluate the options passed on the command line
while getopts d:f:hn:s:x: option
do
        case "${option}"
        in
                d) DOMAINS=(${DOMAINS[@]} $(tolower ${OPTARG}));;
                f) BINDCONF=${OPTARG};;
                s) FIXEDWHOIS_SERVER=${OPTARG};;
                n) EXTDNS=${OPTARG};;
				x) EXCLUDEDOMS=(${EXCLUDEDOMS[@]} $(tolower ${OPTARG}));;
                h|\?) usage
                      exit 1
        esac
done

### Baseline the dates so we have something to compare to
MONTH=$(${DATE} "+%m")
DAY=$(${DATE} "+%d")
YEAR=$(${DATE} "+%Y")
NOWJULIAN=$(date2julian ${MONTH#0} ${DAY#0} ${YEAR})

mkdir -p $WHOISCACHE || errorout 5 "Could not write whois cache in $WHOISCACHE"

print_heading

if [ -n "$DOMAINS" ]; then

		for zone in ${DOMAINS[@]}; do
		        check_zone $zone
        		COUNT=$((++COUNT))
        done

elif [ -n $BINDCONF ]; then

    for zone in $( cat $BINDCONF |awk '/^zone/ && $2 !~ ".*\\.in-addr\\.arpa" { print $2 }'); do

        # Strip quotes from zone-name
        zone="${zone#\"}"
        zone="${zone%\"}"

        case "$zone" in

            "."|"localhost"|"localdomain"|*.local )
                ;;

            *)
				
                check_zone $zone
                COUNT=$((++COUNT))
                ;;

        esac
    done
fi


# Now spit out all information gathered sorted by status

if [[ ${#CRITOUTPUT[*]} -gt 0 ]]; then
	echo "CRITICAL:"
	echo -e "${CRITOUTPUT}"
fi
if [[ ${#WARNOUTPUT[@]} -gt 0 ]]; then
	echo "WARNING:"
	echo -e "${WARNOUTPUT}"
fi
if [[ ${OKOUTPUT} ]]; then
	echo "OK:"
	echo -e "${OKOUTPUT}"
fi 
if [[ ${#UNKNOUTPUT[@]} -gt 0 ]]; then
	echo "UNKNOWN:"
	echo -e "${UNKNOUTPUT}"
fi

# Add Summary and an extra newline
echo "$COUNT domains checked, ${CRITS} critical, ${WARNS} warnings, ${UNKNOWNS} unknown and ${OKS} Ok"
echo

### Remove the temporary files
rm -f ${WHOIS_TMP}

### Exit with a success indicator compatible with nagios checks
if [[ ${#CRITOUTPUT[*]} -gt 0 ]]; then
	exit 2
elif [[ ${#WARNOUTPUT[@]} -gt 0 ]]; then
    exit 1
elif [[ ${#UNKNOUTPUT[@]} -gt 0 ]]; then
	exit 3
fi
exit 0
