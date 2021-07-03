#!/bin/bash

# Based on a script in "How to Investigate Like a Rockstar"
# This does some preliminary checks on large groups of IP addresses
#
# USE
# Create a file called ips.txt containing the IP addresses
# Ensure there are no blank lines at the end of the document
# Run script

filename=$(date -u --iso-8601="seconds" | cut -d '+' -f1 | tr : -)"_output.csv"

echo "Lookups commenced at $(date)"
echo "ip,dns,owner,netname,country,person,email,created,last_modified" > $filename
while read -r ip
do
    echo $ip
    whois $ip > whoisip
    owner=`cat whoisip | grep -i -m 1 "owner:" | sed 's/owner:       //g'`
    netname=`cat whoisip | grep -i -m 1 "netname:" | sed 's/netname:        //g'`
    descr=`cat whoisip | grep -i -m 1 "descr:" | sed 's/descr:          //g'`
    country=`cat whoisip | grep -i -m 1 "country"  |  sed 's/country:     //g'`
    person=`cat whoisip | grep -i -m 1 "person:"  | sed 's/person:      //g'`
    created=`cat whoisip | grep -i -m 1 "created" | sed 's/created:        //g'`
    last_modified=`cat whoisip | grep -i -m 1 "last-modified:" | sed 's/last-modified:  //g'`
    email=`cat whoisip | grep -m 1 "email:" | sed 's/email:      //g'`
    if [[  -z $created ]] ; then
        created=`cat whoisip | grep -i -m 1 "RegDate" | sed 's/RegDate:        //g'`      
    fi
    if [[  -z $last_modified ]] ; then
        last_modified=`cat whoisip | grep -i -m 1 "updated" | sed 's/Updated:        //g'`      
    fi
    if [[ -z $last_modified ]]; then
        last_modified=`cat whoisip | grep -i -m 1 "changed" | sed 's/changed: //g'`
    fi
    echo $ip","$dns","$owner","$netname","$country","$person","$email","$created","$last_modified >> $filename
done <ips.txt
