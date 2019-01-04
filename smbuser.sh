#!/bin/bash
  
if [[ $1 == "" ]]; then
        echo "./smbuser.sh <ip>";
        exit 1;
fi

RPCCLIENT=$(which rpcclient)
IP=$1
for u in $(cat john.txt); do $RPCCLIENT -U "" $IP -N --command="lookupnames $u"; done |grep "User: 1"
