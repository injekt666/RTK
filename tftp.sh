#!/bin/bash

if [[ $1  == "" ]]; then
        echo "Usage: ./tftp.sh <ip>";
        exit 1;
fi

IP=$1
file_list=$(cat files.txt)

for line in $file_list
do
        tftp $IP << EOF
        verbose
        binary
        get $line
EOF
done
#delete empty files when we're finished
#find . -type f -empty -delete
