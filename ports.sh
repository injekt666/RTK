#!/bin/bash

if [[ $1 == "" ]]; then
    echo "./ports.sh XML";
    exit 1;
fi

XMLFILE="$1"

cat $XMLFILE |grep portid |cut -f3 -d" " |cut -f2 -d"=" |cut -f1 -d">" |cut -f2 -d'"'
