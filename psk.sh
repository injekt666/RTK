#!/bin/bash

cat /etc/NetworkManager/system-connections/* |grep -E "^id|^psk"
