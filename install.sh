#!/bin/bash

chmod +x qps.py
cp qps.py /usr/bin/qps
rsync * --exclude=install.sh --exclude=qps.py /lib/quickportscan.1.0
