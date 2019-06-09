#!/bin/sh
set -ex
gcc -O2 -Wall -o cc2531 cc2531.c -s
#sudo install -m 2755 cc2531 /usr/lib/x86_64-linux-gnu/wireshark/extcap/cc2531
