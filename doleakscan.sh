#!/bin/bash

dir=/root/dong
cd ${dir}
rm -fr fc_leakscan/
tar xf fc_leakscan-src.tar.gz
cd fc_leakscan/
make clean;make
./fc-leakscan -d 
