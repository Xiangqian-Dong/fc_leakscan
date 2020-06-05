#!/bin/bash
dir=/home/xiang/project/web-waf
cd ${dir}
tar cfz nginx-src.tar.gz nginx/
ansible 192.168.20.99 -m copy -a "src=./nginx-src.tar.gz dest=/root/waf"
ansible 192.168.20.99 -m shell -a "/root/waf/dongx.sh"

