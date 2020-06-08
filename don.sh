#!/bin/bash
dir=/home/xiang/project/firecloud/
cd ${dir}
tar cfz fc_leakscan-src.tar.gz fc_leakscan/
ansible 192.168.20.91 -m copy -a "src=./fc_leakscan-src.tar.gz dest=/root/dong"
ansible 192.168.20.91 -m shell -a "/root/dong/doleakscan.sh"

