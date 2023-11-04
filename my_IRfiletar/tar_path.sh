#!/bin/bash

mkdir -p cmd_collection

find /home/ -type f -size +512k > ./cmd_collection/file_512k_up
find /etc/ -readable -type f 2>/dev/null > ./cmd_collection/suid_file
find / -mtime -2 -ls 2>/dev/null > ./cmd_collection/file_not_older_then_2days
lsof -i > ./cmd_collection/listening_PIDport_proc
netstat -nap > ./cmd_collection/conn_info
ps aux > ./cmd_collection/running_proc
crontab -l > ./cmd_collection/user_crontab

cat $1 | tr "\n" " " | xargs -I@ sh -c 'tar zvcf IR_list.tar.gz @ cmd_collection'

rm -rf cmd_collection
