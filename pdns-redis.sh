#!/bin/bash
for DIR in /usr/local/lib/python*/site-packages; do
  export PYTHONPATH=$DIR:$PYTHONPATH
done
exec $(dirname $0)/pdns_redis.py \
	-R localhost:9076 -A /etc/powerdns/redis.pass \
	"$@" 
