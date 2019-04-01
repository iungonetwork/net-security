#!/bin/sh

ip route add $SIGNET via $SIGNET_GW

cd /app

SCRIPT=${1:-start}

npm run $SCRIPT