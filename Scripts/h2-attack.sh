#!/bin/bash

DST = 10.0.0.3
PORT_UDP = 5003
PORT_TCP = 5004

echo "[H2] Avvio traffico di ATTACCO"

for cycle in {1..10}; do
    echo "[H2] Ciclo $cycle in corso..."

    # 1. UDP flood (DDoS con h1)
    iperf -c $DST -p $PORT_UDP -u -b 12M -t 15

    # 2. TCP flood
    iperf -c $DST -p $PORT_TCP -b 8M -t 10

    # 3. Stealth (solo h1)
    iperf -c $DST -p $PORT_TCP -b 0.1M -t 30

    echo "[H2] Ciclo $cycle completato."
    SLEEP=$(awk -v min=1 -v max=3 'BEGIN{s=min+rand()*(max-min)}')
    sleep $SLEEP
done

echo "[H2] Script completato!"
