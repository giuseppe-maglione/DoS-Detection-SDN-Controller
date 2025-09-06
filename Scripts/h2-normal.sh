#!/bin/bash

DST = 10.0.0.3
PORT_UDP = 5003
PORT_TCP = 5004

echo "[H2] Avvio traffico NORMALE"

for cycle in {1..5}; do
    echo "[H1] Ciclo $cycle in corso..."

    # 1. UDP medio
    iperf -c $DST -p $PORT_UDP -u -b 2M -t 25

    # 2. TCP leggero
    iperf -c $DST -p $PORT_TCP -b 1M -t 35

    # 3. UDP basso
    iperf -c $DST -p $PORT_UDP -u -b 150K -t 20

    # 4. Ping variabile
    for i in {1..25}; do
        SIZE=$((50 + RANDOM % 150))
        SLEEP=$(awk -v min=0.3 -v max=1 'BEGIN{s=min+rand()*(max-min); print s}')
        ping -c 1 -s $SIZE $DST > /dev/null
        sleep $SLEEP
    done

    echo "[H2] Ciclo $cycle completato."
    SLEEP=$(awk -v min=1 -v max=3 'BEGIN{s=min+rand()*(max-min)}')
    sleep $SLEEP
done

echo "[H2] Script completato!"
