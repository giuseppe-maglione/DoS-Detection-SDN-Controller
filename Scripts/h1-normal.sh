#!/bin/bash

TARGET=10.0.0.3
PORT_UDP=5001
PORT_TCP=5002

echo "[H1] Avvio traffico NORMALE"

for cycle in {1..5}; do
    echo "[H1] Ciclo $cycle in corso..."

    # 1. UDP leggero
    iperf -c $TARGET -p $PORT_UDP -u -b 1M -t 35

    # 2. TCP medio
    iperf -c $TARGET -p $PORT_TCP -b 2M -t 25

    # 3. UDP leggero
    iperf -c $TARGET -p $PORT_UDP -u -b 500K -t 20
    
    # 4. Ping variabile
    for i in {1..30}; do
        SIZE=$((50 + RANDOM % 50))
        SLEEP=$(awk -v min=0.2 -v max=0.8 'BEGIN{s=min+rand()*(max-min); print s}')
        ping -c 1 -s $SIZE $TARGET > /dev/null
        sleep $SLEEP
    done

    echo "[H1] Ciclo $cycle completato."
    SLEEP=$(awk -v min=0 -v max=1 'BEGIN{s=min+rand()*(max-min)}')
    sleep $SLEEP
done

echo "[H1] Script completato!"
