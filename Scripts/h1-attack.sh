#!/bin/bash
DST=10.0.0.3
PORT_UDP=5001
PORT_TCP=5002

echo "[H1] Avvio traffico di ATTACCO"

for cycle in {1..10}; do
    echo "[H1] Ciclo $cycle in corso..."

    # 1. UDP flood (DDoS con h2)
    iperf -c $DST -p $PORT_UDP -u -b 15M -t 25
    # 2. TCP flood (DDoS con h2)
    iperf -c $DST -p $PORT_TCP -b 10M -t 25
    # 3. Stealth
    for i in {1..30}; do
        SIZE=$((500 + RANDOM % 500))   # 500–1000B
        ping -c 1 -s $SIZE $DST > /dev/null
        sleep 1
    done

    echo "[H1] Ciclo $cycle completato."
done

echo "[H1] Script completato!"