#!/bin/bash
DST=10.0.0.3
PORT_UDP=5003
PORT_TCP=5004

echo "[H2] Avvio traffico di ATTACCO"

for cycle in {1..10}; do
    echo "[H2] Ciclo $cycle in corso..."

    # 1. UDP flood (DDoS con h1)
    iperf -c $DST -p $PORT_UDP -u -b 4M -t 25
    # 2. TCP flood (DDoS con h1)
    iperf -c $DST -p $PORT_TCP -b 6M -t 25
    # 3. Stealth (solo h1)
    iperf -c $DST -p $PORT_TCP -b 1M -t 30

    echo "[H2] Ciclo $cycle completato."
done

echo "[H2] Script completato!"