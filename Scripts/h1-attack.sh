#!/bin/bash

TARGET=10.0.0.3
PORT_UDP=5001
PORT_TCP=5002

echo "[H1] Avvio traffico di ATTACCO"

for cycle in {1..20}; do
    echo "[H1] Ciclo $cycle in corso..."

    # 1. UDP flood (DDoS con h2)
    iperf -c $TARGET -p $PORT_UDP -u -b 4M -t 25
    
    # 2. TCP flood (DDoS con h2)
    iperf -c $TARGET -p $PORT_TCP -b 6M -t 25

    echo "[H1] Ciclo $cycle completato."
done

echo "[H1] Script completato!"
