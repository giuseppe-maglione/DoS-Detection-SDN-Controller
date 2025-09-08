#!/bin/bash

TARGET=10.0.0.3
PORT_UDP=5003
PORT_TCP=5004

echo "[H2] Avvio traffico di ATTACCO"

for cycle in {1..20}; do
    echo "[H2] Ciclo $cycle in corso..."

    # 1. UDP flood (DDoS con h1)
    iperf -c $TARGET -p $PORT_UDP -u -b 6M -t 25
    
    # 2. TCP flood (DDoS con h1)
    iperf -c $TARGET -p $PORT_TCP -b 4M -t 25

    echo "[H2] Ciclo $cycle completato."
done

echo "[H2] Script completato!"s
