#!/bin/sh

# Configuration
PF="/run/openbmc/bmc_position"
INT="${CHECK_INTERVAL:-30}"
IF="eth2"
IP="9.6.28.10"

# Get target IP based on BMC position
get_ip() {
    [ ! -f "$PF" ] && return 1
    P=$(cat "$PF" 2>/dev/null)
    [ "$P" -eq 0 ] && D=1 || D=0
    TIP="${IP}${D}"
    return 0
}

# Test connectivity to target IP
ping_test() {
    ip neigh flush dev "$IF" 2>/dev/null
    sleep 1
    ping -I "$IF" -c 2 -W 2 "$TIP" >/dev/null 2>&1
}

# Recover network interface
recover() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Ping failed! Recovering..."
    ip link set "$IF" promisc on
    ip link set "$IF" down
    sleep 2
    ip link set "$IF" up
    sleep 3

    if ping_test; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Recovery OK"
        return 0
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Recovery failed"
        return 1
    fi
}

# Main monitoring loop
while true; do
    if get_ip; then
        if ! ping_test; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Ping failed to $TIP (Pos:$P)"
            recover
        fi
    fi
    sleep "$INT"
done

