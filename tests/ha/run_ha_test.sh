#!/bin/bash
# Two-node HA switchover test in network namespaces (run as root, Linux, e.g. docker --privileged).
# Usage: tests/ha/run_ha_test.sh [extra lb args...]   e.g. --backend-source-vip (or: make ha-test)
# Env: DUR (client seconds), SWITCHES (seconds between SIGUSR1 switchovers), TCPDUMP=1, SSDUMP=1
set -u
cd "$(dirname "$0")/../.."
LB=./advanced_load_balancer
EXTRA=("$@")
VIP=10.50.0.100
cleanup() {
    pkill -f advanced_load_balancer 2>/dev/null; pkill -f backend.py 2>/dev/null
    for n in lb1 lb2 be cl; do ip netns del $n 2>/dev/null; done
    ip link del br0 2>/dev/null
}
trap cleanup EXIT
cleanup; sleep 0.2

ip link add br0 type bridge && ip link set br0 up
i=0
for n in lb1:11 lb2:12 be:20 cl:30; do
    ns=${n%%:*}; host=${n##*:}
    ip netns add $ns
    ip link add v-$ns type veth peer name eth0 netns $ns
    ip link set v-$ns master br0 up
    ip -n $ns addr add 10.50.0.$host/24 dev eth0
    ip -n $ns link set eth0 up
    ip -n $ns link set lo up
done

ip netns exec be python3 tests/ha/backend.py 9000 65536 0.005 &
sleep 0.5
start_lb() { # name ip prio peer
    # Private /tmp per node: a shared one enables the same-host UNIX fd-passing channel,
    # which would hand lb1's own sockets to lb2 and bypass the cross-host TCP_REPAIR path
    ip netns exec $1 unshare -m sh -c 'mount -t tmpfs tmpfs /tmp && exec "$@"' sh $LB -p 8080 -b 10.50.0.20:9000 -w 2 --no-tui --timeout 60 \
        --cluster --vip $VIP/24 --vip-iface eth0 --vrrp-priority $3 --no-multicast \
        --cluster-bind $2:9550 --cluster-peer $4:9550 --cluster-secret ha-test "${EXTRA[@]}" \
        > /tmp/$1.log 2>&1 &
}
start_lb lb1 10.50.0.11 150 10.50.0.12
start_lb lb2 10.50.0.12 100 10.50.0.11
sleep 3

master() { for n in lb1 lb2; do ip -n $n addr | grep -q "$VIP/" && echo $n; done; }
echo "initial master: $(master)"
for n in lb1 lb2 cl; do echo "$n mac: $(ip -n $n link show eth0 | awk '/ether/{print $2}')"; done
[ -n "${TCPDUMP:-}" ] && { ip netns exec cl tcpdump -nn -e -l -i eth0 -c 60 "${TCPDUMP_FILTER:-tcp[tcpflags] \& (tcp-rst|tcp-syn) != 0 or arp}" > /tmp/tcpdump.out 2>&1 & sleep 1; }

DUR=${DUR:-14}
SWITCHES=${SWITCHES:-3 4 4}
ip netns exec cl python3 tests/ha/client.py $VIP 8080 8 $DUR > /tmp/client.out 2>&1 &
CPID=$!
for t in $SWITCHES; do
    sleep $t
    m=$(master)
    echo "switchover: SIGUSR1 -> $m"
    pkill -USR1 -f "cluster-bind 10.50.0.$([ "$m" = lb1 ] && echo 11 || echo 12)"
    sleep 0.5; echo "  new master: $(master)"
    if [ -n "${SSDUMP:-}" ]; then
        sleep 1; nm=$(master)
        echo "--- ss on $nm (backend side)"; ip netns exec $nm ss -tnoi "dport = :9000" | head -12
        echo "--- ss on $nm (client side)"; ip netns exec $nm ss -tnoi "sport = :8080" | head -8
        echo "--- ss on be"; ip netns exec be ss -tnoi "sport = :9000" | head -12
        echo "--- be neigh"; ip -n be neigh
        for n in lb1 lb2; do echo "--- $n cluster tcp"; ip netns exec $n ss -tnp "( sport = :9550 or dport = :9550 )"; done
    fi
done
wait $CPID
[ -n "${TCPDUMP:-}" ] && { sleep 0.5; echo "--- tcpdump"; head -40 /tmp/tcpdump.out; ip -n cl neigh; for n in lb1 lb2; do ip -n $n -br link; done; for n in lb1 lb2; do echo "$n OUTPUT:"; ip netns exec $n iptables-legacy -S OUTPUT -v 2>/dev/null | tail -3; done; }
cat /tmp/client.out
echo "--- lb logs (HA) ---"
grep -hE "HA STREAM|HA MIGRATED|HA RESTORE ERR|RST FILTER.*error|SWITCHOVER" /tmp/lb1.log /tmp/lb2.log | sed -E 's/\x1b\[[0-9;]*m//g; s/^\[[0-9:]+\] //; s/[0-9]+/N/g' | sort | uniq -c | sort -rn | head -20
