#!/bin/bash
set -euo pipefail

### === Config ===
BR_OUT="InternetOut"   # DPID 1
BR_IN="Intranet"       # DPID 2
BR_SF="SvrFarm"        # DPID 3

DPID_OUT="0000000000000001"
DPID_IN="0000000000000002"
DPID_SF="0000000000000003"

# Physical NICs (already cabled as you planned)
IF_OUT="ens33"         # public link
IF_IN="ens34"          # 10.10.x
IF_SF="ens35"          # 10.20.x

# Bridge IPs move onto the bridges (NOT on the enslaved NICs)
IP_OUT="192.168.230.155/24"
IP_IN="10.10.0.2/24"
IP_SF="10.20.0.2/16"

# veths between bridges
VETH_OUT1="veth_out1"     VETH_IN3="veth_intra3"   # OUT:1 <-> IN:3
VETH_OUT2="veth_out2"     VETH_SF3="veth_farm3"    # OUT:2 <-> SF:3
VETH_IN2="veth_intra2"    VETH_SF1="veth_farm1"    # IN:2  <-> SF:1

# Namespace plugged to Intranet port 4 (dataplane presence)
NS="ns-ctrl"
VETH_NS="veth_ns"         # goes inside namespace
VETH_IN4="veth_intra4"    # attaches to Intranet (ofport 4)

# Dedicated mgmt veth so OVS (host) can always reach controller
VETH_MGMT_H="veth_mgmt_h"
VETH_MGMT_N="veth_mgmt_n"
MGMT_HOST_IP="10.99.0.1/30"
MGMT_NS_IP="10.99.0.2/30"
CTRL_IP="10.99.0.2"
CTRL_PORT=6633

# POX command (adjust path if needed)
POX_CMD=(python3.9 pox/pox.py launch)

### === Cleanup ===
cleanup() {
  echo "[*] Cleaning up…"
  set +e
  pkill -P "${CTRL_PID:-999999}" 2>/dev/null || true

  ovs-vsctl --if-exists del-br "$BR_OUT"
  ovs-vsctl --if-exists del-br "$BR_IN"
  ovs-vsctl --if-exists del-br "$BR_SF"

  ip link del "$VETH_OUT1" 2>/dev/null || true
  ip link del "$VETH_OUT2" 2>/dev/null || true
  ip link del "$VETH_IN2"  2>/dev/null || true
  ip link del "$VETH_IN4"  2>/dev/null || true
  ip link del "$VETH_MGMT_H" 2>/dev/null || true

  ip netns del "$NS" 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s 10.99.0.0/30 -o ens32 -j MASQUERADE || true
  set -e
}
trap cleanup EXIT

sysctl -w net.ipv4.ip_forward=1
echo "=== Building 3-bridge lab with controller in a namespace ==="

# Ensure OVS is up
modprobe openvswitch 2>/dev/null || true

## Bridges (fail-mode=secure is fine because controller path is out-of-band)
ovs-vsctl --may-exist add-br "$BR_OUT"
ovs-vsctl set bridge "$BR_OUT" other-config:datapath-id="$DPID_OUT"
ovs-vsctl --no-wait set Bridge "$BR_OUT" fail-mode=secure

ovs-vsctl --may-exist add-br "$BR_IN"
ovs-vsctl set bridge "$BR_IN"  other-config:datapath-id="$DPID_IN"
ovs-vsctl --no-wait set Bridge "$BR_IN"  fail-mode=secure

ovs-vsctl --may-exist add-br "$BR_SF"
ovs-vsctl set bridge "$BR_SF"  other-config:datapath-id="$DPID_SF"
ovs-vsctl --no-wait set Bridge "$BR_SF"  fail-mode=secure

## Inter-bridge veths
ip link add "$VETH_OUT1" type veth peer name "$VETH_IN3"   # OUT:1 <-> IN:3
ip link add "$VETH_OUT2" type veth peer name "$VETH_SF3"   # OUT:2 <-> SF:3
ip link add "$VETH_IN2"  type veth peer name "$VETH_SF1"   # IN:2  <-> SF:1

## Attach ports with fixed ofports
ovs-vsctl add-port "$BR_OUT" "$VETH_OUT1" -- set Interface "$VETH_OUT1" ofport_request=1
ovs-vsctl add-port "$BR_OUT" "$VETH_OUT2" -- set Interface "$VETH_OUT2" ofport_request=2
ovs-vsctl add-port "$BR_OUT" "$IF_OUT"    -- set Interface "$IF_OUT"    ofport_request=3

ovs-vsctl add-port "$BR_IN"  "$IF_IN"     -- set Interface "$IF_IN"     ofport_request=1
ovs-vsctl add-port "$BR_IN"  "$VETH_IN2"  -- set Interface "$VETH_IN2"  ofport_request=2
ovs-vsctl add-port "$BR_IN"  "$VETH_IN3"  -- set Interface "$VETH_IN3"  ofport_request=3

ovs-vsctl add-port "$BR_SF"  "$VETH_SF1"  -- set Interface "$VETH_SF1"  ofport_request=1
ovs-vsctl add-port "$BR_SF"  "$IF_SF"     -- set Interface "$IF_SF"     ofport_request=2
ovs-vsctl add-port "$BR_SF"  "$VETH_SF3"  -- set Interface "$VETH_SF3"  ofport_request=3

## Namespace (controller) + dataplane port4 to Intranet
ip netns add "$NS"
ip link add "$VETH_NS" type veth peer name "$VETH_IN4"
ip link set "$VETH_NS" netns "$NS"
ovs-vsctl add-port "$BR_IN" "$VETH_IN4" -- set Interface "$VETH_IN4" ofport_request=4

## Dedicated mgmt veth host<->ns (NOT attached to OVS) for controller channel
ip link add "$VETH_MGMT_H" type veth peer name "$VETH_MGMT_N"
ip link set "$VETH_MGMT_N" netns "$NS"

## Bring up host-side links
for i in "$VETH_OUT1" "$VETH_OUT2" "$VETH_IN3" "$VETH_IN2" "$VETH_SF1" "$VETH_SF3" "$VETH_IN4" "$VETH_MGMT_H"; do
  ip link set "$i" up
done

## Move L3 IPs to the BRIDGES (not on enslaved NICs)
ip addr flush dev "$IF_OUT" || true
ip addr flush dev "$IF_IN"  || true
ip addr flush dev "$IF_SF"  || true

ip addr add "$IP_OUT" dev "$BR_OUT"
ip addr add "$IP_IN"  dev "$BR_IN"
ip addr add "$IP_SF"  dev "$BR_SF"

ip link set "$BR_OUT" up
ip link set "$BR_IN"  up
ip link set "$BR_SF"  up
ip link set "$IF_OUT" up
ip link set "$IF_IN"  up
ip link set "$IF_SF"  up

## Namespace addressing
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$VETH_NS" up
ip netns exec "$NS" ip link set "$VETH_MGMT_N" up

# Controller mgmt IPs (out-of-band path used by OVS to reach controller)
ip addr add "$MGMT_HOST_IP" dev "$VETH_MGMT_H"
ip netns exec "$NS" ip addr add "$MGMT_NS_IP" dev "$VETH_MGMT_N"

ip netns exec "$NS" ip addr add 10.10.10.10/24 dev veth_ns
ip netns exec "$NS" ip link set veth_ns up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route del default || true
ip netns exec "$NS" ip route replace 10.0.0.0/8 via 10.10.10.1 dev "$VETH_NS"
ip netns exec "$NS" ip route add default via 10.99.0.1 dev "$VETH_MGMT_N"
iptables -t nat -A POSTROUTING -s 10.99.0.0/30 -o ens32 -j MASQUERADE

## Point all bridges to controller (over mgmt veth)
ovs-vsctl set-controller "$BR_OUT" tcp:"$CTRL_IP":"$CTRL_PORT"
ovs-vsctl set-controller "$BR_IN"  tcp:"$CTRL_IP":"$CTRL_PORT"
ovs-vsctl set-controller "$BR_SF"  tcp:"$CTRL_IP":"$CTRL_PORT"

## Start POX inside namespace
echo "[*] Starting POX inside $NS at $CTRL_IP:$CTRL_PORT ..."
ip netns exec "$NS" "${POX_CMD[@]}" & CTRL_PID=$!

echo "=== Running. Press Ctrl+C to clean up ==="
# Keep process alive so trap can clean
while true; do sleep 1; done
