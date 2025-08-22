#!/bin/bash
set -e

echo "=== Creating virtual SDN topology with 3 OVS bridges ==="

# === Enable IPv4 Forwarding
sysctl -w net.ipv4.ip_forward=1

# === Create OVS bridges with specific DPIDs ===
ovs-vsctl add-br InternetOut
ovs-vsctl set bridge InternetOut other-config:datapath-id=0000000000000001
# ovs-vsctl --no-wait set Bridge InternetOut fail-mode=secure

ovs-vsctl add-br Intranet
ovs-vsctl set bridge Intranet other-config:datapath-id=0000000000000002
# ovs-vsctl --no-wait set Bridge Intranet fail-mode=secure

ovs-vsctl add-br SvrFarm
ovs-vsctl set bridge SvrFarm other-config:datapath-id=0000000000000003
# ovs-vsctl --no-wait set Bridge SvrFarm fail-mode=secure

# === Create controller namespace ===
ip netns add ns-ctrl

# === Create veth pairs ===
ip link add veth_out1 type veth peer name veth_intra3   # InternetOut:1 <-> Intranet:3
ip link add veth_out2 type veth peer name veth_farm3    # InternetOut:2 <-> SvrFarm:3
ip link add veth_intra2 type veth peer name veth_farm1  # Intranet:2 <-> SvrFarm:1
ip link add veth_ns type veth peer name veth_intra4 #Intranet:4 <-> Controller

# === Connect veth ends to respective bridges ===
ovs-vsctl add-port InternetOut veth_out1 -- set Interface veth_out1 ofport_request=1
ovs-vsctl add-port InternetOut veth_out2 -- set Interface veth_out2 ofport_request=2
ovs-vsctl add-port InternetOut ens33 -- set Interface ens33 ofport_request=3
ovs-vsctl add-port Intranet veth_intra4 -- set Interface veth_intra4 ofport_request=4

ovs-vsctl add-port Intranet ens34 -- set Interface ens34 ofport_request=1
ovs-vsctl add-port Intranet veth_intra2 -- set Interface veth_intra2 ofport_request=2
ovs-vsctl add-port Intranet veth_intra3 -- set Interface veth_intra3 ofport_request=3

ovs-vsctl add-port SvrFarm veth_farm1 -- set Interface veth_farm1 ofport_request=1
ovs-vsctl add-port SvrFarm ens35 -- set Interface ens35 ofport_request=2
ovs-vsctl add-port SvrFarm veth_farm3 -- set Interface veth_farm3 ofport_request=3

# === Bring up interfaces ===
for intf in veth_out1 veth_out2 veth_intra3 veth_intra2 veth_farm1 veth_farm3 veth_intra4; do
  ip link set $intf up
done
ip link set veth_ns netns ns-ctrl

# === Assign IP addresses ===
ip addr flush dev ens33
ip addr flush dev ens34
ip addr flush dev ens35
ip addr add 192.168.230.155/24 dev ens33
ip addr add 10.10.0.2/16 dev ens34
ip addr add 10.20.0.2/16 dev ens35
ip addr add 10.0.0.1/24 dev veth_out1
ip addr add 10.0.0.2/24 dev veth_out2
ip addr add 10.0.0.3/24 dev veth_intra2
ip addr add 10.0.0.4/24 dev veth_intra3
ip addr add 10.0.0.5/24 dev veth_farm1
ip addr add 10.0.0.6/24 dev veth_farm3

ip addr add 10.10.0.3/16 dev veth_intra4

# === Assign IP addresses for controller ===
ip netns exec ns-ctrl ip addr add 10.10.0.99/24 dev veth_ns
ip netns exec ns-ctrl ip link set veth_ns up
ip netns exec ns-ctrl ip link set lo up
ip netns exec ns-ctrl ip route add default via 10.10.0.3

# === Bring up physical interfaces (assume already up, but just in case) ===
ip link set ens33 up
ip link set ens34 up
ip link set ens35 up
ip link set InternetOut up
ip link set Intranet up
ip link set SvrFarm up

# === Set controller for each bridge ===
ovs-vsctl set-controller InternetOut tcp:10.10.0.99:6633
ovs-vsctl set-controller Intranet tcp:10.10.0.99:6633
ovs-vsctl set-controller SvrFarm tcp:10.10.0.99:6633

echo "=== Setup complete ==="

# === Launch Controller
# ip netns exec ns-ctrl python3.9 pox/pox.py launch
