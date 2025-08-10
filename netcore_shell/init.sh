#!/bin/bash
set -e

echo "=== Creating virtual SDN topology with 3 OVS bridges ==="

# === Enable IPv4 Forwarding
sysctl -w net.ipv4.ip_forward=1

# === Create OVS bridges with specific DPIDs ===
ovs-vsctl add-br InternetOut
ovs-vsctl set bridge InternetOut other-config:datapath-id=0000000000000001
ovs-vsctl --no-wait set Bridge InternetOut fail-mode=secure

ovs-vsctl add-br Intranet
ovs-vsctl set bridge Intranet other-config:datapath-id=0000000000000002
ovs-vsctl --no-wait set Bridge Intranet fail-mode=secure

ovs-vsctl add-br SvrFarm
ovs-vsctl set bridge SvrFarm other-config:datapath-id=0000000000000003
ovs-vsctl --no-wait set Bridge SvrFarm fail-mode=secure

# === Create veth pairs ===
ip link add veth_out1 type veth peer name veth_intra3   # InternetOut:1 <-> Intranet:3
ip link add veth_out2 type veth peer name veth_farm3    # InternetOut:2 <-> SvrFarm:3
ip link add veth_intra2 type veth peer name veth_farm1  # Intranet:2 <-> SvrFarm:1

# === Connect veth ends to respective bridges ===
ovs-vsctl add-port InternetOut veth_out1 -- set Interface veth_out1 ofport_request=1
ovs-vsctl add-port InternetOut veth_out2 -- set Interface veth_out2 ofport_request=2
ovs-vsctl add-port InternetOut ens33 -- set Interface ens33 ofport_request=3

ovs-vsctl add-port Intranet ens34 -- set Interface ens34 ofport_request=1
ovs-vsctl add-port Intranet veth_intra2 -- set Interface veth_intra2 ofport_request=2
ovs-vsctl add-port Intranet veth_intra3 -- set Interface veth_intra3 ofport_request=3

ovs-vsctl add-port SvrFarm veth_farm1 -- set Interface veth_farm1 ofport_request=1
ovs-vsctl add-port SvrFarm ens35 -- set Interface ens35 ofport_request=2
ovs-vsctl add-port SvrFarm veth_farm3 -- set Interface veth_farm3 ofport_request=3

# === Bring up interfaces ===
for intf in veth_out1 veth_out2 veth_intra3 veth_intra2 veth_farm1 veth_farm3; do
  ip link set $intf up
done

# === Assign IP addresses ===
ip addr add 10.0.0.1/24 dev veth_out1
ip addr add 10.0.0.2/24 dev veth_out2
ip addr add 10.0.0.3/24 dev veth_intra2
ip addr add 10.0.0.4/24 dev veth_intra3
ip addr add 10.0.0.5/24 dev veth_farm1
ip addr add 10.0.0.6/24 dev veth_farm3

# === Bring up physical interfaces (assume already up, but just in case) ===
ip link set ens33 up
ip link set ens34 up
ip link set ens35 up
ip link set InternetOut up
ip link set Intranet up
ip link set SvrFarm up

# === Set controller for each bridge ===
ovs-vsctl set-controller InternetOut tcp:127.0.0.1:6633
ovs-vsctl set-controller Intranet tcp:127.0.0.1:6633
ovs-vsctl set-controller SvrFarm tcp:127.0.0.1:6633

echo "=== Setup complete ==="
