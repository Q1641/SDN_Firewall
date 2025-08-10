#!/bin/bash
set -e

echo "=== Cleaning up OVS switches and veth pairs ==="

ovs-vsctl del-br InternetOut || true
ovs-vsctl del-br Intranet || true
ovs-vsctl del-br SvrFarm || true

for veth in veth_out1 veth_out2 veth_intra2 veth_intra3 veth_farm1 veth_farm3; do
  ip link del $veth 2>/dev/null || true
done

echo "=== Cleanup complete ==="
