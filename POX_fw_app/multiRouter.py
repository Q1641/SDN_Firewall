import copy
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.libopenflow_01 import *
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet
from pox.lib.packet.ethernet import ETHER_ANY, ETHER_BROADCAST
from pox.lib.packet import arp, ipv4, icmp
from pox.lib.packet.icmp import TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY, TYPE_DEST_UNREACH, CODE_UNREACH_NET, CODE_UNREACH_HOST, echo

log = core.getLogger()

portToIP = {}
# DPID 1: InternetOut
portToIP[1] = {
    1: "10.0.0.1",     # veth_out1
    2: "10.0.0.2",     # veth_out2
    3: "192.168.230.155"     # ens33
}

# DPID 2: Intranet
portToIP[2] = {
    1: "10.10.0.2",    # ens34
    2: "10.0.0.3",     # veth_intra2
    3: "10.0.0.4",     # veth_intra3
    4: "10.10.10.1"     # veth_intra4
}

# DPID 3: SvrFarm
portToIP[3] = {
    1: "10.0.0.5",     # veth_farm1
    2: "10.20.0.2",    # ens35
    3: "10.0.0.6"      # veth_farm3
}

routeTable = {
  1: [  # InternetOut (DPID 1)
    ['10.10.0.0/16', '10.0.0.4', 1, '10.0.0.1', 1],  # to Intranet
    ['10.20.0.0/16', '10.0.0.6', 2, '10.0.0.2', 2],  # to SvrFarm
    ['0.0.0.0/0',     '192.168.230.2', 3,     '192.168.230.155', 3]  # Direct to Internet
  ],

  2: [  # Intranet (DPID 2)
    ['10.10.10.0/24', '0.0.0.0', 4, '10.10.10.1', 4],
    ['10.10.0.0/16', '0.0.0.0',  1,      '10.10.0.2', 1],  # Direct
    ['10.20.0.0/16', '10.0.0.5', 2, '10.0.0.3', 2],  # via SvrFarm
    ['0.0.0.0/0',     '10.0.0.1', 3, '10.0.0.4', 3]  # via InternetOut
  ],

  3: [  # SvrFarm (DPID 3)
    ['10.20.0.0/16', '0.0.0.0',  2,      '10.20.0.2', 2],  # Direct
    ['10.10.0.0/16', '10.0.0.3', 1, '10.0.0.5', 1],   # via Intranet
    ['0.0.0.0/0',     '10.0.0.2', 3, '10.0.0.6', 3]   # via InternetOut
  ]
}

# NAT variables:
PUBLIC_IP=IPAddr("192.168.230.155")
PUBLIC_PORT=3 #ens33
PUBLIC_MAC=EthAddr("00:00:00:00:00:01")
PUBLIC_DPID=1
PUBLIC_GW_MAC=EthAddr('00:50:56:ed:8a:b4')
# ICMP['id'] = dst IP
ICMP = {}
# UDP['src']['dst'] = last src port
UDP = {}
# NAT key + buffer = port number
# NAT[public_port - BUFFER] = (IP,src port)
BUFFER = 50000
NAT = [None for i in range(65536)]

arpTable = {}
portTable = {}

rDST_NETWORK = 0
rNEXTHOP_IP = 1
rNEXTHOP_PORT_NAME = 2
rNEXTHOP_PORT_IP = 3
rNEXTHOP_PORT = 4

pPORT = 0
pPORT_MAC = 1
pPORT_IP = 2

class routerConnection(object):
  def __init__(self,connection):
    dpid = connection.dpid
    arpTable[dpid] = {}
    portTable[dpid] = []
    for entry in connection.ports.values():
      port = entry.port_no
      mac = entry.hw_addr
      if port <= of.ofp_port_rev_map['OFPP_MAX']:
        arpTable[dpid][port] = {}
        ip = IPAddr(portToIP[dpid][port])
        arpTable[dpid][port][ip] = mac
        portTable[dpid].append([port, mac, ip])
    connection.addListeners(self)

  def _handle_FlowRemoved(self,event):
    dpid = event.connection.dpid
    match = event.ofp.match  # the match structure
    dst_ip = match.nw_dst    # IPv4 destination
    dst_port = match.tp_dst  # TCP/UDP destination port
    try:
      if dst_ip == PUBLIC_IP:
        NAT[dst_port] = None
    except:
      return

  def _handle_PacketIn(self,event):
    dpid = event.connection.dpid
    packet = event.parsed

    # ARP
    if packet.type == ethernet.ARP_TYPE:
      arppacket = packet.payload
      if arppacket.opcode == arp.REPLY:
        arpTable[event.connection.dpid][event.ofp.in_port][arppacket.protosrc] = arppacket.hwsrc
        arpTable[event.connection.dpid][event.ofp.in_port][arppacket.protodst] = arppacket.hwdst
      if arppacket.opcode == arp.REQUEST:
        arpTable[event.connection.dpid][event.ofp.in_port][arppacket.protosrc] = arppacket.hwsrc
        if arppacket.protodst in arpTable[event.connection.dpid][event.ofp.in_port]:
          a = arppacket
          r = arp()
          r.hwtype = a.hwtype
          r.prototype = a.prototype
          r.hwlen = a.hwlen
          r.protolen = a.protolen
          r.opcode = arp.REPLY
          r.hwdst = a.hwsrc
          r.protodst = a.protosrc
          r.protosrc = a.protodst
          r.hwsrc = arpTable[event.connection.dpid][event.ofp.in_port][arppacket.protodst]
          e = ethernet(type=packet.type, src=r.hwsrc,dst=a.hwsrc)
          e.set_payload(r)
          msg = of.ofp_packet_out()
          msg.data = e.pack()
          msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
          event.connection.send(msg)

    # IP
    if packet.type == ethernet.IP_TYPE:
      ippacket = packet.payload
      srcip = ippacket.srcip
      dstip = ippacket.dstip
      try:
        if srcip not in arpTable[dpid][event.ofp.in_port]:
          arpTable[dpid][event.ofp.in_port][srcip] = packet.src
      except:
        pass
      for t in portTable[dpid]:
        selfip = t[pPORT_IP]
        if dstip == selfip:
          if ippacket.protocol == ipv4.ICMP_PROTOCOL:
            icmppacket = ippacket.payload
            if icmppacket.type == TYPE_ECHO_REQUEST:
              selfmac = t[pPORT_MAC]
              r = icmppacket
              r.type = TYPE_ECHO_REPLY
              s = ipv4()
              s.protocol = ipv4.ICMP_PROTOCOL
              s.srcip = selfip
              s.dstip = ippacket.srcip
              s.payload = r
              e = ethernet()
              e.type = ethernet.IP_TYPE
              e.src = selfmac
              e.dst = packet.src
              e.payload = s
              msg = of.ofp_packet_out()
              msg.data = e.pack()
              msg.actions.append(of.ofp_action_output(port=event.port))
              event.connection.send(msg)
              return

      # NAT implementation:
      outbound = srcip.inNetwork("10.0.0.0/8") and not dstip.inNetwork("10.0.0.0/8")
      inbound = not srcip.inNetwork("10.0.0.0/8") and dstip == PUBLIC_IP
      if dpid == PUBLIC_DPID:
        pkt = event.parsed
        if outbound:
          if ippacket.protocol == ipv4.ICMP_PROTOCOL:
            # No revese NAT because flow cannot match ICMP ID
            id = pkt.find('icmp').payload.id
            ICMP[id] = srcip
            # log.info(f"Outbound ICMP NAT {srcip} -> {dstip}")
            msg = of.ofp_flow_mod()
            msg.match.in_port = event.ofp.in_port
            msg.match.dl_type = 0x0800  # IPv4
            msg.match.nw_src = srcip
            msg.match.nw_dst = dstip
            msg.match.nw_proto = 1 #ICMP
            msg.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
            msg.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            msg.actions.append(of.ofp_action_dl_addr.set_dst(PUBLIC_GW_MAC))
            msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            msg.idle_timeout = 10
            event.connection.send(msg)
            return
          else:
            udp_pkt = packet.find('udp')
            tcp_pkt = packet.find('tcp')
            if udp_pkt:
              src_port = udp_pkt.srcport
              dst_port = udp_pkt.dstport
            elif tcp_pkt:
              src_port = tcp_pkt.srcport
              dst_port = tcp_pkt.dstport
            else:
              return
            try:
              NATport = NAT.index((srcip,src_port))
            except:
              NATport = NAT.index(None, BUFFER)
              NAT[NATport] = (srcip,src_port)
            if udp_pkt:
              UDP[(srcip,dstip)] = src_port
              msg = of.ofp_flow_mod()
              msg.match.dl_type = 0x0800
              msg.match.nw_proto = 17
              msg.match.nw_src = srcip
              msg.match.nw_dst = dstip
              msg.match.tp_src = src_port
              msg.match.tp_dst = dst_port
              msg.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
              msg.actions.append(of.ofp_action_tp_port.set_src(NATport))
              msg.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
              msg.actions.append(of.ofp_action_dl_addr.set_dst(PUBLIC_GW_MAC))
              msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
              msg.idle_timeout = 10
              event.connection.send(msg)
            elif tcp_pkt:
              msg = of.ofp_flow_mod()
              msg1 = of.ofp_flow_mod()
              msg.match.dl_type = 0x0800 #ipv4
              msg1.match.dl_type = 0x0800
              msg.match.nw_src = srcip
              msg.match.nw_dst = dstip
              # Inbound flow
              msg1.match.nw_src = dstip
              msg1.match.nw_dst = PUBLIC_IP
              msg.match.nw_proto = 6 #TCP
              msg1.match.nw_proto = 6
              # Outbound flow
              msg.match.tp_src = src_port
              msg.match.tp_dst = dst_port
              # Inbound flow
              msg1.match.tp_src = dst_port
              msg1.match.tp_dst = NATport
              # Outbound flow
              msg.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
              msg.actions.append(of.ofp_action_tp_port.set_src(NATport))
              # Inbound flow
              msg1.actions.append(of.ofp_action_nw_addr.set_dst(srcip))
              msg1.actions.append(of.ofp_action_tp_port.set_dst(src_port))
              msg.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
              msg.actions.append(of.ofp_action_dl_addr.set_dst(PUBLIC_GW_MAC))
              msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
              msg1.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
              msg1.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
              msg1.actions.append(of.ofp_action_output(port=event.ofp.in_port))
              msg1.flags = of.OFPFF_SEND_FLOW_REM
              msg.idle_timeout = 10
              msg1.idle_timeout = 10
              event.connection.send(msg)
              event.connection.send(msg1)
              return
        if inbound:
          if ippacket.protocol == ipv4.ICMP_PROTOCOL:
            id = pkt.find('icmp').payload.id
            realdst = ICMP[id]
            for t in routeTable[PUBLIC_DPID]:
              dstnetwork = t[rDST_NETWORK]
              if realdst.inNetwork(dstnetwork):
                nh_port = t[rNEXTHOP_PORT]
                if nh_port == event.ofp.in_port:
                  return
                # Gateway so we forgo direct connect check
                nh_ip = IPAddr(t[rNEXTHOP_IP])
                nh_port_ip = IPAddr(t[rNEXTHOP_PORT_IP])
                nh_mac_src = arpTable[dpid][nh_port][nh_port_ip]
                nh_mac_dst = arpTable[dpid][nh_port][nh_ip]
                break
            r = icmppacket
            r.type = TYPE_ECHO_REPLY
            r.payload = pkt.find('icmp').payload
            s = ipv4()
            s.protocol = ipv4.ICMP_PROTOCOL
            s.srcip = srcip
            s.dstip = realdst
            s.payload = r
            e = ethernet()
            e.type = ethernet.IP_TYPE
            e.src = nh_mac_src
            e.dst = nh_mac_dst
            e.payload = s
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port=nh_port))
            event.connection.send(msg)
            return
          else:
            udp_pkt = packet.find('udp')
            tcp_pkt = packet.find('tcp')
            if udp_pkt:
              src_port = udp_pkt.srcport
              dst_port = udp_pkt.dstport
            elif tcp_pkt:
              src_port = tcp_pkt.srcport
              dst_port = tcp_pkt.dstport
            else:
              return
            revNAT = NAT[dst_port]
            if revNAT is None:
              return
            realdst = revNAT[0]
            realport = revNAT[1]
            for t in routeTable[PUBLIC_DPID]:
              dstnetwork = t[rDST_NETWORK]
              if realdst.inNetwork(dstnetwork):
                nh_port = t[rNEXTHOP_PORT]
                if nh_port == event.ofp.in_port:
                  return
                # Gateway so we forgo direct connect check
                nh_ip = IPAddr(t[rNEXTHOP_IP])
                nh_port_ip = IPAddr(t[rNEXTHOP_PORT_IP])
                nh_mac_src = arpTable[dpid][nh_port][nh_port_ip]
                nh_mac_dst = arpTable[dpid][nh_port][nh_ip]
                break
            if udp_pkt:
              msg_ip = ipv4()
              msg_ip.srcip = srcip
              msg_ip.dstip = realdst
              msg_ip.protocol = ipv4.UDP_PROTOCOL
              msg_udp = udp()
              msg_udp.srcport = src_port
              msg_udp.dstport = UDP[(realdst, srcip)]
              msg_udp.payload = udp_pkt.payload
              msg_ip.payload = msg_udp
              eth = ethernet()
              eth.src = nh_mac_src
              eth.dst = nh_mac_dst
              eth.type = ethernet.IP_TYPE
              eth.payload = msg_ip
              msg = of.ofp_packet_out()
              msg.data = eth.pack()
              msg.actions.append(of.ofp_action_output(port=nh_port))
              event.connection.send(msg)
              return
            elif tcp_pkt:
              msg = of.ofp_flow_mod()
              msg.match = of.ofp_match()
              msg.match.dl_type = 0x0800 #ipv4
              msg.match.nw_proto = 6 #TCP
              msg.match.nw_src = srcip
              msg.match.nw_dst = PUBLIC_IP
              msg.match.tp_src = src_port
              msg.match.tp_dst = dst_port
              msg.buffer_id = event.ofp.buffer_id
              msg.actions.append(of.ofp_action_nw_addr.set_dst(realdst))
              msg.actions.append(of.ofp_action_tp_port.set_dst(realport))
              msg.actions.append(of.ofp_action_dl_addr.set_src(nh_mac_src))
              msg.actions.append(of.ofp_action_dl_addr.set_dst(nh_mac_dst))
              msg.actions.append(of.ofp_action_output(port=nh_port))
              msg.idle_timeout = 15
              event.connection.send(msg)
              return
      for t in routeTable[dpid]:
        dstnetwork = t[rDST_NETWORK]
        if dstip.inNetwork(dstnetwork):
          nh_port = t[rNEXTHOP_PORT]
          if nh_port == event.ofp.in_port:
            return
          nh_ip = IPAddr(t[rNEXTHOP_IP])
          if nh_ip == IPAddr('0.0.0.0'):
            nh_ip = dstip
          nh_port_ip = IPAddr(t[rNEXTHOP_PORT_IP])
          nh_mac_src = arpTable[dpid][nh_port][nh_port_ip]
          if nh_ip in arpTable[dpid][nh_port]:
            nh_mac_dst = arpTable[dpid][nh_port][nh_ip]
            ip_pkt = packet.find('ipv4')
            tcp_pkt = packet.find('tcp')
            udp_pkt = packet.find('udp')
            icmp_pkt = packet.find('icmp')
            msg1 = of.ofp_flow_mod()
            msg2 = of.ofp_flow_mod()
            if udp_pkt:
              fm_fwd = of.ofp_flow_mod()
              fm_fwd.idle_timeout = 15
              fm_fwd.match.dl_type = 0x0800
              fm_fwd.match.nw_proto = 17
              fm_fwd.match.nw_src = ip_pkt.srcip
              fm_fwd.match.nw_dst = ip_pkt.dstip
              fm_fwd.actions.append(of.ofp_action_dl_addr.set_src(nh_mac_src))
              fm_fwd.actions.append(of.ofp_action_dl_addr.set_dst(nh_mac_dst))
              fm_fwd.actions.append(of.ofp_action_output(port=nh_port))
              event.connection.send(fm_fwd)
              # --- Reverse flow (reply direction) ---
              fm_rev = of.ofp_flow_mod()
              fm_rev.idle_timeout = 15
              fm_rev.match.dl_type = 0x0800
              fm_rev.match.nw_proto = 17
              fm_rev.match.nw_src = ip_pkt.dstip
              fm_rev.match.nw_dst = ip_pkt.srcip
              fm_rev.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
              fm_rev.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
              fm_rev.actions.append(of.ofp_action_output(port=event.ofp.in_port))
              event.connection.send(fm_rev)
            elif tcp_pkt:
              msg1.match = of.ofp_match()
              msg2.match = of.ofp_match()
              msg1.match.dl_type = ethernet.IP_TYPE
              msg2.match.dl_type = ethernet.IP_TYPE
              msg1.match.nw_proto = ip_pkt.protocol
              msg2.match.nw_proto = ip_pkt.protocol
              msg1.match.nw_src = srcip
              msg2.match.nw_src = dstip
              msg1.match.nw_dst = dstip
              msg2.match.nw_dst = srcip
              msg1.match.tp_src = tcp_pkt.srcport
              msg2.match.tp_src = tcp_pkt.dstport
              msg1.match.tp_dst = tcp_pkt.dstport
              msg2.match.tp_dst = tcp_pkt.srcport
              # Flow actions
              msg1.idle_timeout = 10
              msg2.idle_timeout = 10
              msg1.actions.append(of.ofp_action_dl_addr.set_src(nh_mac_src))
              msg1.actions.append(of.ofp_action_dl_addr.set_dst(nh_mac_dst))
              msg1.actions.append(of.ofp_action_output(port=nh_port))
              msg2.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
              msg2.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
              msg2.actions.append(of.ofp_action_output(port=event.ofp.in_port))
              event.connection.send(msg1)
              event.connection.send(msg2)
            elif icmp_pkt:
              msg1.match = of.ofp_match()
              msg2.match = of.ofp_match()
              msg1.match.dl_type = ethernet.IP_TYPE
              msg2.match.dl_type = ethernet.IP_TYPE
              msg1.match.nw_proto = 1 # ICMP
              msg2.match.nw_proto = 1 # ICMP
              msg1.match.nw_src = srcip
              msg2.match.nw_src = dstip
              msg1.match.nw_dst = dstip
              msg2.match.nw_dst = srcip
              # Flow actions
              msg1.idle_timeout = 10
              msg2.idle_timeout = 10
              msg1.actions.append(of.ofp_action_dl_addr.set_src(nh_mac_src))
              msg1.actions.append(of.ofp_action_dl_addr.set_dst(nh_mac_dst))
              msg1.actions.append(of.ofp_action_output(port=nh_port))
              msg2.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
              msg2.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
              msg2.actions.append(of.ofp_action_output(port=event.ofp.in_port))
              event.connection.send(msg1)
              event.connection.send(msg2)
          else:
            r = arp()
            r.opcode = arp.REQUEST
            r.protosrc = nh_port_ip
            r.hwsrc = nh_mac_src
            r.protodst = nh_ip
            e_arp = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc, dst=ETHER_BROADCAST)
            e_arp.set_payload(r)
            msg = of.ofp_packet_out()
            msg.data = e_arp.pack()
            msg.actions.append(of.ofp_action_output(port=nh_port))
            msg.in_port = event.ofp.in_port
            event.connection.send(msg)
            nh_mac_dst = ETHER_BROADCAST
            msg1 = of.ofp_packet_out()
            msg1.in_port = event.port
            msg1.buffer_id = event.ofp.buffer_id
            msg1.actions.append(of.ofp_action_dl_addr.set_src(nh_mac_src))
            msg1.actions.append(of.ofp_action_dl_addr.set_dst(nh_mac_dst))
            msg1.actions.append(of.ofp_action_output(port=nh_port))
            event.connection.send(msg1)
          return
      r = icmp()
      r.type = TYPE_DEST_UNREACH
      r.code = CODE_UNREACH_NET
      d = ippacket.pack()[:ippacket.iplen + 8]
      import struct
      d = struct.pack("!I", 0) + d
      r.payload = d
      s = ipv4()
      s.protocol = ipv4.ICMP_PROTOCOL
      for t in portTable[dpid]:
        selfip = t[pPORT_IP]
        if(event.port == t[pPORT]):
          s.srcip = selfip
          break
      s.dstip = ippacket.srcip
      s.payload = r
      e = ethernet()
      e.type = ethernet.IP_TYPE
      e.src = packet.dst
      e.dst = packet.src
      e.payload = s
      msg = of.ofp_packet_out()
      msg.data = e.pack()
      msg.actions.append(of.ofp_action_output(port=event.port))
      event.connection.send(msg)

class MyHubComponent(object):
  def __init__(self):
    core.openflow.addListeners(self)

  def _handle_ConnectionUp(self,event):
    dpid = event.connection.dpid
    routerConnection(event.connection)

def launch():
  core.registerNew(MyHubComponent)

