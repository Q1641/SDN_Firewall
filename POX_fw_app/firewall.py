from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventHalt
from pox.lib.addresses import IPAddr, EthAddr
import json
import psycopg2
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

log = core.getLogger()

# USER_IP[IP] = USER
USER_IP = {}
# USER_GROUP[USER] = GROUPS (list of group names)
USER_GROUP = {}

class Policy:
	# name: str -> Name of the policy
	# srcip: list of str -> source IP
	# srcuser: list of str -> source USER
	# dstip: list of str -> destination IP
	# tcp: list of int -> dst TCP port
	# udp: list of int -> dst UDP port
	# icmp: boolean
	# action: boolean
	def __init__(self, name="", srcip=[], srcuser=[], dstip=[], tcp=[], udp=[], icmp=False, action=True):
		self.name = name
		self.src = [srcip, srcuser]
		self.dst = dstip
		self.port = [tcp, udp, icmp]
		self.action = action

	# return true if:
	# - list is empty => any ip
	# - ip is in the list
	def _match_ip(self, ip, list):
		if not list:
			# print(f"{self.name}: {ip} matched any")
			return True
		for _ip in list:
			if ip.inNetwork(_ip):
				# print(f"{self.name}: {ip} matched {_ip}")
				return True
		return False
	
	# return true if:
	# - srcuser is empty => any user
	# - user belongs AD group that is in the rule
	# - user is explicitly in the rule
	def _match_usr(self, ip):
		if not self.src[1]:
			# print(f"{self.name}: policy allowed all users")
			return True
		if not USER_IP.get(IPAddr(ip)):
			# print(f"{self.name}: no user found!")
			return False
		usr = USER_IP[IPAddr(ip)]
		grps = USER_GROUP[usr]
		if usr in self.src[1]:
			# print(f"{self.name}: {usr} directly matched")
			return True
		for _usr in self.src[1]:
			if _usr in grps:
				# print(f"{self.name}: {usr} matched {_user}")
				return True
		return False

	# check matching protocol & port
	def _match_service(self, proto, port):
		if proto == 1: #ICMP
			# print(f"{self.name}: ICMP: {self.port[2]}")
			return self.port[2]
		if proto == 6: #TCP
			# print(f"{self.name}: port {port} TCP: {port in self.port[0]}")
			return port in self.port[0]
		if proto == 17: #UDP
			# print(f"{self.name}: port {port} UDP: {port in self.port[1]}")
			return port in self.port[1]
		return False

	# return [True, action] if match; [False, None] if do not match
	def match(self, packet):
		_srcip = packet.find('ipv4').srcip
		_dstip = packet.find('ipv4').dstip
		proto = packet.find('ipv4').protocol
		port = None
		if proto == 6: #TCP
			port = packet.find('tcp').dstport
		if proto == 17: #UDP
			port = packet.find('udp').dstport
		try:
			if not self._match_ip(_srcip, self.src[0]):
				return [False, None]
			if not self._match_usr(_srcip):
				return [False, None]
			if not self._match_ip(_dstip, self.dst):
				return [False, None]
			if not self._match_service(proto, port):
				return [False, None]
			return [True, self.action]
		except Exception as e:
			log.info(f"Unexpected error: {e}")
			return [False, None]
		return [False, None]

def load_policies():
	conn = psycopg2.connect(
		dbname="SDNfw",
		user="srv_acc",
		password="root123",
		host="10.99.0.1",
		port=5432
	)
	cur = conn.cursor()
	cur.execute("""
		SELECT name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, schedule FROM policy
		WHERE disabled = FALSE AND (schedule IS NULL OR schedule >= CURRENT_DATE);
	""")
	policies = []
	for row in cur.fetchall():
		name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, schedule = row
		srcip = srcip or []
		srcuser = srcuser or []
		dstip = dstip or []
		tcp_ports = tcp_ports or []
		udp_ports = udp_ports or []
		policy = Policy(
			name=name,
			srcip=srcip,
			srcuser=srcuser,
			dstip=dstip,
			tcp=tcp_ports,
			udp=udp_ports,
			icmp=icmp,
			action=action
		)
		policies.append(policy)

	cur.close()
	conn.close()
	return policies

class Firewall:
	def __init__(self):
		core.openflow.addListenerByName("PacketIn", self._handle_PacketIn, priority=10)
		self.policies = load_policies()
		# Policies
		# Value (by fields)
		# 0: Policy name
		# 1: Policy srcIP. If empty = any
		# 2: Policy srcUser/AD group. If empty = any
		# 3: Policy destIP. If empty = any.
		# Customizable fields:
		# udp/tcp: list of udp/tcp port. default is empty
		# icmp: boolean. True if icmp is permitted. default is False
		# action: boolean. False if deny policy. default is True
		# self.policies.append(Policy("All_to_DNS", [], [], ["10.10.10.10"], udp = [53], icmp=True))
		# self.policies.append(Policy("AD_to_Ctrl", ["10.10.0.10"], [], ["10.10.10.10"], tcp = [8000]))
		# self.policies.append(Policy("Usr_to_Cloudfare", [], ["johndoe"], ["1.1.1.1"], tcp = [80], icmp=True))
		# self.policies.append(Policy("Usr_to_DNSggl", [], ["Domain Users"], ["8.8.8.8", "8.8.4.4"], icmp=True))
		# self.policies.append(Policy("Inbound ICMP", [], [], ["192.168.230.155"], icmp=True))

	def _handle_PacketIn(self, event):
		allowed = False
		packet = event.parsed
		if not packet.parsed:
			log.info('Incomplete Packet!')
			return EventHalt
		ipv4h = packet.find('ipv4')
		if not ipv4h:
			return
		matching_rule = ""
		for policy in self.policies:
			matching_rule = policy.name
			res = policy.match(packet)
			if res[0]:
				allowed = res[1]
				break
		if not allowed:
			# log.info(f"Blocked Traffic from: {ipv4h.srcip} -> {ipv4h.dstip}")
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match.from_packet(event.parsed)
			msg.data = event.ofp
			msg.idle_timeout = 30
			msg.hard_timeout = 150
			event.connection.send(msg)
			return EventHalt
		log.info(f"Permit Traffic from: {ipv4h.srcip} -> {ipv4h.dstip}; matching rule: {matching_rule}")
		return

class SimpleHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		self.send_response(200)
		self.send_header("Content-type", "text/plain")
		self.end_headers()
		self.wfile.write(b"Hello from POX HTTP server!\n")

	def do_POST(self):
		try:
			# Read and parse the body
			length = int(self.headers.get('Content-Length', 0))
			raw_data = self.rfile.read(length).decode("utf-8")
			data = json.loads(raw_data)
			user = data.get("user")
			ip = data.get("ip")
			groups = data.get("group")
			log.info("Accepted POST: user=%s, ip=%s, groups=%s",user, ip, groups)
			if not USER_IP.get(IPAddr(ip)):
				for connection in core.openflow._connections.values():
					fm = of.ofp_flow_mod()
					fm.command = of.OFPFC_DELETE
					fm.match.dl_type = 0x0800  # IPv4 Ethertype
					fm.match.nw_src = IPAddr(ip)
					connection.send(fm)
			USER_IP[IPAddr(ip)] = user
			USER_GROUP[user] = groups
			self.send_response(200)
			self.end_headers()
		except Exception as e:
			log.error("Error handling POST from %s: %s", client_ip, e)
			self.send_response(400)
			self.end_headers()

	def log_message(self, format, *args):
		# Silence default HTTP logging
		return

def start_http_server():
	server = HTTPServer(("0.0.0.0", 8000), SimpleHandler)
	log.info("Starting HTTP server on port %s", 8000)
	server.serve_forever()

def launch():
	core.registerNew(Firewall)
	t = threading.Thread(target=start_http_server)
	t.daemon = True
	t.start()
	log.info("Webserver module launched (HTTP on port %s)", 8000)
