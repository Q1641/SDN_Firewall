from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventHalt
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

log = core.getLogger()

# USER_IP[IP] = USER
USER_IP = {}
# USER_GROUP[USER] = GROUPS (list of group names)
USER_GROUP = {}

class Policy:
	def __init__(self):
		pass

class Firewall:
	def __init__(self):
		core.openflow.addListenerByName("PacketIn", self._handle_PacketIn, priority=10)
	
	def _handle_PacketIn(self, event):
		allowed = True
		packet = event.parsed
		if not packet.parsed:
			log.info('Incomplete Packet!')
			return EventHalt
		if not allowed:
			log.info('Not Allowed!')
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match.from_packet(event.parsed)
			msg.data = event.ofp
			msg.idle_timeout = 15
			msg.hard_timeout = 60
			event.connection.send(msg)
			return EventHalt
		return

class SimpleHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		self.send_response(200)
		self.send_header("Content-type", "text/plain")
		self.end_headers()
		self.wfile.write(b"Hello from POX HTTP server!\n")

	def do_POST(self):
		client_ip = self.client_address[0]
		if client_ip != "10.10.0.10":
			log.warn("Rejected POST from unauthorized IP: %s", client_ip)
			self.send_response(403)  # Forbidden
			self.end_headers()
			return
		try:
			# Read and parse the body
			length = int(self.headers.get('Content-Length', 0))
			raw_data = self.rfile.read(length).decode("utf-8")
			data = json.loads(raw_data)
			user = data.get("user")
			ip = data.get("ip")
			groups = data.get("group")
			log.info("Accepted POST from %s: user=%s, ip=%s, groups=%s", client_ip, user, ip, groups)
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
