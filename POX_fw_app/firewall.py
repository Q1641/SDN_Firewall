from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventHalt
from pox.lib.addresses import IPAddr, EthAddr
import json
import psycopg2
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash
import os
import re
import logging
import dns.resolver

logging.getLogger('werkzeug').disabled = True   # disable werkzeug logs
logging.getLogger('flask').disabled = True      # disable flask logs
logging.getLogger('flask.cli').disabled = True  # disable startup banner

log = core.getLogger()

# Database connection config
DB_CONFIG = {
    "dbname": "SDNfw",
    "user": "srv_acc",
    "password": "root123",
    "host": "10.99.0.1",
    "port": 5432
}

def get_db_connection():
	return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

# USER_IP[IP] = [USER,expire]
# Add expire field for captive portal authentication
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
	def __init__(self, id, name="", srcip=[], srcuser=[], dstip=[], tcp=[], udp=[], icmp=False, action=True):
		self.name = name
		self.src = [srcip, srcuser]
		self.dst = dstip
		self.port = [tcp, udp, icmp]
		self.action = action
		self.id=id

	# return true if:
	# - list is empty => any ip
	# - ip is in the list
	def _match_ip(self, ip, list):
		if not list:
			return True
		for _ip in list:
			if ip.inNetwork(_ip):
				return True
		return False
	
	# return true if:
	# - srcuser is empty => any user
	# - user belongs AD group that is in the rule
	# - user is explicitly in the rule
	def _match_usr(self, ip):
		if not self.src[1]:
			return True
		if not USER_IP.get(IPAddr(ip)):
			return False
		usr = USER_IP[IPAddr(ip)][0]
		grps = USER_GROUP[usr]
		if usr in self.src[1]:
			return True
		for _usr in self.src[1]:
			if _usr in grps:
				return True
		return False

	# check matching protocol & port
	def _match_service(self, proto, port):
		if proto == 1: #ICMP
			return self.port[2]
		if proto == 6: #TCP
			return port in self.port[0]
		if proto == 17: #UDP
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

def domains_to_ips(domains, dstip):
	resolver = dns.resolver.Resolver()
	resolver.nameservers = ["8.8.8.8"]
	ips = set(dstip)
	for domain in domains:
		try:
			answers = resolver.resolve(domain, 'A')
			for rdata in answers:
				ips.add(rdata.address)
		except Exception as e:
			print(f"[!] Could not resolve {domain}: {e}")
	return list(ips)

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
		SELECT id, name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, schedule, domains FROM policy
		WHERE disabled = FALSE AND (schedule IS NULL OR schedule >= CURRENT_DATE) ORDER BY order_index;
	""")
	policies = []
	for row in cur.fetchall():
		id, name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, schedule, domains = row
		srcip = srcip or []
		srcuser = srcuser or []
		domains = domains or []
		dstip = dstip or []
		dstip = domains_to_ips(domains, dstip)
		tcp_ports = tcp_ports or []
		udp_ports = udp_ports or []
		policy = Policy(
			id,
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
	log.info('Policies loaded')
	return policies

def log_firewall_event(srcip, srcuser, dstip, rulename, action, dpid, ruleid=None, tcpport=None, udpport=None, icmp=False):
	query = """
		INSERT INTO logs (srcip, srcuser, dstip, rulename, action, ruleid, dpid, tcpport, udpport, icmp)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
	"""

	values = (srcip, srcuser, dstip, rulename, action, ruleid, dpid, tcpport, udpport, icmp)
	try:
		conn = get_db_connection()
		with conn.cursor() as cur:
			cur.execute(query, values)
		conn.commit()
	except Exception as e:
		print(f"[!] Failed to insert log entry: {e}")
	finally:
		if conn:
			conn.close()

class Firewall:
	def __init__(self):
		core.openflow.addListenerByName("PacketIn", self._handle_PacketIn, priority=10)
		self.policies = load_policies()

	def _handle_PacketIn(self, event):
		allowed = False
		packet = event.parsed
		if not packet.parsed:
			log.info('Incomplete Packet!')
			return EventHalt
		ipv4h = packet.find('ipv4')
		tcp_pkt = packet.find('tcp')
		udp_pkt = packet.find('udp')
		icmp_pkt = packet.find('icmp')
		if not ipv4h:
			return
		matching_rule = "None"
		matching_id = None
		for policy in self.policies:
			matching_rule = policy.name
			res = policy.match(packet)
			if res[0]:
				matching_id = policy.id
				allowed = res[1]
				break
		### Logging connection
		src_ip = str(ipv4h.srcip)
		dst_ip = str(ipv4h.dstip)
		tcpport = udpport = None
		icmp = False

		if tcp_pkt:
			tcpport = tcp_pkt.dstport
		elif udp_pkt:
			udpport = udp_pkt.dstport
		elif icmp_pkt:
			icmp = True

		src_user = None
		if IPAddr(src_ip) in USER_IP:
			src_user = USER_IP[IPAddr(src_ip)][0]

		log_firewall_event(
			srcip=src_ip,
			srcuser=src_user,
			dstip=dst_ip,
			rulename=matching_rule,
			action=allowed,
			ruleid=matching_id,
			dpid=event.dpid,
			tcpport=tcpport,
			udpport=udpport,
			icmp=icmp
		)

		if not allowed:
			msg = of.ofp_flow_mod()
			msg.match = of.ofp_match.from_packet(event.parsed)
			msg.data = event.ofp
			msg.idle_timeout = 30
			msg.hard_timeout = 150
			event.connection.send(msg)
			return EventHalt
		log.info(f"Permit Traffic from: {ipv4h.srcip} -> {ipv4h.dstip}; matching rule: {matching_rule}")
		return
### FLASK UPDATE IP API ###
user_ip_api = Flask('user_ip_api')
@user_ip_api.route("/", methods=["POST"])
def update_ip():
		data = request.get_json(force=True)
		user = data.get("user")
		ip = data.get("ip")
		groups = data.get("group")

		log.info("Accepted POST: user=%s, ip=%s, groups=%s", user, ip, groups)

		if USER_IP.get(IPAddr(ip)) is not None:
			# User-IP mapping unchanged
			if USER_IP[IPAddr(ip)][0] == user:
				return jsonify({"status": "ok"}), 200
			# Remove old flows for this IP
			for connection in core.openflow._connections.values():
				fm = of.ofp_flow_mod()
				fm.command = of.OFPFC_DELETE
				fm.match.dl_type = 0x0800  # IPv4 Ethertype
				fm.match.nw_src = IPAddr(ip)
				connection.send(fm)

		USER_IP[IPAddr(ip)] = [user, None]
		USER_GROUP[user] = groups
		return jsonify({"status": "ok"}), 200

### FLASK WEBAPP ###
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ctrl_app = Flask(
	'ctrl_app',
	template_folder=os.path.join(BASE_DIR, 'templates'),
	static_folder=os.path.join(BASE_DIR, 'static')
)
ctrl_app.secret_key = os.urandom(24)

@ctrl_app.route("/")
def index():
	if "username" not in session:
		return redirect(url_for("login_page"))
	username = session["username"]
	try:
		conn = get_db_connection()
		cur = conn.cursor()
		cur.execute("""SELECT user_mgmt, policy_mgmt, user_view, policy_view FROM users WHERE username = %s""", (username,))
		user = cur.fetchone()
		cur.close()
		conn.close()

		if not user:
			return jsonify({"error": "User not found"}), 404

		if user["user_mgmt"] or user["policy_mgmt"] or user["user_view"] or user["policy_view"]:
			return redirect(url_for("dashboard"))
	except Exception as e:
		return jsonify({"error"}), 500

@ctrl_app.route("/login", methods=["GET"])
def login_page():
	return render_template("login.html")

@ctrl_app.route("/dashboard", methods=["GET"])
def dashboard():
	if "username" not in session:
		return redirect(url_for("login_page"))
	return render_template("dashboard.html", username=session["username"])

@ctrl_app.route("/login", methods=["POST"])
def login():
	data = request.get_json(force=True)
	username = data.get("username")
	password = data.get("password")
	if not username or not password:
		return jsonify({"error": "Missing username or password"}), 400

	try:
		conn = get_db_connection()
		cur = conn.cursor()
		cur.execute("SELECT username, password_hash FROM users WHERE username = %s", (username,))
		user = cur.fetchone()
		cur.close()
		conn.close()

		if not user:
			return jsonify({"error": "Invalid credentials"}), 401

		# Check password using hashed password
		if check_password_hash(user["password_hash"], password):
			session["username"] = user["username"]
			return jsonify({"message": "Login successful"})
		else:
			return jsonify({"error": "Invalid credentials"}), 401
	except Exception as e:
		return jsonify({"error": str(e)}), 500


@ctrl_app.route("/whoami", methods=["GET"])
def getID():
	username = session.get("username")
	if username:
		return jsonify({"username": username})
	else:
		return jsonify({"error": "Not logged in"}), 401

@ctrl_app.route("/list_policies", methods=["GET"])
def list_policy():
	"""
	Return all firewall policies as JSON list.
	"""
	username = session.get("username")
	if not username:
		return jsonify({"error": "Not logged in"}), 401
	try:
		conn = get_db_connection()
		cur = conn.cursor()
		cur.execute("SELECT policy_view FROM users WHERE username = %s", (username,))
		user = cur.fetchone()
		if not user or not user["policy_view"]:
			cur.close()
			conn.close()
			return jsonify({"error": "Forbidden"}), 403
		cur.execute("SELECT * FROM policy ORDER BY order_index ASC;")
		policies = cur.fetchall()
		cur.close()
		conn.close()
		return jsonify(policies), 200
	except Exception as e:
		return jsonify({"error": str(e)}), 500

@ctrl_app.route("/delete_policy", methods=["DELETE"])
def del_policy():
	username = session.get("username")
	if not username:
		return jsonify({"error": "Not logged in"}), 401

	data = request.get_json(force=True)
	policy_id = data.get("id")
	if not policy_id:
		return jsonify({"error": "Missing policy ID"}), 400

	try:
		conn = get_db_connection()
		cur = conn.cursor()
		cur.execute("SELECT policy_mgmt FROM users WHERE username = %s", (username,))
		user = cur.fetchone()
		if not user or not user["policy_mgmt"]:
			cur.close()
			conn.close()
			return jsonify({"error": "Forbidden"}), 403
		cur.execute("DELETE FROM policy WHERE id = %s RETURNING id", (policy_id,))
		deleted = cur.fetchone()
		conn.commit()
		cur.close()
		conn.close()
		if deleted:
			return jsonify({"message": f"Policy {policy_id} deleted"})
		else:
			return jsonify({"error": "Policy not found"}), 404
	except Exception as e:
		return jsonify({"error": str(e)}), 500

@ctrl_app.route("/create_policy", methods=["POST"])
def create_policy():
	username = session.get("username")
	if not username:
		return jsonify({"error": "Not logged in"}), 401

	data = request.get_json(force=True)

	# Required fields
	name = data.get("name")
	if not name:
		return jsonify({"error": "Missing policy name"}), 400

	# Optional fields with defaults
	srcip = data.get("srcip", [])
	srcuser = data.get("srcuser", [])
	dstip = data.get("dstip", [])
	tcp_ports = data.get("tcp_ports", [])
	udp_ports = data.get("udp_ports", [])
	icmp = data.get("icmp", False)
	action = data.get("action", True)
	disabled = data.get("disabled", False)
	schedule = data.get("schedule")  # should be 'YYYY-MM-DD'
	order_index = data.get("order_index")

	try:
		conn = get_db_connection()
		cur = conn.cursor()
		cur.execute("SELECT policy_mgmt FROM users WHERE username = %s", (username,))
		user = cur.fetchone()
		if not user or not user["policy_mgmt"]:
			cur.close()
			conn.close()
			return jsonify({"error": "Forbidden: no policy management privilege"}), 403
		if order_index is None:
			cur.execute("""
				INSERT INTO policy
				(name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, disabled, schedule)
				VALUES (%s, %s::inet[], %s, %s::inet[], %s, %s, %s, %s, %s, %s)
				RETURNING id, order_index
			""", (name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, disabled, schedule))
		else:
			cur.execute("""
				INSERT INTO policy 
				(name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, disabled, schedule, order_index)
				VALUES (%s, %s::inet[], %s, %s::inet[], %s, %s, %s, %s, %s, %s, %s)
				RETURNING id, order_index
			""", (name, srcip, srcuser, dstip, tcp_ports, udp_ports, icmp, action, disabled, schedule, order_index))
			new_policy = cur.fetchone()
		conn.commit()
		cur.close()
		conn.close()

		return jsonify({
			"message": "Policy created successfully",
			"id": new_policy["id"],
		})

	except Exception as e:
		return jsonify({"error": str(e)}), 500

@ctrl_app.route("/edit_policy", methods=["POST"])
def edit_policy():
	pass

@ctrl_app.route("/list_logs", methods=["GET"])
def list_logs():
	if "username" not in session:
		return jsonify({"error": "Unauthorized"}), 401
	username = session["username"]
	try:
		with get_db_connection() as conn:
			with conn.cursor() as cur:
				cur.execute("SELECT policy_view FROM users WHERE username = %s", (username,))
				row = cur.fetchone()
				if not row or not row["policy_view"]:
					return jsonify({"error": "Access denied"}), 403
				if request.data:
					query = request.data.decode("utf-8").strip()
				else:
					query = "SELECT * FROM logs ORDER BY timestamp DESC;"

				safe_pattern = re.compile(r"^\s*select\b", re.IGNORECASE)
				if not safe_pattern.match(query):
					return jsonify({"error": "Only SELECT queries are allowed."}), 400

				forbidden = ["update", "delete", "insert", "drop", "alter", "create", "execute", "grant"]
				for word in forbidden:
					if re.search(rf"\b{word}\b", query, re.IGNORECASE):
						return jsonify({"error": f"Forbidden SQL keyword detected: {word}"}), 400
				cur.execute(query)
				results = cur.fetchall()
				return jsonify(results), 200
	except Exception as e:
		print(f"[!] Error in /list_logs: {e}")
		return jsonify({"error": "Internal server error"}), 500

def launch():
	core.registerNew(Firewall)
	# Flask server runner
	def run_flask(app, port):
		log.info("Starting Flask app on port %s", port)
		app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
	t1 = threading.Thread(target=run_flask, args=(ctrl_app, 8000))
	t2 = threading.Thread(target=run_flask, args=(user_ip_api, 21012))

	t1.daemon = True
	t2.daemon = True

	t1.start()
	t2.start()

	log.info("Launched 2 Flask apps: ctrl_app@8080, user_ip_api@21012")
