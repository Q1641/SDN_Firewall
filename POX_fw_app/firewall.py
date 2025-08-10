from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventHalt

log = core.getLogger()

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

def launch():
	core.registerNew(Firewall)
