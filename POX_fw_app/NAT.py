from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

def _handle_ConnectionUp(event):
    log.info('NAT component up')
    pass

def _handle_PacketIn(event):
    pass

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn, priority=5)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
