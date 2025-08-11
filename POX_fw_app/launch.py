from pox.core import core

log = core.getLogger()

def launch():
	from pox.samples.pretty_log import launch
	launch()
	from firewall import launch
	launch()
	# from NAT import launch
	# launch()
	from multiRouter import launch
	launch()
