# -*- coding: utf-8 -*-
#
# POX DNS Proxy - caching version
#
# Hardcoded:
#   - Listens on UDP/53 at 192.168.230.155
#   - Forwards to Google DNS 8.8.8.8:53
#   - Caches replies for 30 seconds
#

import socket
import threading
import select
import time
from pox.core import core

log = core.getLogger()

BIND_ADDR = ("0.0.0.0", 53)  # <-- your chosen IP
UPSTREAM_ADDR = ("8.8.8.8", 53)
BUF_SIZE = 4096
TIMEOUT = 3.0
CACHE_TTL = 30.0  # seconds

class DNSProxy(object):
  def __init__(self):
    self.sock = None
    self._stop = False
    self.thread = threading.Thread(target=self.loop)
    self.thread.daemon = True
    self.cache = {}  # key -> (response, expiry)

  def start(self):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.sock.bind(BIND_ADDR)
    log.info("DNS proxy listening on %s:%d -> %s:%d (cache ttl=%ds)",
             BIND_ADDR[0], BIND_ADDR[1],
             UPSTREAM_ADDR[0], UPSTREAM_ADDR[1],
             CACHE_TTL)
    self.thread.start()

  def stop(self):
    self._stop = True
    try: self.sock.close()
    except: pass
    log.info("DNS proxy stopped")

  def _cache_key(self, data):
    return data[2:] if len(data) > 2 else data

  def handle_request(self, data, client_addr):
    key = self._cache_key(data)
    now = time.time()

    if key in self.cache:
      resp, expiry = self.cache[key]
      if now < expiry:
        cached = data[:2] + resp[2:]
        self.sock.sendto(cached, client_addr)
        log.debug("Cache hit for %s", client_addr)
        return
      else:
        del self.cache[key]

    try:
      up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      up.settimeout(TIMEOUT)
      up.sendto(data, UPSTREAM_ADDR)
      resp, _ = up.recvfrom(BUF_SIZE)
      self.sock.sendto(resp, client_addr)
      up.close()

      self.cache[key] = (resp, now + CACHE_TTL)
      log.debug("Cached response for %s", client_addr)
    except Exception as e:
      log.debug("Upstream error: %s", e)

  def loop(self):
    while not self._stop:
      try:
        r, _, _ = select.select([self.sock], [], [], 1.0)
        if not r: continue
        data, addr = self.sock.recvfrom(BUF_SIZE)
        threading.Thread(target=self.handle_request,
                         args=(data, addr)).start()
      except: pass

proxy = None

def launch():
  global proxy
  proxy = DNSProxy()
  proxy.start()
  core.addListenerByName("GoingDownEvent", lambda e: proxy.stop())
