#!/usr/bin/python3

'''HAMprobe v1.0: HAMnet Measurement Probe
https://hamprobe.informatik.hs-augsburg.de
(c) 2017 Tobias Peter DB1QP <tobias.peter@hs-augsburg.de>
THIS SCRIPT SHOULD NOT BE CALLED MANUALLY, BUT BY hamprobe_master.py !!!'''

__version__ = '%PROBE_VERSION%'

import binascii
import errno
import hashlib
import hmac
import http.client
import json
import logging
import logging.config
import random
import sched
import signal
import socket
import struct
import sys
import time

import urllib.parse

if sys.version_info < (3, 3):
	time.monotonic = time.time  # time() possibly has lower resolution, and is susceptible to system clock changes.

# NETWORK STUFF

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

def rfc1071_checksum(data):
	'''Computes the internet checksum as defined in :rfc:`1071`'''
	short_sum = sum(struct.unpack_from("!H", data, i)[0] for i in range(0,len(data),2) if i != 5)
	short_sum = (short_sum & 0xffff) + (short_sum >> 16 & 0xffff)
	short_sum = (short_sum & 0xffff) + (short_sum >> 16 & 0xffff)
	return ~short_sum & 0xffff

def traceroute(target, distance, timeout=5):
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack('ll', timeout, 0))

	trace = []
	target = socket.gethostbyname(target)

	identifier = random.randint(0, 1 << 15)
	for i in range(distance):
		ping_packet = bytearray(struct.pack("!bbHHH", ICMP_ECHO_REQUEST, 0, 0, identifier, 1) + b'http://hamprobe.net ')
		struct.pack_into("!H", ping_packet, 2, rfc1071_checksum(ping_packet))

		hop = {"t": time.time(), "dst": target}

		sock.setsockopt(socket.SOL_IP, socket.IP_TTL, i+1)
		sock.sendto(ping_packet, (target, 33434))

		ping_reply = None
		try:
			ts_send = time.monotonic() # TODO SO_TIMESTAMPING (outbound and inbound)
			ping_reply, addr = sock.recvfrom(512)
			ts_recv = time.monotonic()
		except:
			pass

		icmp = None
		if ping_reply is not None:
			hop["hop"] = addr[0]
			hop["src"] = socket.inet_ntop(socket.AF_INET, ping_reply[16:20])
			hop["delay"] = ts_recv - ts_send
			icmp = struct.unpack_from("!bb", ping_reply, 20)
			if icmp != (ICMP_TIME_EXCEEDED, 0) and icmp != (ICMP_ECHO_REPLY, 0):
				hop["icmp"] = list(icmp)

		trace.append(hop)

		if icmp is not None and icmp[0] == ICMP_ECHO_REPLY:
			break

	return trace

# TESTS - the coordinator publishes a policy to each probe, telling it which tests to run, and how often.

def test_traceroute(probe, params):
	c_targets = params['targets']
	c_distance = int(params.get('distance', 2))
	c_timeout = int(params.get('timeout', 5))

	results = []
	for target in c_targets:
		results.append(traceroute(target, c_distance, c_timeout))
	return results


class APIError(Exception):
	pass

class API:
	def __init__(self, logger, version, config, api_name):
		self.logger = logger
		self.version = version
		self.probe_id = config["hamprobe"]["id"]
		self.probe_key = binascii.unhexlify(config["hamprobe"]["key"].encode('utf-8'))
		self.apis = config["apis"][api_name]

	def request(self, op, data=None):
		req = {"v": self.version, "op": op, "data": data or {}}
		body = json.dumps(req).encode('utf-8')
		mac = hmac.new(self.probe_key, body, digestmod=hashlib.sha256).hexdigest()
		for api in self.apis:
			url = urllib.parse.urlparse(api["url"])
			resp = None
			try:
				conn = http.client.HTTPConnection(url.hostname, url.port)
				conn.request('POST', url.path, body, headers={
					'X-Hamprobe-Id': self.probe_id,
					'X-Hamprobe-Hmac': mac,
					'Content-Type': 'application/json',
					'Content-Encoding': 'utf-8'})
				resp = conn.getresponse()
			except (OSError, http.client.BadStatusLine, socket.gaierror, socket.error):
				self.logger.debug("Failed to connect to api at {}, trying next option.".format(api['url']))
				continue

			if resp.status != 200:
				raise APIError("HTTP error: {} {}".format(resp.status, resp.code))
			rbody = resp.read()
			rbody_mac = hmac.new(self.probe_key, rbody, digestmod=hashlib.sha256).hexdigest()
			if resp.getheader('X-Hamprobe-Hmac') != rbody_mac:
				raise APIError("HMAC mismatch")
			rdata = json.loads(rbody.decode('utf-8'))
			if rdata.get('ret', None) != 'ok':
				raise APIError("API returned an error: {}".format(rdata))
			return rdata.get('resp', None)
		else:
			raise APIError("Failed to connect to API")


class Test:
	def __init__(self, probe, policy, index, config):
		self.test = config["test"]
		test_func_name = "test_" + self.test
		if test_func_name not in globals():
			raise RuntimeError("Test not found")
		self.name = "{}.{}.{}".format(policy, index, self.test)
		self.probe = probe
		self.policy = policy
		self.index = index
		self.func = globals()[test_func_name]
		self.delay = int(config.get("delay", 0))
		self.repeat = int(config.get("repeat", 60*60))
		self.params = config.get("params", {})
		self.logger = logging.getLogger('hamprobe.test.'+self.name)
		self.sched_handle = None

	def cancel(self):
		if self.sched_handle is not None:
			self.probe.sched.cancel(self.sched_handle)
			self.sched_handle = None

	def run(self):
		self.logger.debug("starting")
		try:
			self.sched_handle = None
			result = self.func(self.logger, self.params)
			self.logger.debug("succeeded, rescheduling")
			self.sched_handle = self.probe.sched.enter(self.repeat, 0, self.run, ())
			self.probe.publish(self, result)
		except Exception as ex:
			self.logger.debug("failed, not rescheduling")
			self.probe.report_error(self, ex)


class HAMprobe:
	def __init__(self, config, under_updater=True):
		self.logger = logging.getLogger('hamprobe')
		self.under_updater = under_updater
		self.api = API(self.logger.getChild('api'), __version__, config, 'probe')
		self.sched = sched.scheduler(time.time, time.sleep)
		self.tests = set()
		self.policy = None
		self.interval_status_report = int(config.get("interval_status_report", 300))
		self.interval_backlog_flush = int(config.get("interval_backlog_flush", 3600))
		self.backlog_limit = int(config.get("backlog_limit", 1000))
		self.sched.enter(0, 0, self.status_report, ())
		self.sched.enter(self.interval_backlog_flush, 0, self.backlog_flush, ())
		self.backlog = []
		# TODO load backlog from file

	def exit(self):
		self.logger.info("Termination requested, cancelling all tests and trying a backlog flush")
		self.cancel_all_tests()
		self.backlog_flush()
		# TODO write remaining backlog to file

	def cancel(self, test):
		test.cancel()
		self.tests.discard(test.sched_handle)

	def cancel_all_tests(self):
		for test in self.tests:
			test.cancel()
		self.tests.clear()

	def run(self):
		self.sched.run()

	def backlog_flush(self):
		logger = self.logger.getChild('backlog')
		if not self.backlog:
			return

		try:
			self.logger.debug("Flushing backlog ({} entries)".format(len(self.backlog)))
			while self.backlog:
				request, payload = self.backlog.pop(0)
				try:
					self.api.request(request, payload)
				except APIError:
					self.backlog.insert(0, (request, payload))
					self.logger.debug("Failed to flush backlog, trying again later")
					break
		finally:
			self.sched.enter(self.interval_backlog_flush, 0, self.backlog_flush)

	def backlog_append(self, request, payload):
		if len(self.backlog) > self.backlog_limit:
			self.logger.debug("Backlog too long, culled one old entry")
			self.backlog.pop(0)
		self.backlog.append((request, payload))

	def publish(self, test, result):
		msg = {"test": test.test, "policy": test.policy, "index": test.index, "result": result}
		try:
			self.api.request('publish', msg)
		except APIError:
			self.logger.warning("Failed to publish, backlogging")
			self.backlog_append('publish', msg)

	def report_error(self, test, error):
		# use backlog for errors. Yes, this might drop some error messages, but if it comes to that, the errors will probably be repeating anyway.
		msg = {"test": test.test, "policy": test.policy, "index": test.index, "error": str(error)}
		try:
			self.api.request('error', msg)
		except APIError:
			self.logger.warning("Failed to send error details, backlogging")
			self.backlog_append('error', msg)

	def status_report(self):
		logger = self.logger.getChild('status')
		try:
			logger.debug("Reporting status")
			response = self.api.request('status', {'policy': self.policy})

			if response['script'] != __version__ and self.under_updater:
				logger.info("New version available, requesting termination to update")
				raise SystemExit()

			if response['policy'] != self.policy:
				self.update_policy()
		except Exception:
			logger.log(logging.WARNING, "Failed to report status", exc_info=True)
			return

		finally:
			self.sched.enter(self.interval_status_report, 0, self.status_report, ())

	def update_policy(self):
		logger = self.logger.getChild('policy')
		try:
			logger.debug("Fetching policy")
			policy_resp = self.api.request('policy')
		except:
			logger.log(logging.WARNING, "Failed to update policy", exc_info=True)
			return

		policy_id = policy_resp['id']
		policy = policy_resp['policy']
		self.cancel_all_tests()
		for i, test_config in enumerate(policy.get('tests', [])):
			try:
				test = Test(self, policy_id, i, test_config)
				test.sched_handle = self.sched.enter(test.delay, 0, test.run, ())
				self.tests.add(test)
				logger.debug("Scheduled test {!r} in {} s, repeating every {} s".format(test.name, test.delay, test.repeat))
			except:
				logger.exception("Failed to schedule task {}".format(test_config['test']))
		if self.policy != policy_id:
			logger.info("Policy is now {!r}".format(policy_id))
		self.policy = policy_id

def main():
	def signal_exit(signal, frame):
		raise SystemExit(-signal)
	signal.signal(signal.SIGHUP, signal_exit)
	signal.signal(signal.SIGINT, signal_exit)
	signal.signal(signal.SIGTERM, signal_exit)

	import argparse

	ap = argparse.ArgumentParser()
	ap.add_argument("--config", help='Configuration file.')
	args = ap.parse_args()

	with open(args.config, 'r') as f:
		config = json.load(f)

	#HERE: upgrade config if necessary

	logging.config.dictConfig(config["logging"])
	logger = logging.getLogger('hamprobe')
	logger.info("HAMprobe version {!r}, configuration file {!r}".format(__version__, args.config))

	if config["hamprobe"]["key"] == '%PROBE_KEY%' or config["hamprobe"]["id"] == '%PROBE_ID%':
		raise RuntimeError("Configuration still has placeholder PROBE_ID and PROBE_KEY. Please download hamprobe.py from https://hamprobe.informatik.hs-augsburg.de/hamprobe.py (The file will include a unique key), and run that to regenerate the config.")

	probe = HAMprobe(config)
	try:
		probe.run()
	finally:
		probe.exit()

if __name__ == '__main__':
	sys.exit(main())
