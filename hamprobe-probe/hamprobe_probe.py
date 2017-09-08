#!/usr/bin/python3

'''HAMprobe v1.0: HAMnet Measurement Probe
https://hamprobe.informatik.hs-augsburg.de
(c) 2017 Tobias Peter DB1QP <tobias.peter@hs-augsburg.de>
THIS SCRIPT SHOULD NOT BE CALLED MANUALLY, BUT BY hamprobe_master.py !!!'''

__version__ = '%PROBE_VERSION%'

import binascii
import distutils.spawn
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
import subprocess
import sys
import time
import traceback

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

# TESTS

def test_traceroute(probe, params):
	c_targets = params['targets']
	c_distance = int(params.get('distance', 2))
	c_timeout = int(params.get('timeout', 5))

	results = []
	for target in c_targets:
		results.append(traceroute(target, c_distance, c_timeout))
	return results

def test_iperf(probe, params):
	iperf_executable = distutils.spawn.find_executable('iperf3')
	if iperf_executable is None:
		return
	c_target = params['target']
	command = [iperf_executable, '--clent', c_target, '--json', mode]
	mode = params.get('mode')
	if mode in ['udp']:
		command.append('--udp')
	elif mode is not None:
		raise ValueError("Unknown mode")
	if 'bandwidth' in params:
		command.extend(('--bandwidth', str(params['bandwidth'])))
	if 'time' in params:
		command.extend(('--time', str(params['time'])))
	iperf_proc = subprocess.Popen(command, stdout=subprocess.PIPE)
	iperf_proc.wait()
	result = json.loads(iperf_proc.stdout.read().decode('utf-8'))
	if 'error' in result:
		return {"error": result['error']}
	return {"start": result["start"], "end": result['end']}


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
	def __init__(self, probe, name, config):
		self.probe = probe
		self.name = name
		self.config = config
		self.test = config['test']
		self.func = globals()['test_' + self.test]
		self.logger = probe.logger.getChild('test').getChild(self.test)
		self.config = config
		self.delay = int(config.get("delay", 0))
		self.repeat = int(config.get("repeat", 60*60))
		self.params = config.get("params", {})
		self.handle = None

	def schedule(self):
		if self.handle is not None:
			raise RuntimeError("Test already scheduled.")
		self.handle = self.probe.sched.enter(self.delay, 0, self.run, ())
		self.probe.tests.add(self)

	def run(self):
		try:
			self.handle = None
			result = self.func(self.logger, self.params)
		except Exception:
			self.logger.debug("failed, not rescheduling")
			self.probe.tests.discard(self)
			self.probe.report_error(self, sys.exc_info())
		else:
			self.logger.debug("succeeded, rescheduling")
			self.probe.report_result(self, result)
			self.handle = self.probe.sched.enter(self.repeat, 0, self.run, ())

	def cancel(self):
		if self.handle is None:
			return
		self.probe.sched.cancel(self.handle)
		self.probe.tests.discard(self)
		self.handle = None

	def __hash__(self):
		return id(self)

	def __eq__(self, other):
		return self is other


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
		self.sched.enter(0, 0, self.task_status_report, ())
		self.sched.enter(0, 0, self.task_backlog_flush, ())
		self.backlog = []
		# TODO load backlog from file

	def exit(self):
		self.logger.info("Terminating: cancelling all tests and flushing backlog")
		self.cancel_all_tests()
		self.backlog_flush()
		# TODO write remaining backlog to file

	def cancel_all_tests(self):
		for test in set(self.tests):
			test.cancel()

	def run(self):
		self.sched.run()

	def task_status_report(self):
		try:
			self.status_report()
		except Exception:
			self.logger.log(logging.WARNING, "Failed to report status", exc_info=True)
		finally:
			self.sched.enter(self.interval_status_report, 0, self.task_status_report, ())

	def task_backlog_flush(self):
		try:
			self.backlog_flush()
		except Exception:
			self.logger.log(logging.WARNING, "Error flushing backlog.", exc_info=True)
		finally:
			self.sched.enter(self.interval_backlog_flush, 0, self.task_backlog_flush, ())

	def status_report(self):
		logger = self.logger.getChild('status')
		logger.debug("Reporting status")
		try:
			response = self.api.request('status', {'policy': self.policy})
		except APIError:
			self.logger.debug("API error, trying again later.")
			return

		# The status report went through, so we have a connection. Let's try to flush the backlog.
		if self.backlog:
			self.backlog_flush()

		if response['script'] != __version__ and self.under_updater:
			logger.info("New version available")
			raise SystemExit()

		if response['policy'] != self.policy:
			self.policy_update()

	def policy_update(self):
		logger = self.logger.getChild('policy')
		try:
			logger.debug("Fetching policy")
			policy_resp = self.api.request('policy')
			policy_id = policy_resp['id']
			policy = policy_resp['policy']
		except:
			logger.log(logging.WARNING, "Failed to update policy", exc_info=True)
			return

		self.cancel_all_tests()
		for test_index, test_config in enumerate(policy.get('tests', [])):
			test_name = "{}.{}.{}".format(policy_id, test_index, test_config.get('test', '<invalid>'))
			try:
				test = Test(self, test_name, test_config)
				test.schedule()
			except:
				logger.exception("Failed to schedule test {}".format(test_name))

		if self.policy != policy_id:
			logger.info("Policy is now {!r}".format(policy_id))
		self.policy = policy_id

	def report_result(self, test, result):
		msg = {"test": test.test, "name": test.name, "result": result}
		try:
			self.api.request('publish', msg)
		except APIError:
			self.logger.warning("Failed to report test results, backlogging")
			self.backlog_append('publish', msg)

	def report_error(self, test, exc_info):
		# use backlog for errors. Yes, this might drop some error messages, but if it comes to that, the errors will probably be repeating anyway.
		msg = {"test": test.test, "name": test.name, "error": traceback.format_exception(*exc_info)}
		try:
			self.api.request('error', msg)
		except APIError:
			self.logger.warning("Failed to report error details, backlogging")
			self.backlog_append('error', msg)

	def backlog_flush(self):
		if not self.backlog:
			return

		logger = self.logger.getChild('backlog')
		logger.debug("Attempting to flush {} entries".format(len(self.backlog)))
		while self.backlog:
			request, payload = self.backlog.pop(0)
			try:
				self.api.request(request, payload)
			except APIError:
				self.backlog.insert(0, (request, payload))
				logger.debug("API error, trying again later.")
				break

	def backlog_append(self, request, payload):
		logger = self.logger.getChild('backlog')
		if len(self.backlog) > self.backlog_limit:
			logger.debug("Backlog too long, culled one old entry")
			self.backlog.pop(0)
		self.backlog.append((request, payload))


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

	logging.config.dictConfig(config["logging"])
	logger = logging.getLogger('hamprobe')
	logger.info("HAMprobe version {!r}, configuration file {!r}".format(__version__, args.config))

	if config["hamprobe"]["key"] == '%PROBE_KEY%' or config["hamprobe"]["id"] == '%PROBE_ID%':
		raise RuntimeError("Configuration still has placeholder PROBE_ID and PROBE_KEY. Please download hamprobe.py from https://hamprobe.informatik.hs-augsburg.de/hamprobe.py (The file will include a unique key), and run that to regenerate the config.")

	#HERE: upgrade config if necessary

	probe = HAMprobe(config)
	try:
		probe.run()
	finally:
		probe.exit()

if __name__ == '__main__':
	sys.exit(main())
