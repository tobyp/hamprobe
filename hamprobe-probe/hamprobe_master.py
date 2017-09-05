#!/usr/bin/python3

'''HAMprobe v1.0: HAMnet Measurement Probe - Master
https://hamprobe.informatik.hs-augsburg.de
(c) 2017 Tobias Peter DB1QP <tobias.peter@hs-augsburg.de>'''

__version__ = "0"

import binascii
import hashlib
import hmac
import http.client
import json
import logging
import logging.config
import signal
import socket
import subprocess
import sys
import time
import urllib.parse

DEFAULT_CONFIG = "/etc/hamprobe.conf"


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


def fetch_script(logger, api, current_version):
	try:
		response = api.request('script', {"version": current_version})
		if 'version' in response:
			new_version = response['version']
			new_script = response['script'].replace('%PROBE_VERSION%', new_version, 1)
			logger.debug("New version available: {}".format(new_version))
			return new_version, new_script
	except APIError:
		logger.info("Failed to check for updates, keep using the old one.")

	return current_version, None

class Probe:
	def __init__(self, logger, probe_path, config_path):
		self.logger = logger
		self.probe_path = probe_path
		self.config_path = config_path
		self.version = self._read_version()
		self._probe_process = None

	def __del__(self):
		self.stop()

	@property
	def running(self):
		if self._probe_process is None:
			return False
		if self._probe_process.poll() is None:
			return True
		self._probe_process = None
		return False

	def start(self):
		if self.running:
			return
		self.logger.info("Starting version {!r}".format(self.version))
		self._probe_process = subprocess.Popen([sys.executable, self.probe_path, '--config', self.config_path])

	def run(self):
		if self.running:
			raise RuntimeError("Already running")
		self.start()
		self._probe_process.wait()
		self.logger.info("Probe exited.")

	def stop(self):
		if not self.running:
			return
		self.logger.info("Terminating probe.")
		self._probe_process.terminate()
		self._probe_process = None

	def update(self, api):
		try:
			response = api.request('script', {'version': self.version})
			version = response['version']
			if version != self.version:
				script = response['script'].replace('%PROBE_VERSION%', version)
				self.logger.debug("Updating from version {!r} to {!r}".format(self.version, version))
				try:
					with open(self.probe_path, 'w') as f:
						f.write(script)
					self.version = version
				except:
					pass
		except APIError:
			self.logger.info("Failed to check for updates.")

	def _read_version(self):
		try:
			with open(self.probe_path, 'r') as f:
				return f.read().split("__version__ = '", 1)[1].split("'\n", 1)[0]
		except:
			return None


def command_run(pargs, cargs):
	with open(pargs.config, 'r') as f:
		config = json.load(f)

	logging.config.dictConfig(config["logging"])
	logger = logging.getLogger('hamprobe.master')

	api = API(logger.getChild('api'), __version__, config, 'master')
	probe = Probe(logger, config["path"]["probe"], pargs.config)

	try:
		while True:
			probe.update(api)
			if probe.version is not None:
				probe.run()
			else:
				logger.info("No script installed and failed to fetch one; waiting a while before trying again")
				time.sleep(int(config.get("interval_status_report", 3600)))
	finally:
		probe.stop()


def main():
	def signal_exit(signal, frame):
		raise SystemExit(-signal)
	signal.signal(signal.SIGHUP, signal_exit)
	signal.signal(signal.SIGINT, signal_exit)
	signal.signal(signal.SIGTERM, signal_exit)

	print(__import__(__name__).__doc__)
	import argparse
	import sys

	commands = {n.replace("command_", "", 1): v for n, v in globals().items() if n.startswith("command_")}
	ap = argparse.ArgumentParser("HAMprobe Angel - Installer/Configurator/Updater")
	ap.add_argument("--config", "-c", default=DEFAULT_CONFIG, help='Configuration file')
	ap.add_argument("command", choices=commands, default="run")
	ap.add_argument("command_args", nargs=argparse.REMAINDER)
	args = ap.parse_args()
	command = commands[args.command]
	return command(args, args.command_args)

if __name__ == '__main__':
	import sys
	sys.exit(main())
