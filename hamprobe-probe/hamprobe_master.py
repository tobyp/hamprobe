#!/usr/bin/python3

'''HAMprobe v1.0: HAMnet Measurement Probe - Master
https://hamprobe.informatik.hs-augsburg.de
(c) 2017 Tobias Peter DB1QP <tobias.peter@hs-augsburg.de>'''

__version__ = "0"

import atexit
import binascii
import errno
import hmac
import http.client
import json
import logging
import logging.config
import os
import subprocess
import sys
import time
import urllib.parse

DEFAULT_CONFIG = "/etc/hamprobe.conf"


class API:
	def __init__(self, logger, version, config, api_name):
		self.logger = logger
		self.version = version
		self.probe_id = config["hamprobe"]["id"]
		self.probe_key = binascii.unhexlify(config["hamprobe"]["key"])
		self.apis = config["apis"][api_name]

	def request(self, op, data=None):
		req = {"v": self.version, "op": op, "data": data or {}}
		body = json.dumps(req).encode('utf-8')
		mac = hmac.new(self.probe_key, body, digestmod='sha256').hexdigest()
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
			except (OSError, http.client.BadStatusLine) as e:
				if isinstance(e, ConnectionError) or isinstance(e, OSError) and e.errno in {errno.EHOSTDOWN, errno.EHOSTUNREACH, errno.ENETDOWN, errno.ENETUNREACH}:
					self.logger.debug("Failed to connect to api at {}, trying next option.".format(api['url']))
					continue
				elif isinstance(e, http.client.BadStatusLine):
					self.logger.debug("Failed to connect to api at {}, trying next option.".format(api['url']))
					continue
				else:
					raise

			if resp.status == 503:
				raise ConnectionError("Broken Gateway")
			if resp.status != 200:
				raise RuntimeError("HTTP error: {} {}".format(resp.status, resp.code))
			rbody = resp.read()
			rbody_mac = hmac.new(self.probe_key, rbody, digestmod='sha256').hexdigest()
			if resp.getheader('X-Hamprobe-Hmac') != rbody_mac:
				raise RuntimeError("HMAC mismatch")
			rdata = json.loads(rbody.decode('utf-8'))
			if rdata.get('ret', None) != 'ok':
				raise RuntimeError("API returned an error: {}".format(rdata))
			return rdata.get('resp', None)
		else:
			raise ConnectionError("Failed to connect to API")

def fetch_script(logger, api, current_version):
	try:
		response = api.request('script', {"version": current_version})
		if 'version' in response:
			new_version = response['version']
			new_script = response['script'].replace('%PROBE_VERSION%', new_version, 1)
			logger.debug("New version available: {}".format(new_version))
			return new_version, new_script
	except ConnectionError:
		logger.info("Failed to check for updates, keep using the old one.")

	return current_version, None


def command_run(pargs, cargs):
	with open(pargs.config, 'r') as f:
		config = json.load(f)

	logging.config.dictConfig(config["logging"])
	logger = logging.getLogger('hamprobe.master')

	api = API(logger.getChild('api'), __version__, config, 'master')
	probe_script_path = config["path"]["probe"]
	interval_update = int(config.get("interval_update_check", 0))
	if interval_update <= 0:
		interval_update = None

	probe_version = None
	try:
		with open(probe_script_path, 'r') as f:
			probe_version = f.read().split("__version__ = '", 1)[1].split("'\n", 1)[0]
	except:
		pass

	probe_subproc = None

	def exit_handler():
		nonlocal probe_subproc
		if probe_subproc is not None:
			try:
				probe_subproc.terminate()
			except:
				pass
			finally:
				probe_subproc = None
	atexit.register(exit_handler)

	while True:
		# 1. get script if we need to
		if interval_update is not None or probe_version is None:
			if probe_version is None:
				logger.info("Fetching worker script (just on first run)")
			else:
				logger.debug("Checking for updates")

			probe_version, probe_script = fetch_script(logger, api, probe_version)
			if probe_script is not None:  # we have an update
				logger.debug("Installing new version {!r}".format(probe_version))
				# Terminate the old one so we can update the script (it will flush backlog on SIGTERM)
				if probe_subproc is not None:
					try:
						probe_subproc.terminate()
					except:
						pass
					finally:
						probe_subproc = None
				# Write new script
				with open(probe_script_path, 'w') as f:
					f.write(probe_script)

		# 2. Run it if we can
		if probe_version is None:
			logger.info("No script installed and failed to fetch one; waiting one update interval to try again")
			time.sleep(interval_update)
		else:
			if probe_subproc is None:
				logger.info("Starting probe {}.".format(probe_version))
				probe_subproc = subprocess.Popen([sys.executable, probe_script_path, '--config', pargs.config])

			try:
				probe_subproc.wait(interval_update)
				logger.info("probe exited by itself.")
			except subprocess.TimeoutExpired:  # time to update again
				continue
			except (KeyboardInterrupt, SystemExit):
				return


def main():
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
