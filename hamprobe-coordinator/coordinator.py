import binascii
import datetime
import functools
import hmac
import ipaddress
import logging
import logging.config
import os

from flask import Flask, Response, request, g, redirect, jsonify, abort, send_file
import influxdb
import yaml

import db

logging.getLogger().setLevel(logging.DEBUG)

HAMNET_NETWORK = ipaddress.ip_network('44.0.0.0/8')

app = Flask(__name__)
app.config.from_envvar('COORDINATOR_CONFIG')
logging.config.dictConfig(app.config['LOGGING'])

logger = logging.getLogger('hamprobe.coord')

def get_session():
	if not hasattr(g, 'db'):
		engine = db.get_engine(app.config)
		g.db = db.get_session(engine)
	return g.db

@app.teardown_appcontext
def close_session(error):
	if hasattr(g, 'db'):
		g.db.close()

def get_influx():
	if not hasattr(g, 'influx'):
		g.influx = influxdb.InfluxDBClient(*app.config["INFLUX"])
	return g.influx

@app.teardown_appcontext
def close_influx(error):
	if hasattr(g, 'influx'):
		delattr(g, 'influx')


def restrict(internet=True, hamnet='hmac'):
	def decorator(f):
		@functools.wraps(f)
		def wrapped(*args, **kwargs):
			remote = ipaddress.ip_address(request.remote_addr)
			net = hamnet if remote in HAMNET_NETWORK else internet
			if not net:
				abort(403, "This resource may not be accessed from the {}.".format("HAMNET" if remote in HAMNET_NETWORK else "INTERNET"))
			elif net == 'hmac':
				session = get_session()
				request_probe_id = request.headers['X-Hamprobe-Id']
				request_hmac = request.headers['X-Hamprobe-Hmac']
				g.probe = session.query(db.Probe).filter(db.Probe.id == request_probe_id).one()
				probe_key = binascii.unhexlify(g.probe.key)
				data = request.get_data()  # TODO limit length?
				mac = hmac.new(probe_key, data, digestmod='sha256').hexdigest()
				if request_hmac != mac:
					print("mismatch")
					abort(403, "HMAC mismatch")
			resp = f(*args, **kwargs)
			if net == 'hmac':
				mac = hmac.new(probe_key, resp.get_data(), digestmod='sha256').hexdigest()
				resp.headers.add('X-Hamprobe-Hmac', mac)
			return resp
		return wrapped
	return decorator

# MASTER

def script(data):
	probe_path = os.path.join('../hamprobe-probe/versions/', g.probe.target_script + '.py')
	with open(probe_path, 'r') as f:
		return {"version": g.probe.target_script, "script": f.read()}

master_ops = {'script': script}

# PROBE

def publish(data):
	logger.debug("publish from {} / {}".format(g.probe.id, request.remote_addr))
	influx = get_influx()
	result = data['result']
	if data['test'] == 'traceroute':
		points = []
		for trace in result:
			for i, hop in enumerate(trace):
				if "delay" in hop:
					p = {
						"measurement": 'delay',
						"tags": {
							"distance": i+1,
							"target": hop['dst'],
							"from": hop['src'],
							"to": hop['hop']
						},
						"time": datetime.datetime.fromtimestamp(hop['t'], datetime.timezone.utc).isoformat(),
						"fields": {
							"t": hop['delay']
						}}
					if "icmp" in hop:
						p['tags']['icmp_type'] = hop['icmp'][0]
						p['tags']['icmp_code'] = hop['icmp'][1]
					points.append(p)
		influx.write_points(points)
	else:
		print(data)

def policy(data):
	policy_path = os.path.join('policies/', g.probe.target_policy + ".yml")
	with open(policy_path, 'r') as f:
		policy = yaml.load(f)
	return {"id": g.probe.target_policy, "policy": policy}

def status(data):
	logger.info("status from {} / {} (target_policy {})".format(g.probe.id, request.remote_addr, g.probe.target_policy))
	session = get_session()
	g.probe.last_status = datetime.datetime.now()
	g.probe.last_ip = request.remote_addr
	session.add(g.probe)
	session.commit()
	return {'policy': g.probe.target_policy, 'script': g.probe.target_script}

def error(data):
	logger.error("error from {} / {}: {}".format(g.probe.id, request.remote_addr, data))
	return {}

probe_ops = {'status': status, 'publish': publish, 'policy': policy, 'error': error}

# API

@app.route('/api/probe', methods=['POST'], defaults={'ops': probe_ops, 'logger': logging.getLogger('api.probe')})
@app.route('/api/master', methods=['POST'], defaults={'ops': master_ops, 'logger': logging.getLogger('api.master')})
@restrict(internet='hmac', hamnet='hmac')
def api(ops, logger):
	try:
		req = request.json
		if 'op' not in req:
			return jsonify({"ret": "error", "error": "Missing 'op' field"})
		op = req['op']
		if op not in ops:
			return jsonify({"ret": "error", "error": "Unknown 'op'"})
		logger.info("probe {} op {}".format(g.probe.id, op))
		rdata = ops[op](request.json.get('data', None))
		return jsonify({"ret": "ok", "resp": rdata})
	except Exception:
		logger.exception("API error")
		return jsonify({"ret": "error", "error": "Remote error occurred."})

# KEYS

@app.route('/assets/hamprobe.conf')
@restrict(internet=True, hamnet=True)
def hamprobe_conf():
	probe_id = binascii.hexlify(os.urandom(16)).decode('ascii')  # TODO rate limit registration?
	probe_key = binascii.hexlify(os.urandom(16)).decode('ascii')
	created = datetime.datetime.now()
	session = get_session()
	probe = db.Probe(id=probe_id, key=probe_key, created=created, target_script="default", target_policy="default")
	session.add(probe)
	session.commit()

	with open('../hamprobe-probe/hamprobe.conf.sample', 'r') as f:
		config = f.read()
	config = config.replace("%PROBE_ID%", probe_id, 1).replace("%PROBE_KEY%", probe_key, 1)
	return Response(config, mimetype="text/plain", headers={"Content-disposition": "attachment; filename=hamprobe.conf"})

@app.route('/assets/hamprobe_master.py')
@restrict(internet=True, hamnet=True)
def hamprobe_master():
	return send_file('../hamprobe-probe/hamprobe_master.py', mimetype='text/x-python', as_attachment=True, attachment_filename="hamprobe_master.py")

@app.route('/assets/hamprobe_probe.py')
@restrict(internet=True, hamnet=True)
def hamprobe_probe():
	return send_file('../hamprobe-probe/hamprobe_probe.py', mimetype='text/x-python', as_attachment=True, attachment_filename="hamprobe_probe.py")

@app.route('/assets/hamprobe.service')
@restrict(internet=True, hamnet=True)
def hamprobe_service():
	return send_file('../hamprobe-probe/hamprobe.service', mimetype='text/plain', as_attachment=True, attachment_filename="hamprobe.service")

@app.route('/assets/hamprobe.init')
@restrict(internet=True, hamnet=True)
def hamprobe_init():
	return send_file('../hamprobe-probe/hamprobe.init', mimetype='text/x-shellscript', as_attachment=True, attachment_filename="hamprobe.init")

@app.route('/assets/hamprobe_install.sh')
@restrict(internet=True, hamnet=True)
def hamprobe_install():
	return send_file('../hamprobe-probe/hamprobe_install.sh', mimetype='text/x-shellscript', as_attachment=True, attachment_filename="hamprobe_install.sh")

# INDEX

@app.route('/')
@app.route('/index.html')
@restrict(internet=True, hamnet=True)
def index():
	return redirect('http://hamprobe.net', code=307)


def main():
	import argparse
	ap = argparse.ArgumentParser()
	ap.add_argument("--host", default="localhost")
	ap.add_argument("--port", type=int, default=5000)
	ap.add_argument("--debug", action='store_true', default=False)
	args = ap.parse_args()

	app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
	main()
