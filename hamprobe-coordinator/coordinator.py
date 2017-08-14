import datetime
import functools
import ipaddress
import json
import logging
import hmac
from binascii import hexlify, unhexlify

import influxdb
from flask import Flask, Response, request, g, redirect, jsonify, abort

import db

logging.getLogger().setLevel(logging.DEBUG)

HAMNET_NETWORK = ipaddress.ip_network('44.0.0.0/8')

app = Flask(__name__)
app.config.from_envvar('COORDINATOR_CONFIG')

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
				abort(403, "This resource may not be accessed from this network.")
			elif net == 'hmac':
				session = get_session()
				request_probe_id = request.headers['X-Hamprobe-Id']
				request_hmac = request.headers['X-Hamprobe-Hmac']
				g.probe = session.query(db.Probe).filter(db.Probe.id == request_probe_id).one()
				probe_key = unhexlify(g.probe.key)
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
	if data["version"] != g.probe.target_script:
		probe_path = app.config['PROBE_VERSION_PATH'].format(g.probe.target_script)
		with open(probe_path, 'r') as f:
			return {"version": g.probe.target_script, "script": f.read()}
	return {}

master_ops = {'script': script}

# PROBE

def publish(data):
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
	policy_obj = get_session().query(db.Policy).filter(db.Policy.id == g.probe.target_policy).one()
	policy = json.loads(policy_obj.policy)
	return {"id": policy_obj.id, "policy": policy}

def status(data):
	return {'policy': g.probe.target_policy, 'script': g.probe.target_script}

def error(data):
	print(data)
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

# INSTALLER

# @app.route('/hamprobe_install.py')
# @restrict(internet=True, hamnet=False)
# def hamprobe():
# 	probe_id = hexlify(os.urandom(16))  # TODO rate limit registration?
# 	probe_key = hexlify(os.urandom(16))
# 	created = datetime.datetime.now()
# 	session = get_session()
# 	probe = db.Probe(id=probe_id, key=probe_key, created=created)
# 	session.add(probe)
# 	session.commit()

# 	with open(app.config['PROBE_INSTALLER_PATH'], 'r') as f:
# 		install_script = f.read()
# 	install_script = install_script.replace("%PROBE_ID%", probe_id, 1).replace("%PROBE_KEY%", probe_key, 1)
# 	return Response(install_script, mimetype="text/plain", headers={"Content-disposition": "attachment; filename=hamprobe.py"})

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
