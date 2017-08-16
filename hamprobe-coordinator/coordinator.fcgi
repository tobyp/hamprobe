#!/usr/bin/python3

# run:
# 	COORDINATOR_CONFIG=coordinator.conf spawn-fcgi -n -s /tmp/hamprobe-coordinator.sock -M 777 -- ./coordinator.fcgi

# lighttpd2:
# 	fastcgi "unix:/tmp/hamprobe-coordinator.sock";

from flup.server.fcgi import WSGIServer
from coordinator import app

# from urllib.parse import urljoin

# def wsgi_fix(f):
# 	def app(environ, start_response):
# 		environ['PATH_INFO'] = urljoin(environ['SCRIPT_NAME'], environ['PATH_INFO'])
# 		environ['SCRIPT_NAME'] = ''
# 		return f(environ, start_response)
# 	return app

# app.wsgi_app = wsgi_fix(app.wsgi_app)

if __name__ == '__main__':
	WSGIServer(app).run()
