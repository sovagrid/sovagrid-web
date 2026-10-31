#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable real Hub behind the panel; fixture credentials never reach production."""
import http.client
import os
from pathlib import Path
import re
import signal
import sys
import tempfile
import threading
import uuid
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.environ.get('SOVAGRID_TEST_HUB', str(ROOT.parent / 'sovagrid-hub')))
from sovagrid_hub.store import Store
from sovagrid_hub.http_api import HubApp, make_server


def main():
    with tempfile.TemporaryDirectory(prefix='sovagrid-browser-') as temporary:
        store = Store(Path(temporary) / 'fixture.sqlite')
        store.initialize('owner', 'fixture-owner-passphrase')
        store.migrate()
        store.create_user('reader', 'fixture-reader-passphrase', 'viewer')
        store.create_user('operator', 'fixture-operator-passphrase', 'operator')
        server = store.create_server('Ubuntu fixture')
        now = int(time.time())
        for index in range(10):
            store.ingest(server['id'], {
                'collected_at': now - 300 + index * 30,
                'cpu_percent': 96 if index == 9 else 20 + index * 3,
                'memory_percent': 42, 'disk_percent': 38,
                'network_rx_bytes': 10000 + index * 500,
                'network_tx_bytes': 5000 + index * 100,
                'load1': 0.25, 'uptime_seconds': 86400,
                'memory_total_bytes': 8 * 1024 ** 3,
                'memory_available_bytes': 4 * 1024 ** 3,
                'disk_total_bytes': 100 * 1024 ** 3,
                'disk_available_bytes': 62 * 1024 ** 3,
            }, now=now)
        # Seed a bounded, synthetic result through the real checks store. No
        # worker runs and no socket is opened to this intentionally invalid host.
        check_id = str(uuid.uuid4())
        store.save_check_config(server['id'], {'revision': 0, 'checks': [{
            'id': check_id, 'name': 'Fixture HTTPS', 'kind': 'http', 'enabled': True,
            'url': 'https://fixture.invalid/health', 'interval_seconds': 60, 'timeout_seconds': 5,
        }]})
        lease = store.claim_check(server['id'], server['agent_token'], {'protocol': 1})['lease']
        store.record_check_result(server['id'], check_id, server['agent_token'], {
            'lease_id': lease['id'], 'config_revision': lease['config_revision'],
            'observed_at': now, 'status': 'up', 'latency_ms': 2,
            'http_status': 200, 'tls_expires_at': now + 7 * 86400, 'error_code': None,
        })
        api = make_server(HubApp(store, vpn_status_path=str(Path(temporary) / 'vpn.json')), 0)
        threading.Thread(target=api.serve_forever, daemon=True).start()

        class Handler(SimpleHTTPRequestHandler):
            APP_PREFIX = '/sovagrid/monitoring/'
            CUSTOM_PREFIX = '/ops/monitoring/'
            PORTABLE_IMAGE_PATH = '/api/v1/host-backups/operations/' + 'b' * 32 + '/portable/download/images'
            PORTABLE_IMAGE = b'disposable-image-archive'
            portable_used_grants = set()
            portable_grant_lock = threading.Lock()

            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(ROOT), **kwargs)

            def log_message(self, *_args):
                pass

            def proxy(self):
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 <= length <= 256 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(length) if length else None
                connection = http.client.HTTPConnection('127.0.0.1', api.server_port, timeout=15)
                try:
                    headers = {name: self.headers[name] for name in
                        ('Content-Type', 'Authorization', 'Idempotency-Key') if name in self.headers}
                    connection.request(self.command, self.path, body=body, headers=headers)
                    response = connection.getresponse()
                    data = response.read(1024 * 1024)
                    self.send_response(response.status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Cache-Control', 'no-store')
                    self.end_headers()
                    self.wfile.write(data)
                finally:
                    connection.close()

            def do_GET(self):
                if self.path == self.PORTABLE_IMAGE_PATH:
                    # Native browser downloads bypass Playwright request routing.
                    # Serve a disposable, one-use cookie fixture on the UI origin.
                    cookie = self.headers.get('Cookie', '')
                    grant = re.search(r'(?:^|;\s*)sg_portable_smoke=([a-f0-9]{32})(?:;|$)', cookie)
                    if not grant:
                        self.send_error(403)
                        return
                    with self.portable_grant_lock:
                        if grant.group(1) in self.portable_used_grants:
                            self.send_error(403)
                            return
                        self.portable_used_grants.add(grant.group(1))
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Disposition', 'attachment; filename="images.tar"')
                    self.send_header('Content-Length', str(len(self.PORTABLE_IMAGE)))
                    self.send_header('Cache-Control', 'no-store')
                    self.end_headers()
                    self.wfile.write(self.PORTABLE_IMAGE)
                elif self.path.startswith('/api/') or self.path == '/healthz':
                    self.proxy()
                elif self.path == '/' and self.headers.get('Host') == 'localhost:8900':
                    # A second loopback origin models the public `untouched`
                    # rule without changing older tests of the local listener.
                    self.send_error(404)
                elif self.path == '/sovagrid/monitoring':
                    self.send_response(308)
                    self.send_header('Location', self.APP_PREFIX)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                elif self.path.startswith((self.APP_PREFIX, self.CUSTOM_PREFIX)):
                    prefix = self.APP_PREFIX if self.path.startswith(self.APP_PREFIX) else self.CUSTOM_PREFIX
                    self.path = '/' + self.path[len(prefix):]
                    super().do_GET()
                elif self.path in ('/', '/index.html') or self.path.startswith(('/icons/', '/vendor/')):
                    super().do_GET()
                elif self.path.count('/') == 1 and self.path.split('?', 1)[0].endswith(('.js', '.css', '.webmanifest', '.html')):
                    super().do_GET()
                else:
                    self.send_error(404)

            do_POST = do_PATCH = do_DELETE = proxy

        ui = ThreadingHTTPServer(('127.0.0.1', 8900), Handler)

        def stop(_signal, _frame):
            raise KeyboardInterrupt()

        signal.signal(signal.SIGTERM, stop)
        try:
            ui.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            ui.server_close()
            api.shutdown()
            api.server_close()


if __name__ == '__main__':
    main()
