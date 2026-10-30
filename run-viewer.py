import errno
import gzip
import http.server
import ipaddress
import json
import os
import re
import select
import socket
import socketserver
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zlib

DIRECTORY = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(DIRECTORY, 'index.html')

# Pe Render (sau orice hosting) variabila PORT e setată de platformă.
HOSTED = 'PORT' in os.environ
PORT = int(os.environ.get('PORT', 8080))
BIND = '0.0.0.0' if HOSTED else '127.0.0.1'

# Când rulează public, proxy-ul nu are voie să ajungă la rețele interne (SSRF).
# Local e permis, ca să poți testa și un dev server (ex. http://localhost:3000).
ALLOW_PRIVATE = os.environ.get('ALLOW_PRIVATE_NETWORK', '0' if HOSTED else '1') == '1'

MAX_BYTES = 15 * 1024 * 1024
TIMEOUT = 20

USER_AGENTS = {
    'chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'googlebot-smartphone': 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'googlebot-desktop': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/130.0.0.0 Safari/537.36',
}


class BlockedURL(Exception):
    pass


def resolve_allowed(host, port):
    """Resolve host and return its addresses, refusing non-public IPs unless ALLOW_PRIVATE."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise BlockedURL(f'Nu s-a putut rezolva domeniul {host}: {e}')
    if not ALLOW_PRIVATE:
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split('%')[0])
            if getattr(ip, 'ipv4_mapped', None):
                ip = ip.ipv4_mapped
            if not ip.is_global:
                raise BlockedURL(f'Adresa {ip} ({host}) nu este publică — blocată.')
    return infos


def check_url(url):
    """Allow only http(s) URLs whose host resolves to public IPs (unless ALLOW_PRIVATE)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise BlockedURL('Sunt permise doar URL-uri http:// sau https://')
    resolve_allowed(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))


# ── Egress proxy ─────────────────────────────────────────────────────────────
# Every outgoing connection (urllib and Chromium) goes through this local proxy.
# It checks the IP it actually connects to, so redirects, subresources, WebSockets
# and DNS changes between check and connect can't reach internal addresses.

def open_upstream(host, port):
    last_error = None
    for family, socktype, proto, _, addr in resolve_allowed(host, port):
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(TIMEOUT)
        try:
            sock.connect(addr)
            return sock
        except OSError as e:
            last_error = e
            sock.close()
    raise last_error or OSError(f'Nu s-a putut conecta la {host}:{port}')


def pipe(client, upstream):
    """Relay bytes both ways until either side closes."""
    sockets = [client, upstream]
    while True:
        readable, _, _ = select.select(sockets, [], [], 120)
        if not readable:
            return
        for sock in readable:
            data = sock.recv(65536)
            if not data:
                return
            (upstream if sock is client else client).sendall(data)


class EgressProxyHandler(socketserver.StreamRequestHandler):
    # Unbuffered, so no client bytes past the headers get stuck in rfile before piping.
    rbufsize = 0

    def handle(self):
        try:
            request_line = self.rfile.readline(65537).decode('latin-1').strip()
            method, target, _ = request_line.split(' ', 2)
            headers = []
            while True:
                line = self.rfile.readline(65537)
                if line in (b'\r\n', b'\n', b''):
                    break
                headers.append(line)

            if method == 'CONNECT':
                host, _, port = target.rpartition(':')
                upstream = open_upstream(host.strip('[]'), int(port))
                self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                self.wfile.flush()
            else:
                url = urllib.parse.urlsplit(target)
                if url.scheme != 'http' or not url.hostname:
                    raise BlockedURL('Proxy: cerere invalidă')
                upstream = open_upstream(url.hostname, url.port or 80)
                path = (url.path or '/') + (f'?{url.query}' if url.query else '')
                kept = [h for h in headers if not re.match(rb'(proxy-connection|connection|keep-alive)\s*:', h, re.I)]
                upstream.sendall(f'{method} {path} HTTP/1.1\r\n'.encode('latin-1') + b''.join(kept) + b'Connection: close\r\n\r\n')
        except BlockedURL as e:
            print(f'[!] Egress blocked: {e}')
            self.wfile.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            return
        except Exception:
            self.wfile.write(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            return
        with upstream:
            try:
                pipe(self.connection, upstream)
            except OSError:
                pass


class EgressProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_egress_proxy():
    server = EgressProxy(('127.0.0.1', 0), EgressProxyHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f'http://127.0.0.1:{server.server_address[1]}'


EGRESS_PROXY = None


class RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validates every redirect hop and records the chain."""

    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = urllib.parse.urljoin(req.full_url, newurl)
        check_url(newurl)
        self.chain.append({'status': code, 'from': req.full_url, 'to': newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def decompress(content, encoding):
    try:
        if 'gzip' in encoding:
            return gzip.decompress(content)
        if 'deflate' in encoding:
            try:
                return zlib.decompress(content)
            except zlib.error:
                return zlib.decompress(content, -zlib.MAX_WBITS)
    except Exception as e:
        print(f'[!] Decompression error ({encoding}): {e}')
    return content


def decode_body(content, content_type):
    charset = None
    m = re.search(r'charset=["\']?([\w.:-]+)', content_type or '', re.I)
    if m:
        charset = m.group(1)
    else:
        m = re.search(rb'<meta[^>]+charset=["\']?([\w.:-]+)', content[:4096], re.I)
        if m:
            charset = m.group(1).decode('ascii', 'ignore')
    try:
        return content.decode(charset or 'utf-8', errors='replace'), charset or 'utf-8 (implicit)'
    except LookupError:
        return content.decode('utf-8', errors='replace'), 'utf-8 (fallback)'


def fetch(url, ua_key):
    check_url(url)
    ua = USER_AGENTS.get(ua_key, USER_AGENTS['chrome'])
    redirects = RecordingRedirectHandler()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({'http': EGRESS_PROXY, 'https': EGRESS_PROXY}), redirects)
    req = urllib.request.Request(url, headers={
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ro-RO,ro;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
    })

    started = time.time()
    try:
        response = opener.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        # 4xx/5xx still have a body worth inspecting; the status itself matters for SEO.
        response = e

    with response:
        raw = response.read(MAX_BYTES + 1)
        truncated = len(raw) > MAX_BYTES
        raw = raw[:MAX_BYTES]
        headers = response.headers
        content = decompress(raw, (headers.get('Content-Encoding') or '').lower())
        html, charset = decode_body(content, headers.get('Content-Type'))
        return {
            'ok': True,
            'status': response.status,
            'reason': response.reason,
            'requested_url': url,
            'final_url': response.url,
            'redirects': redirects.chain,
            'headers': {k.lower(): v for k, v in headers.items()},
            'charset': charset,
            'bytes': len(content),
            'truncated': truncated,
            'elapsed_ms': int((time.time() - started) * 1000),
            'user_agent': ua,
            'html': html,
        }


# ── Headless Chromium rendering (Playwright) ─────────────────────────────────
# Optional: available when the `playwright` package and its Chromium are installed
# (the Dockerfile uses the official Playwright image). Without it, /render reports
# itself as unavailable and the viewer falls back to manual paste.

RENDER_TIMEOUT = 30          # seconds for the whole navigation
NETWORK_IDLE_TIMEOUT = 8     # extra wait for XHR/fetch content after "load"
DOM_STABLE_TIMEOUT = 6       # if the network never goes idle, wait at most this long for the text to settle
RENDER_QUEUE_TIMEOUT = 60    # how long a request waits for a free browser slot
# One Chromium at a time: the free Render instance has 512 MB RAM.
RENDER_SLOTS = threading.Semaphore(int(os.environ.get('RENDER_CONCURRENCY', '1')))
# Images, media and fonts don't change the text, but cost memory and time.
SKIPPED_RESOURCES = {'image', 'media', 'font'}

VIEWPORTS = {
    'googlebot-smartphone': {'viewport': {'width': 412, 'height': 732}, 'is_mobile': True, 'has_touch': True, 'device_scale_factor': 2.625},
    'googlebot-desktop': {'viewport': {'width': 1350, 'height': 1000}},
    'chrome': {'viewport': {'width': 1366, 'height': 900}},
}

render_status = {'available': False, 'reason': 'Playwright nu este instalat pe server.'}


def detect_render_support():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return
    try:
        with sync_playwright() as p:
            path = p.chromium.executable_path
        if os.path.exists(path):
            render_status.update(available=True, reason='')
        else:
            render_status['reason'] = 'Chromium nu este instalat (rulează aplicația cu Dockerfile-ul inclus).'
    except Exception as e:
        render_status['reason'] = f'Playwright indisponibil: {e}'


class RenderBusy(Exception):
    pass


def wait_for_stable_text(page, timeout):
    """Poll the body text length until it stays the same for 1.5 s. Returns False on timeout."""
    deadline = time.time() + timeout
    last, unchanged = None, 0
    while time.time() < deadline:
        try:
            length = page.evaluate('document.body ? document.body.innerText.length : 0')
        except Exception:
            return False
        unchanged = unchanged + 1 if length == last else 0
        if unchanged >= 3:
            return True
        last = length
        page.wait_for_timeout(500)
    return False


def render(url, ua_key):
    """Load the page in headless Chromium, run its JavaScript and return the rendered DOM."""
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

    check_url(url)
    ua = USER_AGENTS.get(ua_key, USER_AGENTS['chrome'])
    stats = {'requests': 0, 'skipped': 0, 'blocked': 0, 'failed': 0}
    console_errors = []
    failed_requests = []
    host_ok = {}

    def allowed(request_url):
        host = urllib.parse.urlparse(request_url).hostname
        if host not in host_ok:
            try:
                check_url(request_url)
                host_ok[host] = True
            except BlockedURL:
                host_ok[host] = False
        return host_ok[host]

    def handle(route):
        # Security is enforced by the egress proxy; this only skips heavy resources
        # and fails early on hosts that would be refused anyway.
        request = route.request
        stats['requests'] += 1
        if request.resource_type in SKIPPED_RESOURCES:
            stats['skipped'] += 1
            # 'blockedbyclient' tells our own skips apart from real failures in the events below.
            return route.abort('blockedbyclient')
        if not request.url.startswith(('http://', 'https://')) or not allowed(request.url):
            stats['blocked'] += 1
            return route.abort('blockedbyclient')
        route.continue_()

    if not RENDER_SLOTS.acquire(timeout=RENDER_QUEUE_TIMEOUT):
        raise RenderBusy('Serverul randează deja altă pagină. Încearcă din nou în câteva secunde.')
    started = time.time()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                # '<-loopback>' makes Chromium send even localhost traffic through the proxy.
                proxy={'server': EGRESS_PROXY, 'bypass': '<-loopback>'},
                args=['--disable-dev-shm-usage', '--disable-gpu', '--disable-quic',
                      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'],
            )
            try:
                context = browser.new_context(
                    user_agent=ua,
                    locale='ro-RO',
                    service_workers='block',
                    **VIEWPORTS.get(ua_key, VIEWPORTS['chrome']),
                )
                page = context.new_page()
                page.route('**/*', handle)
                def on_request_failed(request):
                    if 'ERR_BLOCKED_BY_CLIENT' in (request.failure or ''):
                        return
                    stats['failed'] += 1
                    if len(failed_requests) < 15:
                        failed_requests.append({'url': request.url[:300], 'type': request.resource_type, 'error': request.failure})

                def on_console(message):
                    # "Failed to load resource" duplicates requestfailed; our own skips are not errors.
                    if message.type != 'error' or 'Failed to load resource' in message.text or len(console_errors) >= 10:
                        return
                    console_errors.append(message.text[:300])

                page.on('requestfailed', on_request_failed)
                page.on('console', on_console)
                page.on('pageerror', lambda e: len(console_errors) < 10 and console_errors.append(str(e)[:300]))

                response = page.goto(url, wait_until='domcontentloaded', timeout=RENDER_TIMEOUT * 1000)
                timed_out = False
                dom_stable = True
                for state, timeout in (('load', RENDER_TIMEOUT), ('networkidle', NETWORK_IDLE_TIMEOUT)):
                    try:
                        page.wait_for_load_state(state, timeout=timeout * 1000)
                    except PlaywrightTimeout:
                        timed_out = True
                if timed_out:
                    # Analytics, chat widgets or long polling keep the network busy forever;
                    # what matters is whether the visible text has stopped changing.
                    dom_stable = wait_for_stable_text(page, DOM_STABLE_TIMEOUT)
                html = page.content()
                return {
                    'ok': True,
                    'status': response.status if response else None,
                    'final_url': page.url,
                    'html': html,
                    'bytes': len(html.encode('utf-8')),
                    'elapsed_ms': int((time.time() - started) * 1000),
                    'network_idle_timeout': timed_out,
                    'dom_stable': dom_stable,
                    'console_errors': console_errors,
                    'failed_requests': failed_requests,
                    'user_agent': ua,
                    **stats,
                }
            finally:
                browser.close()
    finally:
        RENDER_SLOTS.release()


class ProxyHandler(http.server.BaseHTTPRequestHandler):

    def send_json(self, code, payload):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == '/proxy':
            query = urllib.parse.parse_qs(parsed.query)
            target_url = query.get('url', [''])[0].strip()
            if not target_url:
                return self.send_json(400, {'ok': False, 'error': "Lipsește parametrul 'url'"})
            try:
                print(f'[*] Fetching: {target_url}')
                return self.send_json(200, fetch(target_url, query.get('ua', ['chrome'])[0]))
            except BlockedURL as e:
                return self.send_json(403, {'ok': False, 'error': str(e)})
            except Exception as e:
                print(f'[!] Error fetching {target_url}: {e}')
                return self.send_json(502, {'ok': False, 'error': f'Eroare la descărcare: {e}'})

        if parsed.path == '/render':
            if not render_status['available']:
                return self.send_json(501, {'ok': False, 'error': render_status['reason']})
            query = urllib.parse.parse_qs(parsed.query)
            target_url = query.get('url', [''])[0].strip()
            if not target_url:
                return self.send_json(400, {'ok': False, 'error': "Lipsește parametrul 'url'"})
            try:
                print(f'[*] Rendering: {target_url}')
                return self.send_json(200, render(target_url, query.get('ua', ['chrome'])[0]))
            except BlockedURL as e:
                return self.send_json(403, {'ok': False, 'error': str(e)})
            except RenderBusy as e:
                return self.send_json(429, {'ok': False, 'error': str(e)})
            except Exception as e:
                print(f'[!] Error rendering {target_url}: {e}')
                return self.send_json(502, {'ok': False, 'error': f'Eroare la randare: {e}'})

        if parsed.path == '/capabilities':
            return self.send_json(200, {'render': render_status['available'], 'reason': render_status['reason']})

        # Only the app itself is served — never the source files or .git.
        if parsed.path in ('/', '/index.html'):
            with open(INDEX_FILE, 'rb') as f:
                body = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404)


def main():
    global EGRESS_PROXY
    EGRESS_PROXY = start_egress_proxy()
    detect_render_support()
    port = PORT
    for _ in range(3):
        try:
            httpd = http.server.ThreadingHTTPServer((BIND, port), ProxyHandler)
        except OSError as e:
            if e.errno == errno.EADDRINUSE and not HOSTED:
                print(f'[!] Port {port} busy, trying next...')
                port += 1
                continue
            raise
        with httpd:
            print(f'🚀 Text-Only Viewer running at: http://localhost:{port}')
            print(f'🔒 Private network access: {"allowed" if ALLOW_PRIVATE else "blocked"}')
            print(f'🤖 Chromium rendering: {"available" if render_status["available"] else render_status["reason"]}')
            print('💡 Press Ctrl+C to stop the server.')
            if not HOSTED:
                webbrowser.open(f'http://localhost:{port}')
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
        return
    raise SystemExit('Nu s-a găsit niciun port liber.')


if __name__ == '__main__':
    main()
