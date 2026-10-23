import errno
import gzip
import http.server
import ipaddress
import json
import os
import re
import socket
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


def check_url(url):
    """Allow only http(s) URLs whose host resolves to public IPs (unless ALLOW_PRIVATE)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise BlockedURL('Sunt permise doar URL-uri http:// sau https://')
    if ALLOW_PRIVATE:
        return
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise BlockedURL(f'Nu s-a putut rezolva domeniul: {e}')
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        if not ip.is_global:
            raise BlockedURL(f'Adresa {ip} nu este publică — blocată.')


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
    opener = urllib.request.build_opener(redirects)
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
