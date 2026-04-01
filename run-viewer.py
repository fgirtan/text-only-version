import http.server
import socketserver
import urllib.request
import urllib.parse
import webbrowser
import os
import sys
import gzip
import zlib
import io

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == '/proxy':
            query = urllib.parse.parse_qs(parsed_url.query)
            target_url = query.get('url', [None])[0]
            
            if not target_url:
                self.send_error(400, "Missing 'url' parameter")
                return

            try:
                print(f"[*] Fetching: {target_url}")
                req = urllib.request.Request(
                    target_url, 
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept-Encoding': 'gzip, deflate'
                    }
                )
                
                with urllib.request.urlopen(req, timeout=15) as response:
                    content = response.read()
                    encoding = response.info().get('Content-Encoding', '').lower()
                    
                    if 'gzip' in encoding:
                        try:
                            content = gzip.GzipFile(fileobj=io.BytesIO(content)).read()
                        except Exception as e:
                            print(f"[!] Gzip decompression error: {e}")
                    elif 'deflate' in encoding:
                        try:
                            content = zlib.decompress(content)
                        except zlib.error:
                            # Try raw deflate
                            content = zlib.decompress(content, -zlib.MAX_WBITS)
                        except Exception as e:
                            print(f"[!] Deflate decompression error: {e}")
                        
                    self.send_response(200)
                    self.send_header('Content-Type', response.info().get_content_type() or 'text/html')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(content)
            except Exception as e:
                print(f"[!] Error fetching {target_url}: {e}")
                self.send_error(500, f"Error fetching URL: {str(e)}")
            return
        
        return super().do_GET()

def main():
    os.chdir(DIRECTORY)
    
    # Simple retry logic for port
    port = PORT
    for _ in range(3):
        try:
            with socketserver.TCPServer(("", port), ProxyHandler) as httpd:
                print(f"🚀 Text-Only Viewer running at: http://localhost:{port}")
                print(f"📁 Serving files from: {DIRECTORY}")
                print(f"💡 Press Ctrl+C to stop the server.")
                webbrowser.open(f"http://localhost:{port}")
                httpd.serve_forever()
                break
        except OSError as e:
            if e.errno == 48:
                print(f"[!] Port {port} busy, trying next...")
                port += 1
            else:
                raise e

if __name__ == "__main__":
    main()
