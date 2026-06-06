#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if 'id' in params:
            if "'" in params['id'][0]:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"You have an error in your SQL syntax")
                return

        if 'name' in params:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            reflected = f"<html><body>Hello {params['name'][0]}</body></html>"
            self.wfile.write(reflected.encode())
            return

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"""
        <html>
        <body>
            <h1>Vulnerable Test</h1>
            <form action="/" method="get">
                <input name="id" type="text" placeholder="SQL injection">
                <input type="submit" value="Send">
            </form>
            <form action="/" method="post">
                <input name="name" type="text" placeholder="XSS">
                <input type="submit" value="Send">
            </form>
            <a href="/?id=1">Test ID</a>
            <a href="/?name=test">Test Name</a>
        </body>
        </html>
        """)

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 8000), VulnerableHandler)
    print("Test server running on http://127.0.0.1:8000")
    server.serve_forever()
