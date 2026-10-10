from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

class NoCache(SimpleHTTPRequestHandler):
    def send_head(self):
        # always send the full file, never answer 304
        for h in ("If-Modified-Since", "If-None-Match"):
            if h in self.headers:
                del self.headers[h]
        return super().send_head()

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

print("Serving on http://localhost:8000 (no cache, no 304)")
ThreadingHTTPServer(("", 8000), NoCache).serve_forever()