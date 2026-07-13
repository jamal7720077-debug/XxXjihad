#!/usr/bin/env bash
# ============================================================================
# FalconDNS  -  single-file server installer.
# One command:
#   apt update && apt install -y wget && \
#   wget -q -O install.sh <YOUR_RAW_GITHUB_URL>/install.sh && \
#   chmod +x install.sh && ./install.sh
# It installs deps, writes the server, sets up TUN + NAT, and starts a service.
# ============================================================================
set -e
echo "==> FalconDNS server installer"

read -rp "Tunnel domain (delegated to this VPS, e.g. t.example.com): " DOMAIN
PUBLIC_IP=$(curl -s https://api.ipify.org || echo "0.0.0.0")
read -rp "Public IP [$PUBLIC_IP]: " IN; PUBLIC_IP=${IN:-$PUBLIC_IP}
read -rp "Pre-shared key (64 hex chars, blank = generate): " PSK
[ -z "$PSK" ] && PSK=$(head -c32 /dev/urandom | xxd -p -c99) && echo "    generated PSK: $PSK"
read -rp "First username (UUID). Blank = generate: " USERNAME
[ -z "$USERNAME" ] && USERNAME=$(cat /proc/sys/kernel/random/uuid) && echo "    username: $USERNAME"
read -rp "Token for that user [mytoken]: " TOKEN; TOKEN=${TOKEN:-mytoken}

apt-get update -y
apt-get install -y python3 python3-pip iptables iproute2 curl xxd openssl
pip3 install --break-system-packages cryptography 2>/dev/null || pip3 install cryptography

install -d /etc/falcon /opt/falcon
[ -f /etc/falcon/cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /etc/falcon/key.pem -out /etc/falcon/cert.pem -days 825 \
  -subj "/CN=${DOMAIN}" >/dev/null 2>&1

cat > /etc/falcon/falcon.env <<EOF
FALCON_DOMAIN=${DOMAIN}
FALCON_IP=${PUBLIC_IP}
FALCON_PSK=${PSK}
FALCON_USER=${USERNAME}
FALCON_TOKEN=${TOKEN}
EOF

# ---------------------------- write the server ------------------------------
cat > /opt/falcon/server.py <<'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64, hashlib, hmac, json, os, socket, struct, threading, time, secrets, fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG = {
    "DOMAIN":     os.environ.get("FALCON_DOMAIN", "t.example.com"),
    "PSK_HEX":    os.environ.get("FALCON_PSK", ""),
    "DNS_PORT":   53, "DOH_PORT": 443, "CTRL_PORT": 8443, "MTU": 1280,
    "VIP_SUBNET": "10.8.0", "HS_SKEW": 120, "TUN_NAME": "falcon0",
    "USERS": {os.environ.get("FALCON_USER",""): os.environ.get("FALCON_TOKEN","")},
}
B32 = "abcdefghijklmnopqrstuvwxyz234567"

def b32decode(s):
    idx = {c:i for i,c in enumerate(B32)}; bits=val=0; out=bytearray()
    for c in s.lower():
        if c not in idx: continue
        val=(val<<5)|idx[c]; bits+=5
        if bits>=8: bits-=8; out.append((val>>bits)&0xFF)
    return bytes(out)

def b32encode(b):
    bits=val=0; o=[]
    for x in b:
        val=(val<<8)|x; bits+=8
        while bits>=5: bits-=5; o.append(B32[(val>>bits)&31])
    if bits>0: o.append(B32[(val<<(5-bits))&31])
    return "".join(o)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def _nonce(c): return b"\x00\x00\x00\x00"+struct.pack(">Q", c)
def enc(key,pt,c): return struct.pack(">Q",c)+AESGCM(key).encrypt(_nonce(c),pt,None)
def dec(key,w):    return AESGCM(key).decrypt(_nonce(struct.unpack(">Q",w[:8])[0]), w[8:], None)

class Sessions:
    def __init__(s): s.sid={}; s.tag={}; s.vip={}; s.l=threading.Lock(); s.n=2
    def create(s,u):
        with s.l:
            vip=f"{CONFIG['VIP_SUBNET']}.{s.n}"; s.n = 2 if s.n>=254 else s.n+1
            sid=secrets.token_hex(16); key=secrets.token_bytes(32)
            o={"sid":sid,"vip":vip,"key":key,"user":u,"down":[],
               "ctr":(1<<63),"frags":{},"last":time.time()}
            s.sid[sid]=o; s.tag[sid[:8]]=o; s.vip[vip]=o; return o
    def by_tag(s,t):
        with s.l: return s.tag.get(t)
    def drop(s,sid):
        with s.l:
            o=s.sid.pop(sid,None)
            if o: s.tag.pop(o["sid"][:8],None); s.vip.pop(o["vip"],None)
S=Sessions()

def str_uuid(b):
    h=b.hex(); return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def parse_qname(d,off):
    lb=[]
    while True:
        n=d[off]; off+=1
        if n==0: break
        if n&0xC0==0xC0: off+=1; break
        lb.append(d[off:off+n].decode("latin1")); off+=n
    return lb, off

def txt_response(q, payload):
    txid=q[:2]; _,qend=parse_qname(q,12); question=q[12:qend+4]
    hdr=txid+b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    chunks=[payload[i:i+255] for i in range(0,len(payload),255)] or [b""]
    rd=b"".join(bytes([len(c)])+c for c in chunks)
    ans=b"\xc0\x0c"+struct.pack(">HHIH",16,1,0,len(rd))+rd
    return hdr+question+ans

def drain(o):
    out=bytearray()
    with S.l:
        while o["down"] and len(out)<8000:
            pkt=o["down"].pop(0); w=enc(o["key"],pkt,o["ctr"]); o["ctr"]+=1
            out+=struct.pack(">H",len(w))+w
    return bytes(out)

def handle(q):
    try: labels,_=parse_qname(q,12)
    except Exception: return b""
    dom=CONFIG["DOMAIN"].split(".")
    if labels[-len(dom):]!=dom: return txt_response(q,b"")
    body=labels[:-len(dom)]
    if not body: return txt_response(q,b"")
    if body[0]=="hs":
        return txt_response(q, do_handshake(b32decode("".join(body[1:]))))
    if body[0]=="p":                              # data fragment
        try:
            tag=body[-1][1:]; cnt=int(body[-2][1:]); idx=int(body[-3][1:]); seq=body[-4][1:]
            b32part="".join(body[1:-4]); o=S.by_tag(tag)
            if not o: return txt_response(q,b"")
            o["last"]=time.time()
            with S.l:
                fr=o["frags"].setdefault(seq,{"cnt":cnt,"parts":{}})
                fr["parts"][idx]=b32part
                complete = len(fr["parts"])==fr["cnt"]
                if complete:
                    full="".join(fr["parts"][i] for i in range(fr["cnt"]))
                    del o["frags"][seq]
                else: full=None
            if full is not None:
                try: TUN.write(dec(o["key"], b32decode(full)))
                except Exception: pass
            return txt_response(q, drain(o))
        except Exception: return txt_response(q,b"")
    if body[0].startswith("t") and len(body)==1:  # poll
        o=S.by_tag(body[0][1:])
        return txt_response(q, drain(o) if o else b"")
    return txt_response(q,b"")

def do_handshake(p):
    try:
        u=str_uuid(p[:16]); tl=p[16]; tok=p[17:17+tl].decode("latin1")
        i=17+tl; ts=struct.unpack(">I",p[i:i+4])[0]; their=p[i+4:i+4+32]
        if abs(time.time()-ts)>CONFIG["HS_SKEW"]:
            return json.dumps({"error":"expired","detail":"timestamp skew"}).encode()
        if CONFIG["USERS"].get(u)!=tok:
            return json.dumps({"error":"auth","detail":"unknown user/token"}).encode()
        psk=bytes.fromhex(CONFIG["PSK_HEX"])
        mac=hmac.new(psk,f"{u}:{tok}:{ts}".encode(),hashlib.sha256).digest()
        if not hmac.compare_digest(mac,their):
            return json.dumps({"error":"auth","detail":"bad hmac"}).encode()
        o=S.create(u)
        return json.dumps({"sid":o["sid"],"virtual_ip":o["vip"],
                           "session_key":o["key"].hex(),"mtu":CONFIG["MTU"]}).encode()
    except Exception as e:
        return json.dumps({"error":"server","detail":str(e)}).encode()

class Tun:
    def __init__(s):
        s.fd=os.open("/dev/net/tun",os.O_RDWR)
        ifr=struct.pack("16sH",CONFIG["TUN_NAME"].encode(),0x1001)  # IFF_TUN|IFF_NO_PI
        fcntl.ioctl(s.fd,0x400454ca,ifr)
    def write(s,p): os.write(s.fd,p)
    def loop(s):
        while True:
            p=os.read(s.fd,65535)
            if len(p)<20: continue
            dst=".".join(str(x) for x in p[16:20]); o=S.vip.get(dst)
            if o:
                with S.l:
                    if len(o["down"])<1024: o["down"].append(p)
TUN=None

def udp_loop():
    k=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    k.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); k.bind(("0.0.0.0",CONFIG["DNS_PORT"]))
    while True:
        d,a=k.recvfrom(4096)
        try: k.sendto(handle(d),a)
        except Exception: pass

def tcp_loop():
    srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srv.bind(("0.0.0.0",CONFIG["DNS_PORT"])); srv.listen(64)
    while True:
        c,_=srv.accept(); threading.Thread(target=_tcp,args=(c,),daemon=True).start()
def _tcp(c):
    try:
        n=struct.unpack(">H",c.recv(2))[0]; q=b""
        while len(q)<n: q+=c.recv(n-len(q))
        r=handle(q); c.sendall(struct.pack(">H",len(r))+r)
    except Exception: pass
    finally: c.close()

class Doh(BaseHTTPRequestHandler):
    def log_message(s,*a): pass
    def _r(s,dq):
        r=handle(dq); s.send_response(200)
        s.send_header("Content-Type","application/dns-message")
        s.send_header("Content-Length",str(len(r))); s.end_headers(); s.wfile.write(r)
    def do_POST(s):
        if not s.path.startswith("/dns-query"): s.send_response(404); s.end_headers(); return
        n=int(s.headers.get("Content-Length",0)); s._r(s.rfile.read(n))
    def do_GET(s):
        if "/dns-query" not in s.path or "dns=" not in s.path:
            s.send_response(404); s.end_headers(); return
        import urllib.parse
        q=urllib.parse.parse_qs(s.path.split("?",1)[1])["dns"][0]
        s._r(base64.urlsafe_b64decode(q+"="*(-len(q)%4)))

class Ctrl(BaseHTTPRequestHandler):
    def log_message(s,*a): pass
    def do_POST(s):
        n=int(s.headers.get("Content-Length",0))
        try: b=json.loads(s.rfile.read(n) or b"{}")
        except Exception: b={}
        if s.path.endswith("/session/heartbeat"):
            o=S.sid.get(b.get("session_id"));  o and o.update(last=time.time())
        elif s.path.endswith("/session/disconnect"):
            S.drop(b.get("session_id"))
        s.send_response(200); s.send_header("Content-Length","2"); s.end_headers(); s.wfile.write(b"ok")

def start_doh():
    srv=ThreadingHTTPServer(("0.0.0.0",CONFIG["DOH_PORT"]),Doh)
    c,k="/etc/falcon/cert.pem","/etc/falcon/key.pem"
    if os.path.exists(c) and os.path.exists(k):
        import ssl; ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(c,k)
        srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
    srv.serve_forever()
def start_ctrl(): ThreadingHTTPServer(("0.0.0.0",CONFIG["CTRL_PORT"]),Ctrl).serve_forever()

def main():
    global TUN
    if not CONFIG["PSK_HEX"]: raise SystemExit("Set FALCON_PSK.")
    TUN=Tun(); threading.Thread(target=TUN.loop,daemon=True).start()
    for f in (udp_loop,tcp_loop,start_doh,start_ctrl):
        threading.Thread(target=f,daemon=True).start()
    print(f"[FalconDNS] up domain={CONFIG['DOMAIN']} vip={CONFIG['VIP_SUBNET']}.0/24")
    while True: time.sleep(3600)

if __name__=="__main__": main()
PYEOF

# ------------------------------ TUN + NAT -----------------------------------
WAN_IF=$(ip route | awk '/default/{print $5; exit}')
sysctl -w net.ipv4.ip_forward=1
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE

cat > /etc/systemd/system/falcon.service <<'EOF'
[Unit]
Description=FalconDNS tunnel server
After=network-online.target
[Service]
EnvironmentFile=/etc/falcon/falcon.env
ExecStartPre=/bin/sh -c 'ip tuntap add dev falcon0 mode tun 2>/dev/null; ip addr add 10.8.0.1/24 dev falcon0 2>/dev/null; ip link set falcon0 up'
ExecStart=/usr/bin/python3 /opt/falcon/server.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now falcon.service

echo
echo "==> Done. Enter these in the app's manual config screen:"
echo "    Domain         : ${DOMAIN}"
echo "    Server IP      : ${PUBLIC_IP}"
echo "    DNS Resolver   : ${PUBLIC_IP}:443   (DoH)"
echo "    Username (UUID): ${USERNAME}"
echo "    Token          : ${TOKEN}"
echo "    Pre-Shared Key : ${PSK}"
echo
echo "    logs: journalctl -u falcon -f"
