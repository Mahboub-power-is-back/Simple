#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP=/opt/vps-panel
DB="$APP/users.db"
CFG=/usr/local/etc/xray/config.json
XRAY=/usr/local/bin/xray
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
REALITY_TARGET="${REALITY_TARGET:-www.cloudflare.com:443}"
REALITY_SNI="${REALITY_SNI:-www.cloudflare.com}"
API=10085
SSHWS=8880
SQUID=3128
DROPBEAR=2222

log(){ echo "[+] $*"; }
warn(){ echo "[!] $*" >&2; }
die(){ echo "[x] $*" >&2; exit 1; }
needroot(){ [[ $EUID == 0 ]] || die "Run as root."; }
valid_name(){ [[ "$1" =~ ^[a-zA-Z0-9._-]{2,32}$ ]]; }

install_packages(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y curl ca-certificates jq nginx libnginx-mod-stream squid dropbear openssh-server apache2-utils certbot openssl python3 cron iproute2
}

install_xray(){
  [[ -x "$XRAY" ]] || bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  [[ -x "$XRAY" ]] || die "Xray install failed."
}

backup(){
  mkdir -p "$APP/backups"
  local t; t=$(date +%Y%m%d-%H%M%S)
  [[ -f "$CFG" ]] && cp -a "$CFG" "$APP/backups/xray-$t.json"
}

setup_domain(){
  [[ -n "$DOMAIN" ]] || read -rp "Domain (DNS A record must point here): " DOMAIN
  [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "Bad domain."
  [[ -n "$EMAIL" ]] || read -rp "Let's Encrypt email: " EMAIL
  systemctl stop nginx 2>/dev/null || true
  certbot certonly --standalone --non-interactive --agree-tos -m "$EMAIL" -d "$DOMAIN" || die "Certificate failed."
}

reality_keys(){
  local o; o=$("$XRAY" x25519)
  REALITY_PRIV=$(awk -F': ' '/PrivateKey:/{print $2;exit}' <<<"$o")
  REALITY_PUB=$(awk -F': ' '/Password:|PublicKey:/{print $2;exit}' <<<"$o")
  REALITY_SID=$(openssl rand -hex 8)
  [[ -n "$REALITY_PRIV" && -n "$REALITY_PUB" ]] || die "REALITY key generation failed."
}

write_xray(){
  mkdir -p "$(dirname "$CFG")" "$APP"
  cat > "$CFG" <<EOF
{
  "log": {"loglevel":"warning"},
  "api": {"tag":"api","listen":"127.0.0.1:$API","services":["HandlerService","StatsService"]},
  "stats": {},
  "policy": {"levels":{"0":{"handshake":4,"connIdle":300,"uplinkOnly":2,"downlinkOnly":5,"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}},"system":{}},
  "inbounds": [
    {
      "listen":"127.0.0.1","port":8443,"protocol":"vless","tag":"reality",
      "settings":{"clients":[],"decryption":"none"},
      "streamSettings":{
        "network":"raw","security":"reality",
        "realitySettings":{"show":false,"target":"$REALITY_TARGET","xver":0,"serverNames":["$REALITY_SNI"],"privateKey":"$REALITY_PRIV","shortIds":["$REALITY_SID"]}
      }
    },
    {"listen":"127.0.0.1","port":10001,"protocol":"vmess","tag":"vmess-ws-tls","settings":{"clients":[]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vmess-ws"}}},
    {"listen":"127.0.0.1","port":10002,"protocol":"vless","tag":"vless-ws-tls","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vless-ws"}}},
    {"listen":"127.0.0.1","port":10003,"protocol":"trojan","tag":"trojan-ws-tls","settings":{"clients":[]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/trojan-ws"}}},
    {"listen":"127.0.0.1","port":10004,"protocol":"vmess","tag":"vmess-ws-ntls","settings":{"clients":[]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vmess-ntls"}}},
    {"listen":"127.0.0.1","port":10005,"protocol":"vless","tag":"vless-ws-ntls","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vless-ntls"}}},
    {"listen":"127.0.0.1","port":10006,"protocol":"trojan","tag":"trojan-ws-ntls","settings":{"clients":[]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/trojan-ntls"}}},
    {"listen":"127.0.0.1","port":10007,"protocol":"vless","tag":"vless-httpupgrade","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"httpupgrade","security":"none","httpupgradeSettings":{"path":"/vless-hu"}}},
    {"listen":"127.0.0.1","port":10008,"protocol":"vless","tag":"vless-xhttp","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"path":"/xhttp"}}}
  ],
  "outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}]
}
EOF
  "$XRAY" run -test -config "$CFG" || die "Xray config test failed."
}

write_nginx(){
  mkdir -p /etc/nginx/stream.d /var/www/html
  cat > /etc/nginx/conf.d/vps-http.conf <<EOF
server {
  listen 80;
  server_name $DOMAIN _;
  location /vmess-ws { proxy_pass http://127.0.0.1:10004; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; }
  location /vless-ntls { proxy_pass http://127.0.0.1:10005; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; }
  location /trojan-ntls { proxy_pass http://127.0.0.1:10006; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; }
  location /ssh { proxy_pass http://127.0.0.1:$SSHWS; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; }
  location / { return 200 "VPS panel online\n"; add_header Content-Type text/plain; }
}
server {
  listen 127.0.0.1:8444 ssl;
  server_name $DOMAIN _;
  ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  location /vmess-ws { proxy_pass http://127.0.0.1:10001; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; }
  location /vless-ws { proxy_pass http://127.0.0.1:10002; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; }
  location /trojan-ws { proxy_pass http://127.0.0.1:10003; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; }
  location /vless-hu { proxy_pass http://127.0.0.1:10007; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; }
  location /xhttp { proxy_pass http://127.0.0.1:10008; proxy_http_version 1.1; proxy_set_header Host \$host; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_buffering off; }
  location / { return 200 "VPS TLS endpoint\n"; add_header Content-Type text/plain; }
}
EOF
  # Ensure main nginx config has a stream block; do not place stream directives in http context.
  if ! grep -qE '^[[:space:]]*include[[:space:]]+/etc/nginx/stream\.d/\*\.conf;' /etc/nginx/nginx.conf; then
    cat >> /etc/nginx/nginx.conf <<'EOF'

stream {
  map $ssl_preread_server_name $vps_backend {
    default 127.0.0.1:8444;
    www.cloudflare.com 127.0.0.1:8443;
  }
  server {
    listen 443;
    proxy_pass $vps_backend;
    ssl_preread on;
  }
}
EOF
  fi
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
}

write_ssh_ws(){
  cat > /usr/local/bin/vps-ssh-ws <<'PY'
#!/usr/bin/env python3
import asyncio,base64,hashlib,os,socket,struct,sys
PORT=int(sys.argv[1])
MAGIC=b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
async def handle(r,w):
    s=None
    try:
        h=await r.readuntil(b"\r\n\r\n"); key=None
        for x in h.decode("latin1").split("\r\n"):
            if x.lower().startswith("sec-websocket-key:"): key=x.split(":",1)[1].strip()
        if not key: return
        a=base64.b64encode(hashlib.sha1(key.encode()+MAGIC).digest()).decode()
        w.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+a+"\r\n\r\n").encode()); await w.drain()
        loop=asyncio.get_running_loop(); s=socket.create_connection(("127.0.0.1",22)); s.setblocking(False)
        async def up():
            while 1:
                h=await r.readexactly(2); op=h[0]&15; m=h[1]&128; n=h[1]&127
                if n==126:n=int.from_bytes(await r.readexactly(2),"big")
                elif n==127:n=int.from_bytes(await r.readexactly(8),"big")
                mk=await r.readexactly(4) if m else b""; d=bytearray(await r.readexactly(n))
                if m:
                    for i in range(n):d[i]^=mk[i%4]
                if op==8:return
                if op==9:w.write(b"\x8a"+bytes([len(d)])+d);await w.drain()
                elif op==2 or op==1:await loop.sock_sendall(s,d)
        async def down():
            while 1:
                d=await loop.sock_recv(s,65535)
                if not d:return
                n=len(d); head=b"\x82"+(bytes([n]) if n<126 else b"\x82")
                if n<126:w.write(b"\x82"+bytes([n])+d)
                elif n<65536:w.write(b"\x82\x7e"+struct.pack("!H",n)+d)
                else:w.write(b"\x82\x7f"+struct.pack("!Q",n)+d)
                await w.drain()
        await asyncio.gather(up(),down())
    except: pass
    finally:
        try:
            if s:s.close()
            w.close()
        except: pass
async def main():
    srv=await asyncio.start_server(handle,"127.0.0.1",PORT)
    async with srv:await srv.serve_forever()
asyncio.run(main())
PY
  chmod 755 /usr/local/bin/vps-ssh-ws
  cat >/etc/systemd/system/vps-ssh-ws.service <<EOF
[Unit]
After=network.target ssh.service
[Service]
ExecStart=/usr/local/bin/vps-ssh-ws $SSHWS
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now vps-ssh-ws
}

write_squid(){
  cp -a /etc/squid/squid.conf /etc/squid/squid.conf.bak 2>/dev/null || true
  cat >/etc/squid/squid.conf <<EOF
http_port $SQUID
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm VPS-Proxy
acl auth proxy_auth REQUIRED
http_access allow auth
http_access deny all
cache deny all
EOF
  touch /etc/squid/passwd; chmod 640 /etc/squid/passwd
  systemctl enable --now squid
  systemctl restart squid
}

init(){
  needroot
  [[ -f /etc/os-release ]] || die "Debian/Ubuntu required."
  backup
  install_packages
  install_xray
  setup_domain
  reality_keys
  write_xray
  write_ssh_ws
  write_squid
  write_nginx
  : > "$DB"; chmod 600 "$DB"
  systemctl enable --now xray dropbear ssh
  systemctl restart xray
  cat >/usr/local/bin/vps-quota <<'PY'
#!/usr/bin/env python3
import json, subprocess, time, os
DB="/opt/vps-panel/users.db"
XRAY="/usr/local/bin/xray"
CFG="/usr/local/etc/xray/config.json"
API="127.0.0.1:10085"
def stats():
    p=subprocess.run([XRAY,"api","statsquery","--server="+API],capture_output=True,text=True)
    if p.returncode!=0: return {}
    try: data=json.loads(p.stdout)
    except: return {}
    out={}
    for x in data.get("stat",[]):
        n=x.get("name","")
        if n.startswith("user>>>") and n.endswith(">>>traffic>>>uplink"):
            e=n.split(">>>")[1]; out.setdefault(e,[0,0])[0]=int(x.get("value","0"))
        if n.startswith("user>>>") and n.endswith(">>>traffic>>>downlink"):
            e=n.split(">>>")[1]; out.setdefault(e,[0,0])[1]=int(x.get("value","0"))
    return out
while True:
    st=stats()
    if os.path.exists(DB):
        rows=[]
        changed=False
        for line in open(DB):
            f=line.rstrip("\n").split("|")
            if len(f)<7: continue
            name,uuid,tpw,expiry,quota,speed,used=f[:7]
            try:
                q=int(quota)
            except: q=0
            total=sum(st.get(name,[0,0]))
            used_gb=total/1000000000
            if q and used_gb >= q:
                subprocess.run(["sed","-i","-E",f"/^{name.replace('.','\\.')}\\|/d",DB])
                subprocess.run(["userdel","-r",name],stderr=subprocess.DEVNULL)
                subprocess.run(["htpasswd","-D","/etc/squid/passwd",name],stderr=subprocess.DEVNULL)
                # Remove Xray user by email and reload.
                p=subprocess.run(["jq","--arg","e",name,'(.inbounds[]|select(.settings.clients!=null)|.settings.clients) |= map(select(.email != $e))',CFG],capture_output=True,text=True)
                if p.returncode==0:
                    open(CFG+".tmp","w").write(p.stdout); os.replace(CFG+".tmp",CFG)
                    subprocess.run([XRAY,"run","-test","-config",CFG],stdout=subprocess.DEVNULL)
                    subprocess.run(["systemctl","restart","xray"])
                changed=True
                continue
            f[6]=str(int(used_gb))
            rows.append("|".join(f))
        if changed:
            open(DB,"w").write("\n".join(rows)+"\n")
    time.sleep(60)
PY
  chmod 755 /usr/local/bin/vps-quota
  cat >/etc/systemd/system/vps-quota.service <<EOF
[Unit]
After=xray.service
[Service]
ExecStart=/usr/local/bin/vps-quota
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now vps-quota.service
  log "Installed."
  echo "Domain: $DOMAIN"
  echo "REALITY target: $REALITY_TARGET"
  echo "REALITY SNI: $REALITY_SNI"
  echo "REALITY public key: $REALITY_PUB"
  echo "REALITY shortId: $REALITY_SID"
  echo "Public: 80 and 443 only; backends are localhost."
}

create_user(){
  local name days quota speed pass uuid tpass expiry
  read -rp "Username: " name
  valid_name "$name" || { warn "Invalid username."; return; }
  cut -d'|' -f1 "$DB" | grep -Fxq "$name" && { warn "Already exists."; return; }
  read -rp "Validity days: " days; [[ "$days" =~ ^[0-9]+$ && $days -gt 0 ]] || return
  read -rp "Quota GB (0=unlimited): " quota; [[ "$quota" =~ ^[0-9]+$ ]] || return
  read -rp "Speed Mbps (0=unlimited): " speed; [[ "$speed" =~ ^[0-9]+$ ]] || return
  pass=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)
  tpass=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)
  uuid=$("$XRAY" uuid); expiry=$(date -d "+$days days" +%F)
  useradd -m -s /bin/bash -e "$expiry" "$name"
  echo "$name:$pass" | chpasswd
  htpasswd -b /etc/squid/passwd "$name" "$pass" >/dev/null
  jq --arg u "$uuid" --arg e "$name" --arg p "$tpass" '
    (.inbounds[]|select(.protocol=="vmess")|.settings.clients)+=[{"id":$u,"email":$e,"level":0}] |
    (.inbounds[]|select(.protocol=="vless")|.settings.clients)+=[{"id":$u,"email":$e,"level":0}] |
    (.inbounds[]|select(.protocol=="trojan")|.settings.clients)+=[{"password":$p,"email":$e,"level":0}]
  ' "$CFG" > "$CFG.tmp" && mv "$CFG.tmp" "$CFG"
  "$XRAY" run -test -config "$CFG" && systemctl restart xray
  printf '%s|%s|%s|%s|%s|%s|0\n' "$name" "$uuid" "$tpass" "$expiry" "$quota" "$speed" >> "$DB"
  echo "USER: $name"
  echo "VLESS/VMess UUID: $uuid"
  echo "Trojan password: $tpass"
  echo "SSH/Squid password: $pass"
  echo "Expires: $expiry"
}

list_users(){
  printf "%-16s %-12s %-8s %-8s\n" USER EXPIRES QUOTA_GB SPEED_MB
  awk -F'|' '{printf "%-16s %-12s %-8s %-8s\n",$1,$4,$5,$6}' "$DB"
}

remove_user(){
  local n; read -rp "Username: " n
  cut -d'|' -f1 "$DB"|grep -Fxq "$n" || { warn "Not found."; return; }
  userdel -r "$n" 2>/dev/null || true
  sed -i -E "/^${n//./\\.}\|/d" "$DB"
  sed -i -E "/^${n//./\\.}:/d" /etc/squid/passwd
  # Remove matching Xray users by email.
  jq --arg e "$n" '(.inbounds[]|select(.settings.clients!=null)|.settings.clients) |= map(select(.email != $e))' "$CFG" > "$CFG.tmp" && mv "$CFG.tmp" "$CFG"
  "$XRAY" run -test -config "$CFG" && systemctl restart xray
  log "Removed $n"
}

status(){
  systemctl --no-pager --full status xray nginx vps-ssh-ws dropbear squid | sed -n '1,150p'
}

menu(){
  while :; do
    echo
    echo "=== VPS PANEL ==="
    echo "1) Create user"
    echo "2) Remove user"
    echo "3) List users"
    echo "4) Service status"
    echo "5) Test Xray config"
    echo "6) Restart services"
    echo "0) Exit"
    read -rp "Choice: " c
    case "$c" in
      1) create_user;;
      2) remove_user;;
      3) list_users;;
      4) status;;
      5) "$XRAY" run -test -config "$CFG";;
      6) systemctl restart xray nginx vps-ssh-ws dropbear squid;;
      0) exit;;
      *) warn "Invalid";;
    esac
  done
}

if [[ "${1:-}" == "--install" ]]; then init; else needroot; [[ -f "$DB" ]] || die "Run $0 --install first."; menu; fi
