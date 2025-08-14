#!/bin/bash
# VPN Server Auto Installer - Complete Script
# Compatible with Ubuntu 20.04/22.04 & Debian 10/11
# All-in-One Installation Script

clear
echo "=========================================="
echo "    VPN SERVER AUTO INSTALLER v2025     "
echo "=========================================="
echo ""

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fungsi untuk log
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Cek root user
if [[ $EUID -ne 0 ]]; then
   error "Script ini harus dijalankan sebagai root!"
   exit 1
fi

# Cek OS
if [[ -e /etc/debian_version ]]; then
    OS="debian"
    source /etc/os-release
    VER=$VERSION_ID
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
    OS="centos"
    VER=$(rpm -q --qf "%{VERSION}" $(rpm -q --whatprovides redhat-release))
else
    error "OS tidak didukung!"
    exit 1
fi

# Update sistem
log "Updating system packages..."
apt update && apt upgrade -y
apt install -y wget curl nano unzip zip tar openssl jq bc htop iftop nethogs speedtest-cli

# Install dependencies
log "Installing dependencies..."
apt install -y software-properties-common apt-transport-https ca-certificates gnupg lsb-release

# Variabel global
DOMAIN=""
EMAIL=""
MYIP=$(curl -s ipv4.icanhazip.com)

# Input domain
echo ""
echo -e "${CYAN}Masukkan domain Anda:${NC}"
read -p "Domain: " DOMAIN
echo ""
echo -e "${CYAN}Masukkan email untuk SSL:${NC}"
read -p "Email: " EMAIL

# Validasi domain
if [[ -z "$DOMAIN" ]]; then
    error "Domain tidak boleh kosong!"
    exit 1
fi

# Simpan konfigurasi
mkdir -p /etc/vpnserver
cat > /etc/vpnserver/config.conf << EOF
DOMAIN=$DOMAIN
EMAIL=$EMAIL
MYIP=$MYIP
INSTALL_DATE=$(date)
EOF

# Install semua komponen
log "Starting installation process..."

# 1. Install Nginx
install_nginx() {
    log "Installing Nginx..."
    apt install -y nginx
    systemctl enable nginx
    systemctl start nginx
    
    # Konfigurasi Nginx untuk WebSocket
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Gzip Settings
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Site default
    cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    
    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
    
    # WebSocket untuk VMess
    location /vmess {
        proxy_pass http://127.0.0.1:23456;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_redirect off;
    }
    
    # WebSocket untuk VLess
    location /vless {
        proxy_pass http://127.0.0.1:14016;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_redirect off;
    }
    
    # WebSocket untuk Trojan
    location /trojan {
        proxy_pass http://127.0.0.1:25432;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_redirect off;
    }
    
    # WebSocket untuk Shadowsocks
    location /ss {
        proxy_pass http://127.0.0.1:30300;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_redirect off;
    }
}
EOF

    systemctl reload nginx
}

# 2. Install SSL Certificate
install_ssl() {
    log "Installing SSL Certificate..."
    apt install -y certbot python3-certbot-nginx
    
    # Stop nginx sementara
    systemctl stop nginx
    
    # Generate certificate
    certbot certonly --standalone --agree-tos --no-eff-email --email $EMAIL -d $DOMAIN
    
    # Auto renewal
    echo "0 3 * * * root certbot renew --quiet" >> /etc/crontab
    
    systemctl start nginx
}

# 3. Install Xray
install_xray() {
    log "Installing Xray-core..."
    
    # Download dan install Xray
    wget -O /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
    unzip -o /tmp/xray.zip -d /usr/local/bin/
    chmod +x /usr/local/bin/xray
    
    # Buat direktori konfigurasi
    mkdir -p /etc/xray
    mkdir -p /var/log/xray
    
    # Generate UUID
    UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # Konfigurasi Xray
    cat > /etc/xray/config.json << EOF
{
    "log": {
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log",
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": 23456,
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vmess"
                }
            }
        },
        {
            "port": 14016,
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vless"
                }
            }
        },
        {
            "port": 25432,
            "protocol": "trojan",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/trojan"
                }
            }
        },
        {
            "port": 1080,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": true
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF

    # Systemd service untuk Xray
    cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable xray
    systemctl start xray
}

# 4. Install OpenSSH
install_ssh() {
    log "Configuring SSH..."
    
    # Backup konfigurasi SSH
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Konfigurasi SSH
    cat > /etc/ssh/sshd_config << 'EOF'
Port 22
Port 2222
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 120
ClientAliveCountMax 3
EOF

    systemctl restart ssh
}

# 5. Install Dropbear
install_dropbear() {
    log "Installing Dropbear..."
    apt install -y dropbear
    
    # Konfigurasi Dropbear
    cat > /etc/default/dropbear << 'EOF'
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 109 -p 69"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
EOF

    systemctl restart dropbear
}

# 6. Install Stunnel (SSL Tunnel)
install_stunnel() {
    log "Installing Stunnel..."
    apt install -y stunnel4
    
    # Konfigurasi Stunnel
    cat > /etc/stunnel/stunnel.conf << EOF
cert = /etc/letsencrypt/live/$DOMAIN/fullchain.pem
key = /etc/letsencrypt/live/$DOMAIN/privkey.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:143

[openssh]
accept = 777
connect = 127.0.0.1:22

[openvpn]
accept = 992
connect = 127.0.0.1:1194
EOF

    # Enable stunnel
    sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
    systemctl restart stunnel4
}

# 7. Install OpenVPN
install_openvpn() {
    log "Installing OpenVPN..."
    apt install -y openvpn easy-rsa
    
    # Setup CA
    make-cadir /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa
    
    # Konfigurasi vars
    cat > vars << 'EOF'
export KEY_COUNTRY="ID"
export KEY_PROVINCE="JT"
export KEY_CITY="Jakarta"
export KEY_ORG="VPNServer"
export KEY_EMAIL="admin@vpnserver.com"
export KEY_OU="VPNServer"
export KEY_NAME="server"
EOF

    source vars
    ./clean-all
    ./build-ca --batch
    ./build-key-server --batch server
    ./build-dh
    openvpn --genkey --secret keys/ta.key
    
    # Copy certificates
    cp keys/ca.crt keys/server.crt keys/server.key keys/dh2048.pem keys/ta.key /etc/openvpn/
    
    # Server config
    cat > /etc/openvpn/server.conf << 'EOF'
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
tls-auth ta.key 0
cipher AES-256-CBC
auth SHA256
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
mute 20
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
username-as-common-name
EOF

    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Iptables rules
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    iptables -A INPUT -p udp --dport 1194 -j ACCEPT
    iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # Save iptables
    iptables-save > /etc/iptables.rules
    
    systemctl enable openvpn@server
    systemctl start openvpn@server
}

# 8. Install Shadowsocks
install_shadowsocks() {
    log "Installing Shadowsocks..."
    apt install -y shadowsocks-libev simple-obfs
    
    # Konfigurasi Shadowsocks
    cat > /etc/shadowsocks-libev/config.json << 'EOF'
{
    "server":"0.0.0.0",
    "server_port":8388,
    "local_port":1080,
    "password":"defaultpass123",
    "timeout":60,
    "method":"aes-256-gcm",
    "fast_open":true,
    "workers":1,
    "prefer_ipv6":false,
    "no_delay":true,
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls"
}
EOF

    systemctl enable shadowsocks-libev
    systemctl start shadowsocks-libev
}

# 9. Install HAProxy
install_haproxy() {
    log "Installing HAProxy..."
    apt install -y haproxy
    
    cat > /etc/haproxy/haproxy.cfg << 'EOF'
global
    daemon
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option dontlognull

frontend multiport
    bind *:80
    bind *:8080
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if HTTP
    
    acl is_websocket hdr(Upgrade) -i websocket
    acl is_ssl req.ssl_hello_type 1
    
    use_backend ssl_backend if is_ssl
    use_backend http_backend if HTTP
    default_backend ssh_backend

backend ssl_backend
    mode tcp
    server nginx 127.0.0.1:443 check

backend http_backend
    mode tcp
    server nginx 127.0.0.1:8081 check

backend ssh_backend
    mode tcp
    server openssh 127.0.0.1:22 check
    server dropbear 127.0.0.1:143 check
EOF

    systemctl enable haproxy
    systemctl start haproxy
}

# 10. Install NoobzVPN
install_noobzvpn() {
    log "Installing NoobzVPN..."
    
    # Download NoobzVPN
    wget -O /usr/local/bin/noobzvpns https://github.com/noobz-id/noobzvpns/raw/master/noobzvpns.x86_64
    chmod +x /usr/local/bin/noobzvpns
    
    # Konfigurasi
    cat > /etc/noobzvpns.conf << 'EOF'
[server]
port = 8080
bind = 0.0.0.0

[users]
# Format: username:password
EOF

    # Systemd service
    cat > /etc/systemd/system/noobzvpns.service << 'EOF'
[Unit]
Description=NoobzVPN Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/noobzvpns -c /etc/noobzvpns.conf
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable noobzvpns
    systemctl start noobzvpns
}

# 11. Install Squid Proxy
install_squid() {
    log "Installing Squid Proxy..."
    apt install -y squid
    
    cat > /etc/squid/squid.conf << 'EOF'
http_port 3128
http_port 8080
http_access allow all
via off
forwarded_for off
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all
EOF

    systemctl enable squid
    systemctl start squid
}

# Jalankan semua instalasi
install_nginx
install_ssl
install_xray
install_ssh
install_dropbear
install_stunnel
install_openvpn
install_shadowsocks
install_haproxy
install_noobzvpn
install_squid

# Buat direktori untuk scripts
mkdir -p /usr/local/bin/vpnserver
mkdir -p /var/log/vpnserver

# Setup firewall
apt install -y ufw
ufw --force enable
ufw allow ssh
ufw allow 22,80,143,443,1194,3128,8080,8388,777,992,109,69,2222/tcp
ufw allow 1194/udp

log "Creating management scripts..."

# ==================== MENU UTAMA ====================
cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
clear

# Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Load konfigurasi
source /etc/vpnserver/config.conf

# Fungsi untuk mendapatkan info sistem
get_system_info() {
    OS=$(lsb_release -d | cut -f2)
    CORE=$(nproc)
    RAM_TOTAL=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    RAM_USED=$(free -m | awk 'NR==2{printf "%.0f", $3}')
    LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1 | sed 's/^[ \t]*//')
    UPTIME=$(uptime -p | sed 's/up //')
    DATE=$(date '+%d-%m-%Y')
    TIME=$(date '+%H-%M-%S')
}

# Fungsi untuk menghitung akun aktif
count_accounts() {
    SSH_COUNT=$(grep -c "^[^#].*:/bin/bash\|/bin/sh" /etc/passwd)
    VMESS_COUNT=$(jq '.inbounds[0].settings.clients | length' /etc/xray/config.json 2>/dev/null || echo "0")
    VLESS_COUNT=$(jq '.inbounds[1].settings.clients | length' /etc/xray/config.json 2>/dev/null || echo "0")
    TROJAN_COUNT=$(jq '.inbounds[2].settings.clients | length' /etc/xray/config.json 2>/dev/null || echo "0")
    SS_COUNT=$(grep -c "^[^#]" /etc/shadowsocks-libev/users.txt 2>/dev/null || echo "0")
}

# Fungsi untuk cek status service
check_services() {
    SSH_STATUS=$(systemctl is-active ssh >/dev/null 2>&1 && echo "ON" || echo "OFF")
    NOOBZ_STATUS=$(systemctl is-active noobzvpns >/dev/null 2>&1 && echo "ON" || echo "OFF")
    NGINX_STATUS=$(systemctl is-active nginx >/dev/null 2>&1 && echo "ON" || echo "OFF")
    HAPROXY_STATUS=$(systemctl is-active haproxy >/dev/null 2>&1 && echo "ON" || echo "OFF")
    XRAY_STATUS=$(systemctl is-active xray >/dev/null 2>&1 && echo "ON" || echo "OFF")
    DROPBEAR_STATUS=$(systemctl is-active dropbear >/dev/null 2>&1 && echo "ON" || echo "OFF")
}

# Ambil informasi sistem
get_system_info
count_accounts
check_services

# Tampilkan menu
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                    ${GREEN}VPN SERVER PANEL${NC}                     ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SYSTEM OS    = ${GREEN}$OS${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SYSTEM CORE  = ${GREEN}$CORE${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} SERVER RAM   = ${GREEN}$RAM_TOTAL / $RAM_USED MB${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} LOADCPU      = ${GREEN}$LOAD %${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} DATE         = ${GREEN}$DATE${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} TIME         = ${GREEN}$TIME${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} UPTIME       = ${GREEN}$UPTIME${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} IP VPS       = ${GREEN}$MYIP${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}●${NC} DOMAIN       = ${GREEN}$DOMAIN${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "                   ${PURPLE}>>> INFORMATION ACCOUNT <<<${NC}"
echo -e "          ${CYAN}═════════════════════════════════════════════${NC}"
echo -e "                ${YELLOW}SSH/OPENVPN/UDP  = ${GREEN}$SSH_COUNT${NC}"
echo -e "                ${YELLOW}VMESS/WS/GRPC    = ${GREEN}$VMESS_COUNT${NC}"
echo -e "                ${YELLOW}VLESS/WS/GRPC    = ${GREEN}$VLESS_COUNT${NC}"
echo -e "                ${YELLOW}TROJAN/WS/GRPC   = ${GREEN}$TROJAN_COUNT${NC}"
echo -e "                ${YELLOW}SHADOW/WS/GRPC   = ${GREEN}$SS_COUNT${NC}"
echo -e "          ${CYAN}═════════════════════════════════════════════${NC}"
echo -e "                  ${PURPLE}>>> VPN Server Panel <<<${NC}"
echo -e "  ${CYAN}╭═══════════════════╮╭═══════════════════╮╭══════════════════╮${NC}"
echo -e "  ${CYAN}│${NC} SSH     ${GREEN}$SSH_STATUS${NC}     NOOBZVPN   ${GREEN}$NOOBZ_STATUS${NC}     NGINX ${GREEN}$NGINX_STATUS${NC}     HAPROXY  ${GREEN}$HAPROXY_STATUS${NC}"
echo -e "  ${CYAN}│${NC} WS-ePro ${GREEN}ON${NC}     UDP CUSTOM ${GREEN}ON${NC}     XRAY  ${GREEN}$XRAY_STATUS${NC}     DROPBEAR ${GREEN}$DROPBEAR_STATUS${NC}"
echo -e "  ${CYAN}╰═══════════════════╯╰═══════════════════╯╰══════════════════╯${NC}"
echo -e "  ${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}[01]${NC} SSH MENU     ${CYAN}│${NC} ${YELLOW}[08]${NC} BCKP/RSTR    ${CYAN}│${NC} ${YELLOW}[15]${NC} MENU BOT"
echo -e "  ${CYAN}│${NC} ${YELLOW}[02]${NC} VMESS MENU   ${CYAN}│${NC} ${YELLOW}[09]${NC} GOTOP X RAM  ${CYAN}│${NC} ${YELLOW}[16]${NC} CHANGE DOMAIN   ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}[03]${NC} VLESS MENU   ${CYAN}│${NC} ${YELLOW}[10]${NC} RESTART ALL  ${CYAN}│${NC} ${YELLOW}[17]${NC} FIX CRT DOMAIN  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}[04]${NC} TROJAN MENU  ${CYAN}│${NC} ${YELLOW}[11]${NC} TELE BOT     ${CYAN}│${NC} ${YELLOW}[18]${NC} CHANGE BANNER"
echo -e "  ${CYAN}│${NC} ${YELLOW}[05]${NC} AKUN NOOBZVPN${CYAN}│${NC} ${YELLOW}[12]${NC} UPDATE MENU  ${CYAN}│${NC} ${YELLOW}[19]${NC} RESTART BANNER  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}[06]${NC} SS - LIBEV   ${CYAN}│${NC} ${YELLOW}[13]${NC} RUNNING      ${CYAN}
echo -e "  ${CYAN}│${NC} ${YELLOW}[07]${NC} INSTALL UDP  ${CYAN}│${NC} ${YELLOW}[14]${NC} INFO PORT    ${CYAN}│${NC} ${YELLOW}[21]${NC} EKSTRAK MENU"
echo -e "  ${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "  ${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "  ${CYAN}│${NC} Script Version =  ${GREEN}HAPPY NEW YEAR 2025${NC}"
echo -e "  ${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
echo -ne "  Options [ 1 - 21 ] ❱❱❱ "
read -r option

case $option in
    1) ssh-menu ;;
    2) vmess-menu ;;
    3) vless-menu ;;
    4) trojan-menu ;;
    5) noobz-menu ;;
    6) ss-menu ;;
    7) install-udp ;;
    8) backup-restore ;;
    9) gotop ;;
    10) restart-all ;;
    11) tele-bot ;;
    12) update-menu ;;
    13) running ;;
    14) info-port ;;
    15) menu-bot ;;
    16) change-domain ;;
    17) fix-cert ;;
    18) change-banner ;;
    19) restart-banner ;;
    20) speedtest-cli ;;
    21) ekstrak-menu ;;
    *) echo -e "${RED}Invalid option!${NC}" && sleep 2 && menu ;;
esac
EOF

# ==================== SSH MENU ====================
cat > /usr/local/bin/ssh-menu << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                      ${GREEN}SSH MENU${NC}                         ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}[1]${NC} Create SSH Account"
echo -e "${CYAN}│${NC} ${YELLOW}[2]${NC} Delete SSH Account"
echo -e "${CYAN}│${NC} ${YELLOW}[3]${NC} Extend SSH Account"
echo -e "${CYAN}│${NC} ${YELLOW}[4]${NC} Check User Login"
echo -e "${CYAN}│${NC} ${YELLOW}[5]${NC} List SSH Accounts"
echo -e "${CYAN}│${NC} ${YELLOW}[6]${NC} Delete Expired Accounts"
echo -e "${CYAN}│${NC} ${YELLOW}[7]${NC} Set Auto Kill Multi Login"
echo -e "${CYAN}│${NC} ${YELLOW}[8]${NC} Cek Traffic"
echo -e "${CYAN}│${NC} ${YELLOW}[0]${NC} Back to Main Menu"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
echo -ne "Select an option [0-8]: "
read -r option

case $option in
    1) create-ssh ;;
    2) delete-ssh ;;
    3) extend-ssh ;;
    4) cek-login ;;
    5) list-ssh ;;
    6) delete-expired ;;
    7) autokill ;;
    8) cek-traffic ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option!${NC}" && sleep 2 && ssh-menu ;;
esac
EOF

# ==================== CREATE SSH ====================
cat > /usr/local/bin/create-ssh << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                   ${GREEN}CREATE SSH ACCOUNT${NC}                  ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Input username
echo -ne "${YELLOW}Username: ${NC}"
read -r username

# Cek apakah user sudah ada
if id "$username" &>/dev/null; then
    echo -e "${RED}User $username already exists!${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    ssh-menu
    exit 1
fi

# Input password
echo -ne "${YELLOW}Password: ${NC}"
read -r password

# Input masa aktif
echo -ne "${YELLOW}Expired (days): ${NC}"
read -r masaaktif

# Hitung tanggal expired
exp_date=$(date -d "$masaaktif days" +"%Y-%m-%d")

# Buat user
useradd -e $exp_date -s /bin/false -M $username
echo -e "$password\n$password\n" | passwd $username &> /dev/null

# Simpan data user
echo "$username:$password:$exp_date" >> /etc/vpnserver/ssh-clients.txt

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                   ${GREEN}SSH ACCOUNT CREATED${NC}                 ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Username${NC}     : ${GREEN}$username${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Password${NC}     : ${GREEN}$password${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Expired${NC}      : ${GREEN}$exp_date${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Host/IP${NC}      : ${GREEN}$DOMAIN${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}OpenSSH${NC}      : ${GREEN}22${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Dropbear${NC}     : ${GREEN}143, 109, 69${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}SSL/TLS${NC}      : ${GREEN}443, 777${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Port Squid${NC}   : ${GREEN}3128, 8080${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}OpenVPN${NC}      : ${GREEN}1194 (UDP)${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Payload WS${NC}   : ${GREEN}GET / HTTP/1.1[crlf]Host: $DOMAIN[crlf]Upgrade: websocket[crlf][crlf]${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
read -n 1 -s -r -p "Press any key to continue..."
ssh-menu
EOF

# ==================== VMESS MENU ====================
cat > /usr/local/bin/vmess-menu << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                     ${GREEN}VMESS MENU${NC}                        ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}[1]${NC} Create VMess Account"
echo -e "${CYAN}│${NC} ${YELLOW}[2]${NC} Delete VMess Account"
echo -e "${CYAN}│${NC} ${YELLOW}[3]${NC} Extend VMess Account"
echo -e "${CYAN}│${NC} ${YELLOW}[4]${NC} Check VMess Config"
echo -e "${CYAN}│${NC} ${YELLOW}[5]${NC} List VMess Accounts"
echo -e "${CYAN}│${NC} ${YELLOW}[6]${NC} Delete Expired VMess"
echo -e "${CYAN}│${NC} ${YELLOW}[0]${NC} Back to Main Menu"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
echo -ne "Select an option [0-6]: "
read -r option

case $option in
    1) create-vmess ;;
    2) delete-vmess ;;
    3) extend-vmess ;;
    4) check-vmess ;;
    5) list-vmess ;;
    6) delete-expired-vmess ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option!${NC}" && sleep 2 && vmess-menu ;;
esac
EOF

# ==================== CREATE VMESS ====================
cat > /usr/local/bin/create-vmess << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                  ${GREEN}CREATE VMESS ACCOUNT${NC}                 ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Input username
echo -ne "${YELLOW}Username: ${NC}"
read -r username

# Cek apakah user sudah ada
if grep -q "\"email\": \"$username\"" /etc/xray/config.json; then
    echo -e "${RED}User $username already exists!${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    vmess-menu
    exit 1
fi

# Input masa aktif
echo -ne "${YELLOW}Expired (days): ${NC}"
read -r masaaktif

# Generate UUID
uuid=$(cat /proc/sys/kernel/random/uuid)

# Hitung tanggal expired
exp_date=$(date -d "$masaaktif days" +"%Y-%m-%d")
exp_timestamp=$(date -d "$masaaktif days" +%s)

# Backup config
cp /etc/xray/config.json /etc/xray/config.json.bak

# Add client ke config
jq --arg email "$username" --arg id "$uuid" \
   '.inbounds[0].settings.clients += [{"id": $id, "email": $email, "alterId": 0}]' \
   /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json

# Simpan data user
echo "$username:$uuid:$exp_date:$exp_timestamp" >> /etc/vpnserver/vmess-clients.txt

# Restart xray
systemctl restart xray

# Generate config
vmess_link=$(echo -n "{
  \"v\": \"2\",
  \"ps\": \"$username\",
  \"add\": \"$DOMAIN\",
  \"port\": \"443\",
  \"id\": \"$uuid\",
  \"aid\": \"0\",
  \"net\": \"ws\",
  \"path\": \"/vmess\",
  \"type\": \"none\",
  \"host\": \"$DOMAIN\",
  \"tls\": \"tls\"
}" | base64 -w 0)

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                  ${GREEN}VMESS ACCOUNT CREATED${NC}               ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Username${NC}     : ${GREEN}$username${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}UUID${NC}         : ${GREEN}$uuid${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Expired${NC}      : ${GREEN}$exp_date${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Host/IP${NC}      : ${GREEN}$DOMAIN${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Port TLS${NC}     : ${GREEN}443${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Port NTLS${NC}    : ${GREEN}80${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Network${NC}      : ${GREEN}ws${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Path${NC}         : ${GREEN}/vmess${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Security${NC}     : ${GREEN}auto${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}AlterID${NC}      : ${GREEN}0${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Link TLS${NC}     :"
echo -e "${GREEN}vmess://$vmess_link${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
read -n 1 -s -r -p "Press any key to continue..."
vmess-menu
EOF

# ==================== VLESS MENU ====================
cat > /usr/local/bin/vless-menu << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                     ${GREEN}VLESS MENU${NC}                        ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}[1]${NC} Create VLess Account"
echo -e "${CYAN}│${NC} ${YELLOW}[2]${NC} Delete VLess Account"
echo -e "${CYAN}│${NC} ${YELLOW}[3]${NC} Extend VLess Account"
echo -e "${CYAN}│${NC} ${YELLOW}[4]${NC} Check VLess Config"
echo -e "${CYAN}│${NC} ${YELLOW}[5]${NC} List VLess Accounts"
echo -e "${CYAN}│${NC} ${YELLOW}[6]${NC} Delete Expired VLess"
echo -e "${CYAN}│${NC} ${YELLOW}[0]${NC} Back to Main Menu"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
echo -ne "Select an option [0-6]: "
read -r option

case $option in
    1) create-vless ;;
    2) delete-vless ;;
    3) extend-vless ;;
    4) check-vless ;;
    5) list-vless ;;
    6) delete-expired-vless ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option!${NC}" && sleep 2 && vless-menu ;;
esac
EOF

# ==================== CREATE VLESS ====================
cat > /usr/local/bin/create-vless << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                  ${GREEN}CREATE VLESS ACCOUNT${NC}                 ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Input username
echo -ne "${YELLOW}Username: ${NC}"
read -r username

# Cek apakah user sudah ada
if grep -q "\"email\": \"$username\"" /etc/xray/config.json; then
    echo -e "${RED}User $username already exists!${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    vless-menu
    exit 1
fi

# Input masa aktif
echo -ne "${YELLOW}Expired (days): ${NC}"
read -r masaaktif

# Generate UUID
uuid=$(cat /proc/sys/kernel/random/uuid)

# Hitung tanggal expired
exp_date=$(date -d "$masaaktif days" +"%Y-%m-%d")
exp_timestamp=$(date -d "$masaaktif days" +%s)

# Backup config
cp /etc/xray/config.json /etc/xray/config.json.bak

# Add client ke config
jq --arg email "$username" --arg id "$uuid" \
   '.inbounds[1].settings.clients += [{"id": $id, "email": $email}]' \
   /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json

# Simpan data user
echo "$username:$uuid:$exp_date:$exp_timestamp" >> /etc/vpnserver/vless-clients.txt

# Restart xray
systemctl restart xray

# Generate config link
vless_link="vless://$uuid@$DOMAIN:443?path=/vless&security=tls&encryption=none&host=$DOMAIN&type=ws&sni=$DOMAIN#$username"

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                  ${GREEN}VLESS ACCOUNT CREATED${NC}               ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Username${NC}     : ${GREEN}$username${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}UUID${NC}         : ${GREEN}$uuid${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Expired${NC}      : ${GREEN}$exp_date${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Host/IP${NC}      : ${GREEN}$DOMAIN${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Port TLS${NC}     : ${GREEN}443${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Port NTLS${NC}    : ${GREEN}80${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Network${NC}      : ${GREEN}ws${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Path${NC}         : ${GREEN}/vless${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Security${NC}     : ${GREEN}tls${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Encryption${NC}   : ${GREEN}none${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Link TLS${NC}     :"
echo -e "${GREEN}$vless_link${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
read -n 1 -s -r -p "Press any key to continue..."
vless-menu
EOF

# ==================== TROJAN MENU ====================
cat > /usr/local/bin/trojan-menu << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                     ${GREEN}TROJAN MENU${NC}                       ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}[1]${NC} Create Trojan Account"
echo -e "${CYAN}│${NC} ${YELLOW}[2]${NC} Delete Trojan Account"
echo -e "${CYAN}│${NC} ${YELLOW}[3]${NC} Extend Trojan Account"
echo -e "${CYAN}│${NC} ${YELLOW}[4]${NC} Check Trojan Config"
echo -e "${CYAN}│${NC} ${YELLOW}[5]${NC} List Trojan Accounts"
echo -e "${CYAN}│${NC} ${YELLOW}[6]${NC} Delete Expired Trojan"
echo -e "${CYAN}│${NC} ${YELLOW}[0]${NC} Back to Main Menu"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
echo -ne "Select an option [0-6]: "
read -r option

case $option in
    1) create-trojan ;;
    2) delete-trojan ;;
    3) extend-trojan ;;
    4) check-trojan ;;
    5) list-trojan ;;
    6) delete-expired-trojan ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option!${NC}" && sleep 2 && trojan-menu ;;
esac
EOF

# ==================== CREATE TROJAN ====================
cat > /usr/local/bin/create-trojan << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                 ${GREEN}CREATE TROJAN ACCOUNT${NC}                ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Input username
echo -ne "${YELLOW}Username: ${NC}"
read -r username

# Cek apakah user sudah ada
if grep -q "\"email\": \"$username\"" /etc/xray/config.json; then
    echo -e "${RED}User $username already exists!${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    trojan-menu
    exit 1
fi

# Input masa aktif
echo -ne "${YELLOW}Expired (days): ${NC}"
read -r masaaktif

# Generate password
password=$(openssl rand -hex 16)

# Hitung tanggal expired
exp_date=$(date -d "$masaaktif days" +"%Y-%m-%d")
exp_timestamp=$(date -d "$masaaktif days" +%s)

# Backup config
cp /etc/xray/config.json /etc/xray/config.json.bak

# Add client ke config
jq --arg email "$username" --arg password "$password" \
   '.inbounds[2].settings.clients += [{"password": $password, "email": $email}]' \
   /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json

# Simpan data user
echo "$username:$password:$exp_date:$exp_timestamp" >> /etc/vpnserver/trojan-clients.txt

# Restart xray
systemctl restart xray

# Generate config link
trojan_link="trojan://$password@$DOMAIN:443?path=/trojan&security=tls&host=$DOMAIN&type=ws&sni=$DOMAIN#$username"

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                 ${GREEN}TROJAN ACCOUNT CREATED${NC}              ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Username${NC}     : ${GREEN}$username${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Password${NC}     : ${GREEN}$password${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Expired${NC}      : ${GREEN}$exp_date${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Host/IP${NC}      : ${GREEN}$DOMAIN${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Port TLS${NC}     : ${GREEN}443${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Network${NC}      : ${GREEN}ws${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Path${NC}         : ${GREEN}/trojan${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Security${NC}     : ${GREEN}tls${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Link TLS${NC}     :"
echo -e "${GREEN}$trojan_link${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
read -n 1 -s -r -p "Press any key to continue..."
trojan-menu
EOF

# ==================== SHADOWSOCKS MENU ====================
cat > /usr/local/bin/ss-menu << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                  ${GREEN}SHADOWSOCKS MENU${NC}                    ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}[1]${NC} Create SS Account"
echo -e "${CYAN}│${NC} ${YELLOW}[2]${NC} Delete SS Account"
echo -e "${CYAN}│${NC} ${YELLOW}[3]${NC} Extend SS Account"
echo -e "${CYAN}│${NC} ${YELLOW}[4]${NC} Check SS Config"
echo -e "${CYAN}│${NC} ${YELLOW}[5]${NC} List SS Accounts"
echo -e "${CYAN}│${NC} ${YELLOW}[6]${NC} Delete Expired SS"
echo -e "${CYAN}│${NC} ${YELLOW}[0]${NC} Back to Main Menu"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
echo -ne "Select an option [0-6]: "
read -r option

case $option in
    1) create-ss ;;
    2) delete-ss ;;
    3) extend-ss ;;
    4) check-ss ;;
    5) list-ss ;;
    6) delete-expired-ss ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option!${NC}" && sleep 2 && ss-menu ;;
esac
EOF

# ==================== CREATE SHADOWSOCKS ====================
cat > /usr/local/bin/create-
# ==================== CREATE SHADOWSOCKS ====================
cat > /usr/local/bin/create-ss << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}               ${GREEN}CREATE SHADOWSOCKS ACCOUNT${NC}             ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Input username
echo -ne "${YELLOW}Username: ${NC}"
read -r username

# Cek apakah user sudah ada
if grep -q "^$username:" /etc/vpnserver/ss-clients.txt 2>/dev/null; then
    echo -e "${RED}User $username already exists!${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    ss-menu
    exit 1
fi

# Input masa aktif
echo -ne "${YELLOW}Expired (days): ${NC}"
read -r masaaktif

# Generate password
password=$(openssl rand -base64 16)

# Hitung tanggal expired
exp_date=$(date -d "$masaaktif days" +"%Y-%m-%d")

# Simpan data user
echo "$username:$password:$exp_date" >> /etc/vpnserver/ss-clients.txt

# Generate SS link
ss_link=$(echo -n "aes-256-gcm:$password" | base64 -w 0)
ss_url="ss://$ss_link@$DOMAIN:8388#$username"

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}               ${GREEN}SHADOWSOCKS ACCOUNT CREATED${NC}           ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Username${NC}     : ${GREEN}$username${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Password${NC}     : ${GREEN}$password${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Expired${NC}      : ${GREEN}$exp_date${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Host/IP${NC}      : ${GREEN}$DOMAIN${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Port${NC}         : ${GREEN}8388${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Method${NC}       : ${GREEN}aes-256-gcm${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Plugin${NC}       : ${GREEN}obfs-server${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Plugin Opts${NC}  : ${GREEN}obfs=tls${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}SS Link${NC}      :"
echo -e "${GREEN}$ss_url${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
read -n 1 -s -r -p "Press any key to continue..."
ss-menu
EOF

# ==================== NOOBZVPN MENU ====================
cat > /usr/local/bin/noobz-menu << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                    ${GREEN}NOOBZVPN MENU${NC}                      ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}[1]${NC} Create NoobzVPN Account"
echo -e "${CYAN}│${NC} ${YELLOW}[2]${NC} Delete NoobzVPN Account"
echo -e "${CYAN}│${NC} ${YELLOW}[3]${NC} Extend NoobzVPN Account"
echo -e "${CYAN}│${NC} ${YELLOW}[4]${NC} List NoobzVPN Accounts"
echo -e "${CYAN}│${NC} ${YELLOW}[5]${NC} Delete Expired NoobzVPN"
echo -e "${CYAN}│${NC} ${YELLOW}[0]${NC} Back to Main Menu"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
echo -ne "Select an option [0-5]: "
read -r option

case $option in
    1) create-noobz ;;
    2) delete-noobz ;;
    3) extend-noobz ;;
    4) list-noobz ;;
    5) delete-expired-noobz ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option!${NC}" && sleep 2 && noobz-menu ;;
esac
EOF

# ==================== CREATE NOOBZVPN ====================
cat > /usr/local/bin/create-noobz << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                ${GREEN}CREATE NOOBZVPN ACCOUNT${NC}               ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Input username
echo -ne "${YELLOW}Username: ${NC}"
read -r username

# Cek apakah user sudah ada
if grep -q "^$username:" /etc/noobzvpns.conf; then
    echo -e "${RED}User $username already exists!${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    noobz-menu
    exit 1
fi

# Input password
echo -ne "${YELLOW}Password: ${NC}"
read -r password

# Input masa aktif
echo -ne "${YELLOW}Expired (days): ${NC}"
read -r masaaktif

# Hitung tanggal expired
exp_date=$(date -d "$masaaktif days" +"%Y-%m-%d")

# Tambah user ke config
echo "$username:$password" >> /etc/noobzvpns.conf

# Simpan data user
echo "$username:$password:$exp_date" >> /etc/vpnserver/noobz-clients.txt

# Restart service
systemctl restart noobzvpns

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                ${GREEN}NOOBZVPN ACCOUNT CREATED${NC}             ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Username${NC}     : ${GREEN}$username${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Password${NC}     : ${GREEN}$password${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Expired${NC}      : ${GREEN}$exp_date${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Host/IP${NC}      : ${GREEN}$DOMAIN${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Port TCP${NC}     : ${GREEN}8080${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Port UDP${NC}     : ${GREEN}8080${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
read -n 1 -s -r -p "Press any key to continue..."
noobz-menu
EOF

# ==================== INFO PORT ====================
cat > /usr/local/bin/info-port << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                     ${GREEN}PORT INFORMATION${NC}                   ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}SSH/OpenSSH${NC}          : ${GREEN}22, 2222${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}SSH/Dropbear${NC}         : ${GREEN}143, 109, 69${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}SSH/SSL-TLS${NC}          : ${GREEN}443, 777${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}OpenVPN${NC}              : ${GREEN}1194 (UDP)${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}OpenVPN/SSL${NC}          : ${GREEN}992 (TCP)${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Stunnel4${NC}             : ${GREEN}443, 777${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Squid Proxy${NC}          : ${GREEN}3128, 8080${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Nginx${NC}                : ${GREEN}80, 443${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}XRAY Vmess TLS${NC}       : ${GREEN}443${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}XRAY Vmess None TLS${NC}  : ${GREEN}80${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}XRAY Vless TLS${NC}       : ${GREEN}443${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}XRAY Vless None TLS${NC}  : ${GREEN}80${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}XRAY Trojan${NC}          : ${GREEN}443${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}Shadowsocks-Libev${NC}    : ${GREEN}8388${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}NoobzVPN${NC}             : ${GREEN}8080${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}HAProxy${NC}              : ${GREEN}80, 8080${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
read -n 1 -s -r -p "Press any key to continue..."
menu
EOF

# ==================== BACKUP & RESTORE ====================
cat > /usr/local/bin/backup-restore << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                   ${GREEN}BACKUP & RESTORE${NC}                    ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC} ${YELLOW}[1]${NC} Backup Data"
echo -e "${CYAN}│${NC} ${YELLOW}[2]${NC} Restore Data"
echo -e "${CYAN}│${NC} ${YELLOW}[3]${NC} Auto Backup Setup"
echo -e "${CYAN}│${NC} ${YELLOW}[0]${NC} Back to Main Menu"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
echo -ne "Select an option [0-3]: "
read -r option

case $option in
    1) backup_data ;;
    2) restore_data ;;
    3) auto_backup ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option!${NC}" && sleep 2 && backup-restore ;;
esac

backup_data() {
    clear
    echo -e "${YELLOW}Creating backup...${NC}"
    
    # Buat direktori backup
    mkdir -p /root/backup
    
    # Backup tanggal
    backup_date=$(date +%Y%m%d_%H%M%S)
    backup_file="/root/backup/vpnserver_backup_$backup_date.tar.gz"
    
    # File yang akan dibackup
    tar -czf $backup_file \
        /etc/xray/ \
        /etc/vpnserver/ \
        /etc/nginx/sites-available/ \
        /etc/openvpn/ \
        /etc/shadowsocks-libev/ \
        /etc/passwd \
        /etc/shadow \
        /etc/group \
        /etc/gshadow \
        /etc/ssh/sshd_config \
        /etc/default/dropbear \
        /etc/stunnel/ \
        /etc/haproxy/ \
        /etc/noobzvpns.conf \
        2>/dev/null
    
    echo -e "${GREEN}Backup created: $backup_file${NC}"
    echo -e "${GREEN}Backup size: $(du -h $backup_file | cut -f1)${NC}"
    
    read -n 1 -s -r -p "Press any key to continue..."
    backup-restore
}

restore_data() {
    clear
    echo -e "${YELLOW}Available backups:${NC}"
    ls -la /root/backup/*.tar.gz 2>/dev/null
    echo ""
    echo -ne "${YELLOW}Enter backup file path: ${NC}"
    read -r backup_file
    
    if [[ ! -f "$backup_file" ]]; then
        echo -e "${RED}Backup file not found!${NC}"
        read -n 1 -s -r -p "Press any key to continue..."
        backup-restore
        return
    fi
    
    echo -e "${YELLOW}Restoring backup...${NC}"
    
    # Stop services
    systemctl stop xray nginx ssh dropbear openvpn@server shadowsocks-libev haproxy noobzvpns
    
    # Restore files
    tar -xzf $backup_file -C /
    
    # Restart services
    systemctl start xray nginx ssh dropbear openvpn@server shadowsocks-libev haproxy noobzvpns
    
    echo -e "${GREEN}Restore completed!${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    backup-restore
}

auto_backup() {
    clear
    echo -e "${YELLOW}Setting up auto backup...${NC}"
    
    # Buat script auto backup
    cat > /usr/local/bin/auto-backup << 'EOFAB'
#!/bin/bash
backup_date=$(date +%Y%m%d_%H%M%S)
backup_file="/root/backup/auto_backup_$backup_date.tar.gz"

mkdir -p /root/backup

tar -czf $backup_file \
    /etc/xray/ \
    /etc/vpnserver/ \
    /etc/nginx/sites-available/ \
    /etc/openvpn/ \
    /etc/shadowsocks-libev/ \
    /etc/passwd \
    /etc/shadow \
    /etc/group \
    /etc/gshadow \
    /etc/ssh/sshd_config \
    /etc/default/dropbear \
    /etc/stunnel/ \
    /etc/haproxy/ \
    /etc/noobzvpns.conf \
    2>/dev/null

# Hapus backup lama (lebih dari 7 hari)
find /root/backup -name "auto_backup_*.tar.gz" -mtime +7 -delete

echo "Auto backup completed: $backup_file" >> /var/log/auto-backup.log
EOFAB

    chmod +x /usr/local/bin/auto-backup
    
    # Tambah ke crontab (backup setiap hari jam 2 pagi)
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/auto-backup") | crontab -
    
    echo -e "${GREEN}Auto backup setup completed!${NC}"
    echo -e "${GREEN}Backup will run daily at 2:00 AM${NC}"
    
    read -n 1 -s -r -p "Press any key to continue..."
    backup-restore
}
EOF

# ==================== RESTART ALL SERVICES ====================
cat > /usr/local/bin/restart-all << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                   ${GREEN}RESTARTING ALL SERVICES${NC}             ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

services=("nginx" "xray" "ssh" "dropbear" "openvpn@server" "shadowsocks-libev" "haproxy" "noobzvpns" "stunnel4")

for service in "${services[@]}"; do
    echo -ne "${YELLOW}Restarting $service...${NC}"
    if systemctl restart $service 2>/dev/null; then
        echo -e " ${GREEN}[OK]${NC}"
    else
        echo -e " ${RED}[FAILED]${NC}"
    fi
    sleep 1
done

echo ""
echo -e "${GREEN}All services restarted!${NC}"
read -n 1 -s -r -p "Press any key to continue..."
menu
EOF

# ==================== RUNNING SERVICES ====================
cat > /usr/local/bin/running << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                    ${GREEN}RUNNING SERVICES${NC}                    ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

services=("nginx" "xray" "ssh" "dropbear" "openvpn@server" "shadowsocks-libev" "haproxy" "noobzvpns" "stunnel4" "squid")

for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        status="${GREEN}[RUNNING]${NC}"
    else
        status="${RED}[STOPPED]${NC}"
    fi
    printf "%-20s : %s\n" "$service" "$status"
done

echo ""
read -n 1 -s -r -p "Press any key to continue..."
menu
EOF

# ==================== CEK LOGIN ====================
cat > /usr/local/bin/cek-login << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                     ${GREEN}USER LOGIN STATUS${NC}                  ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# SSH Login
echo -e "${YELLOW}SSH/OpenSSH Login:${NC}"
who | grep -E "pts|tty" | awk '{print $1 " - " $3 " " $4 " from " $5}'

echo ""
echo -e "${YELLOW}Dropbear Login:${NC}"
ps aux | grep dropbear | grep -v grep | awk '{print $11}' | sort | uniq -c

echo ""
echo -e "${YELLOW}OpenVPN Login:${NC}"
if [[ -f /var/log/openvpn/openvpn-status.log ]]; then
    grep "^CLIENT_LIST" /var/log/openvpn/openvpn-status.log | awk -F',' '{print $2 " - " $3 " - " $4}'
else
    echo "No OpenVPN log found"
fi

echo ""
read -n 1 -s -r -p "Press any key to continue..."
ssh-menu
EOF

# ==================== LIST SSH ====================
cat > /usr/local/bin/list-ssh << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                     ${GREEN}SSH ACCOUNTS LIST${NC}                  ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

if [[ -f /etc/vpnserver/ssh-clients.txt ]]; then
    echo -e "${YELLOW}Username${NC}        ${YELLOW}Password${NC}        ${YELLOW}Expired${NC}"
    echo "================================================"
    while IFS=':' read -r username password exp_date; do
        printf "%-15s %-15s %s\n" "$username" "$password" "$exp_date"
    done < /etc/vpnserver/ssh-clients.txt
else
    echo -e "${RED}No SSH accounts found${NC}"
fi

echo ""
read -n 1 -s -r -p "Press any key to continue..."
ssh-menu
EOF

# ==================== DELETE SSH ====================
cat > /usr/local/bin/delete-ssh << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                   ${GREEN}DELETE SSH ACCOUNT${NC}                  ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Tampilkan daftar user
if [[ -f /etc/vpnserver/ssh-clients.txt ]]; then
    echo -e "${YELLOW}Existing SSH accounts:${NC}"
    cat /etc/vpnserver/ssh-clients.txt | cut -d':' -f1
    echo ""
fi

echo -ne "${YELLOW}Username to delete: ${NC}"
read -r username

# Cek apakah user ada
if ! id "$username" &>/dev/null; then
    echo -e "${RED}User $username not found!${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    ssh-menu
    exit 1
fi

# Hapus user
userdel -f $username 2>/dev/null

# Hapus dari database
sed -i "/^$username:/d" /etc/vpnserver/ssh-clients.txt

echo -e "${GREEN}User $username deleted successfully!${NC}"
read -n 1 -s -r -p "Press any key to continue..."
ssh-menu
EOF

# ==================== EXTEND SSH ====================
cat > /usr/local/bin/extend-ssh << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                   ${GREEN}EXTEND SSH ACCOUNT${NC}                  ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Tampilkan daftar user
if [[ -f /etc/vpnserver/ssh-clients.txt ]]; then
    echo -e "${YELLOW}Existing SSH accounts:${NC}"
    cat /etc/vpnserver/ssh-clients.txt | cut -d':' -f1
    echo ""
fi

echo -ne "${YELLOW}Username to extend: ${NC}"
read -r username

# Cek apakah user ada
if ! id "$username" &>/dev/null; then
    echo -e "${RED}User $username not found!${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    ssh-menu
    exit 1
fi

echo -ne "${YELLOW}Extend days: ${NC}"
read -r extend_days

# Hitung tanggal baru
new_exp_date=$(date -d "$extend_days days" +"%Y-%m-%d")

# Update expiry date
chage -E $new_exp_date $username

# Update database
sed -i "s/^$username:\([^:]*\):[^:]*/&$username:\1:$new_exp_date/" /etc/vpnserver/ssh-clients.txt

echo -e "${GREEN}User $username extended until $new_exp_date${NC}"
read -n 1 -s -r -p "Press any key to continue..."
ssh-menu
EOF

# ==================== DELETE EXPIRED ====================
cat > /usr/local/bin/delete-expired << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│${NC}                 ${GREEN}DELETE EXPIRED ACCOUNTS${NC}              ${CYAN}│${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

current_date=$(date +%Y-%m-%d)
expired_count=0

if [[ -f /etc/vpnserver/ssh-clients.txt ]]; then
    while IFS=':' read -r username password exp_date; do
        if [[ "$exp_date" < "$current_date" ]]; then
            echo -e "${YELLOW}Deleting expired user: $username (expired: $exp_date)${NC}"
            userdel -f $username 2>/dev/null
            sed -i "/^$username:/d" /etc/vpnserver/ssh-clients.txt
            ((expired_count++))
        fi
    done < /etc/vpnserver/ssh-clients.txt
fi

echo -e "${GREEN}Deleted $expired_count expired accounts${NC}"
read -n 1 -s -r -p "Press any key to continue..."
ssh-menu
EOF

# ==================== AUTO KILL MULTI LOGIN ====================
cat > /usr/local/bin/autokill << 'EOF'
#!/bin/bash
clear
source /etc/vpnserver/config.conf

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\
