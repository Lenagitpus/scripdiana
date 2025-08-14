#!/bin/bash
# Auto Installer VPN Multi-Protocol
# Created by: VPN Script Installer
# Version: HAPPY NEW YEAR 2025

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Clear screen
clear

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Banner
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│                    VPN AUTO INSTALLER                     │${NC}"
echo -e "${CYAN}│                  HAPPY NEW YEAR 2025                      │${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Get server information
MYIP=$(curl -sS ipv4.icanhazip.com)
DOMAIN=""

echo -e "${YELLOW}Enter your domain (or press Enter to use IP):${NC}"
read -p "Domain: " DOMAIN

if [[ -z "$DOMAIN" ]]; then
    DOMAIN=$MYIP
fi

echo -e "${GREEN}Using domain: $DOMAIN${NC}"
sleep 2

# Update system
echo -e "${YELLOW}Updating system...${NC}"
apt update -y && apt upgrade -y
apt install -y wget curl nano zip unzip tar gzip

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
apt install -y software-properties-common
apt install -y build-essential cmake
apt install -y nginx haproxy dropbear stunnel4
apt install -y python3 python3-pip
apt install -y openvpn easy-rsa
apt install -y shadowsocks-libev
apt install -y htop gotop
apt install -y jq bc

# Create directories
mkdir -p /etc/xray
mkdir -p /etc/vmess
mkdir -p /etc/vless  
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /etc/ssh-clients
mkdir -p /var/log/xray
mkdir -p /root/backup
mkdir -p /etc/bot

# Install Xray
echo -e "${YELLOW}Installing Xray...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate certificates
echo -e "${YELLOW}Generating SSL certificates...${NC}"
mkdir -p /etc/xray/tls
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$DOMAIN" \
    -keyout /etc/xray/tls/server.key \
    -out /etc/xray/tls/server.crt

# Generate UUIDs
VMESS_UUID=$(cat /proc/sys/kernel/random/uuid)
VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
TROJAN_PASS=$(openssl rand -base64 16)

# Configure Xray
cat > /etc/xray/config.json << EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$VMESS_UUID",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/tls/server.crt",
              "keyFile": "/etc/xray/tls/server.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vmess"
        }
      }
    },
    {
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$VLESS_UUID"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/tls/server.crt",
              "keyFile": "/etc/xray/tls/server.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vless"
        }
      }
    },
    {
      "port": 9443,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$TROJAN_PASS"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/tls/server.crt",
              "keyFile": "/etc/xray/tls/server.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/trojan"
        }
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

# Configure Nginx
cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/xray/tls/server.crt;
    ssl_certificate_key /etc/xray/tls/server.key;
    
    location /vmess {
        proxy_pass http://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vless {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /trojan {
        proxy_pass http://127.0.0.1:9443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location / {
        root /var/www/html;
        index index.html;
    }
}
EOF

# Configure Dropbear
echo -e "${YELLOW}Configuring Dropbear...${NC}"
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
echo 'DROPBEAR_EXTRA_ARGS="-p 109 -p 69"' >> /etc/default/dropbear

# Configure OpenVPN
echo -e "${YELLOW}Configuring OpenVPN...${NC}"
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

# OpenVPN Easy-RSA configuration
cat > vars << EOF
export KEY_COUNTRY="ID"
export KEY_PROVINCE="Jakarta"
export KEY_CITY="Jakarta"
export KEY_ORG="VPN"
export KEY_EMAIL="admin@$DOMAIN"
export KEY_OU="VPN"
export KEY_NAME="server"
EOF

source vars
./clean-all
./build-ca --batch
./build-key-server --batch server
./build-dh
openvpn --genkey --secret keys/ta.key

# OpenVPN server config
cat > /etc/openvpn/server.conf << EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/server.crt
key /etc/openvpn/easy-rsa/keys/server.key
dh /etc/openvpn/easy-rsa/keys/dh2048.pem
tls-auth /etc/openvpn/easy-rsa/keys/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
EOF

# Configure Shadowsocks
echo -e "${YELLOW}Configuring Shadowsocks...${NC}"
SS_PASS=$(openssl rand -base64 16)
cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":"0.0.0.0",
    "server_port":8388,
    "local_port":1080,
    "password":"$SS_PASS",
    "timeout":60,
    "method":"aes-256-gcm"
}
EOF

# Install NoobzVPN
echo -e "${YELLOW}Installing NoobzVPN...${NC}"
cd /tmp
wget -O noobzvpns.tar.gz "https://github.com/noobz-id/noobzvpns/releases/download/v1.0/noobzvpns-linux-amd64.tar.gz"
tar -xf noobzvpns.tar.gz
mv noobzvpns /usr/local/bin/
chmod +x /usr/local/bin/noobzvpns

# NoobzVPN config
cat > /etc/noobzvpns.json << EOF
{
    "tcp_std": [8080],
    "tcp_ssl": [8443],
    "ssl_cert": "/etc/xray/tls/server.crt",
    "ssl_key": "/etc/xray/tls/server.key",
    "ssl_version": "AUTO"
}
EOF

# Create systemd service for NoobzVPN
cat > /etc/systemd/system/noobzvpns.service << EOF
[Unit]
Description=NoobzVPN Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/noobzvpns -config /etc/noobzvpns.json
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

# Create menu script
cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get system info
MYIP=$(curl -sS ipv4.icanhazip.com)
DOMAIN=$(cat /etc/xray/domain 2>/dev/null || echo $MYIP)
UPTIME=$(uptime -p | sed 's/up //')
LOAD=$(uptime | awk -F'load average:' '{print $2}' | cut -d, -f1 | sed 's/ //g')
CORE=$(nproc)
RAM_TOTAL=$(free -m | awk 'NR==2{printf "%.0f", $2}')
RAM_USED=$(free -m | awk 'NR==2{printf "%.0f", $3}')
DATE=$(date '+%d-%m-%Y')
TIME=$(date '+%H-%M-%S')

# Count accounts
SSH_COUNT=$(cat /etc/passwd | grep "/bin/bash" | grep -v root | wc -l)
VMESS_COUNT=$(grep -c "id" /etc/vmess/clients.json 2>/dev/null || echo "0")
VLESS_COUNT=$(grep -c "id" /etc/vless/clients.json 2>/dev/null || echo "0")
TROJAN_COUNT=$(grep -c "password" /etc/trojan/clients.json 2>/dev/null || echo "0")
SS_COUNT=$(grep -c "port_password" /etc/shadowsocks/clients.json 2>/dev/null || echo "0")

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│ ● SYSTEM OS    = $(lsb_release -d | cut -f2)"
echo -e "${CYAN}│ ● SYSTEM CORE  = $CORE${NC}"
echo -e "${CYAN}│ ● SERVER RAM   = $RAM_TOTAL / $RAM_USED MB${NC}"
echo -e "${CYAN}│ ● LOADCPU      = $LOAD ℅${NC}"
echo -e "${CYAN}│ ● DATE         = $DATE${NC}"
echo -e "${CYAN}│ ● TIME         = $TIME${NC}"
echo -e "${CYAN}│ ● UPTIME       = $UPTIME${NC}"
echo -e "${CYAN}│ ● IP VPS       = $MYIP${NC}"
echo -e "${CYAN}│ ● DOMAIN       = $DOMAIN${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${YELLOW}                   >>> INFORMATION ACCOUNT <<<${NC}"
echo -e "${YELLOW}          ═════════════════════════════════════════════${NC}"
echo -e "${YELLOW}                SSH/OPENVPN/UDP  = $SSH_COUNT${NC}"
echo -e "${YELLOW}                VMESS/WS/GRPC    = $VMESS_COUNT${NC}"
echo -e "${YELLOW}                VLESS/WS/GRPC    = $VLESS_COUNT${NC}"
echo -e "${YELLOW}                TROJAN/WS/GRPC   = $TROJAN_COUNT${NC}"
echo -e "${YELLOW}                SHADOW/WS/GRPC   = $SS_COUNT${NC}"
echo -e "${YELLOW}          ═════════════════════════════════════════════${NC}"
echo -e "${GREEN}                  >>> Dekengane Pusat Blitar <<<${NC}"

# Check service status
SSH_STATUS=$(systemctl is-active ssh && echo "ON" || echo "OFF")
NGINX_STATUS=$(systemctl is-active nginx && echo "ON" || echo "OFF")
XRAY_STATUS=$(systemctl is-active xray && echo "ON" || echo "OFF")
DROPBEAR_STATUS=$(systemctl is-active dropbear && echo "ON" || echo "OFF")
NOOBZ_STATUS=$(systemctl is-active noobzvpns && echo "ON" || echo "OFF")
HAPROXY_STATUS=$(systemctl is-active haproxy && echo "ON" || echo "OFF")

echo -e "${CYAN}  ╭═══════════════════╮╭═══════════════════╮╭══════════════════╮${NC}"
echo -e "${CYAN}  │ SSH     $SSH_STATUS     NOOBZVPN   $NOOBZ_STATUS     NGINX $NGINX_STATUS     HAPROXY  $HAPROXY_STATUS${NC}"
echo -e "${CYAN}  │ WS-ePro ON     UDP CUSTOM ON     XRAY  $XRAY_STATUS     DROPBEAR $DROPBEAR_STATUS${NC}"
echo -e "${CYAN}  ╰═══════════════════╯╰═══════════════════╯╰══════════════════╯${NC}"

echo -e "${CYAN}  ╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}  │ [01] SSH MENU     │ [08] BCKP/RSTR    │ [15] MENU BOT      │${NC}"
echo -e "${CYAN}  │ [02] VMESS MENU   │ [09] GOTOP X RAM  │ [16] CHANGE DOMAIN │${NC}"
echo -e "${CYAN}  │ [03] VLESS MENU   │ [10] RESTART ALL  │ [17] FIX CRT DOMAIN│${NC}"
echo -e "${CYAN}  │ [04] TROJAN MENU  │ [11] TELE BOT     │ [18] CHANGE BANNER │${NC}"
echo -e "${CYAN}  │ [05] AKUN NOOBZVPN│ [12] UPDATE MENU  │ [19] RESTART BANNER│${NC}"
echo -e "${CYAN}  │ [06] SS - LIBEV   │ [13] RUNNING      │ [20] SPEEDTEST     │${NC}"
echo -e "${CYAN}  │ [07] INSTALL UDP  │ [14] INFO PORT    │ [21] EKSTRAK MENU  │${NC}"
echo -e "${CYAN}  ╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}  ╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}  │ Script Version =  HAPPY NEW YEAR 2025                     │${NC}"
echo -e "${CYAN}  ╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
read -p "  Options [ 1 - 21 ] ❱❱❱ " menu

case $menu in
    1) ssh-menu ;;
    2) vmess-menu ;;
    3) vless-menu ;;
    4) trojan-menu ;;
    5) noobz-menu ;;
    6) ss-menu ;;
    7) udp-install ;;
    8) backup-restore ;;
    9) gotop ;;
    10) restart-services ;;
    11) bot-menu ;;
    12) update-script ;;
    13) running-services ;;
    14) port-info ;;
    15) bot-menu ;;
    16) change-domain ;;
    17) fix-cert ;;
    18) change-banner ;;
    19) restart-banner ;;
    20) speedtest-cli ;;
    21) extract-menu ;;
    *) echo -e "${RED}Invalid option${NC}" ;;
esac
EOF

chmod +x /usr/local/bin/menu

# Create SSH menu
cat > /usr/local/bin/ssh-menu << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│                        SSH MENU                           │${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${YELLOW}  [1] Create SSH Account${NC}"
echo -e "${YELLOW}  [2] Delete SSH Account${NC}"
echo -e "${YELLOW}  [3] Extend SSH Account${NC}"
echo -e "${YELLOW}  [4] Check SSH Login${NC}"
echo -e "${YELLOW}  [5] List SSH Accounts${NC}"
echo -e "${YELLOW}  [6] Lock SSH Account${NC}"
echo -e "${YELLOW}  [7] Unlock SSH Account${NC}"
echo -e "${YELLOW}  [0] Back to Main Menu${NC}"
echo ""
read -p "Select option: " ssh_option

case $ssh_option in
    1) create-ssh ;;
    2) delete-ssh ;;
    3) extend-ssh ;;
    4) check-ssh ;;
    5) list-ssh ;;
    6) lock-ssh ;;
    7) unlock-ssh ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option${NC}" ;;
esac
EOF

chmod +x /usr/local/bin/ssh-menu

# Create SSH account creator
cat > /usr/local/bin/create-ssh << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${GREEN}Create SSH Account${NC}"
echo ""

read -p "Username: " username
read -p "Password: " password
read -p "Expired (days): " days

if [[ -z "$username" || -z "$password" || -z "$days" ]]; then
    echo -e "${RED}All fields are required!${NC}"
    exit 1
fi

# Check if user exists
if id "$username" &>/dev/null; then
    echo -e "${RED}User $username already exists!${NC}"
    exit 1
fi

# Create user
useradd -e $(date -d "$days days" +"%Y-%m-%d") -s /bin/false -M $username
echo -e "$password\n$password" | passwd $username

# Save to client list
echo "$username:$password:$(date -d "$days days" +"%Y-%m-%d")" >> /etc/ssh-clients/clients.txt

# Get server info
DOMAIN=$(cat /etc/xray/domain 2>/dev/null || curl -sS ipv4.icanhazip.com)

clear
echo -e "${GREEN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${GREEN}│                    SSH ACCOUNT CREATED                     │${NC}"
echo -e "${GREEN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${YELLOW}Username    : $username${NC}"
echo -e "${YELLOW}Password    : $password${NC}"
echo -e "${YELLOW}Expired     : $(date -d "$days days" +"%Y-%m-%d")${NC}"
echo -e "${YELLOW}Domain      : $DOMAIN${NC}"
echo -e "${YELLOW}Port SSH    : 22${NC}"
echo -e "${YELLOW}Port Dropbear: 109, 143, 69${NC}"
echo -e "${YELLOW}Port SSL    : 443, 777${NC}"
echo -e "${YELLOW}Port OVPN   : 1194 (UDP)${NC}"
echo -e "${GREEN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""
read -p "Press enter to continue..."
ssh-menu
EOF

chmod +x /usr/local/bin/create-ssh

# Create VMESS menu
cat > /usr/local/bin/vmess-menu << 'EOF'
#!/bin/bash

# Colors  
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│                       VMESS MENU                          │${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${YELLOW}  [1] Create VMESS Account${NC}"
echo -e "${YELLOW}  [2] Delete VMESS Account${NC}"
echo -e "${YELLOW}  [3] Extend VMESS Account${NC}"
echo -e "${YELLOW}  [4] Check VMESS Config${NC}"
echo -e "${YELLOW}  [5] List VMESS Accounts${NC}"
echo -e "${YELLOW}  [0] Back to Main Menu${NC}"
echo ""
read -p "Select option: " vmess_option

case $vmess_option in
    1) create-vmess ;;
    2) delete-vmess ;;
    3) extend-vmess ;;
    4) check-vmess ;;
    5) list-vmess ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option${NC}" ;;
esac
EOF

chmod +x /usr/local/bin/vmess-menu

# Create VMESS account creator
cat > /usr/local/bin/create-vmess << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${GREEN}Create VMESS Account${NC}"
echo ""

read -p "Username: " username
read -p "Expired (days): " days

if [[ -z "$username" || -z "$days" ]]; then
    echo -e "${RED}All fields are required!${NC}"
    exit 1
fi

# Generate UUID
uuid=$(cat /proc/sys/kernel/random/uuid)
exp_date=$(date -d "$days days" +"%Y-%m-%d")

# Save to client list
mkdir -p /etc/vmess
echo "$username:$uuid:$exp_date" >> /etc/vmess/clients.txt

# Get domain
DOMAIN=$(cat /etc/xray/domain 2>/dev/null || curl -sS ipv4.icanhazip.com)

# Create config
vmess_config="{
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
}"

vmess_link="vmess://$(echo -n "$vmess_config" | base64 -w 0)"

clear
echo -e "${GREEN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${GREEN}│                   VMESS ACCOUNT CREATED                    │${NC}"
echo -e "${GREEN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${YELLOW}Username    : $username${NC}"
echo -e "${YELLOW}UUID        : $uuid${NC}"
echo -e "${YELLOW}Domain      : $DOMAIN${NC}"
echo -e "${YELLOW}Port        : 443${NC}"
echo -e "${YELLOW}Network     : WebSocket${NC}"
echo -e "${YELLOW}Path        : /vmess${NC}"
echo -e "${YELLOW}Security    : TLS${NC}"
echo -e "${YELLOW}Expired     : $exp_date${NC}"
echo -e "${GREEN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${YELLOW}VMESS Link:${NC}"
echo -e "${GREEN}$vmess_link${NC}"
echo ""
read -p "Press enter to continue..."
vmess-menu
EOF

chmod +x /usr/local/bin/create-vmess

# Create other menu scripts (simplified versions)
for script in vless-menu trojan-menu noobz-menu ss-menu; do
    cat > /usr/local/bin/$script << 'EOF'
#!/bin/bash
echo "This menu is under development"
read -p "Press enter to continue..."
menu
EOF
    chmod +x /usr/local/bin/$script
done

# Create utility scripts
cat > /usr/local/bin/restart-services << 'EOF'
#!/bin/bash
echo "Restarting all services..."
systemctl restart ssh
systemctl restart nginx  
systemctl restart xray
systemctl restart dropbear
systemctl restart openvpn@server
systemctl restart shadowsocks-libev
systemctl restart noobzvpns
echo "All services restarted!"
read -p "Press enter to continue..."
menu
EOF

chmod +x /usr/local/bin/restart-services

cat > /usr/local/bin/port-info << 'EOF'
#!/bin/bash
clear
echo "╭════════════════════════════════════════════════════════════╮"
echo "│                        PORT INFO                           │"
echo "╰════════════════════════════════════════════════════════════╯"
echo "SSH         : 22"
echo "Dropbear    : 109, 143, 69"
echo "SSL/TLS     : 443, 777"
echo "OpenVPN     : 1194 (UDP)"
echo "Squid       : 3128, 8080"
echo "VMESS WS    : 443"
echo "VLESS WS    : 8443"
echo "Trojan WS   : 9443"
echo "Shadowsocks : 8388"
echo "NoobzVPN    : 8080 (TCP), 8443 (SSL)"
echo ""
read -p "Press enter to continue..."
menu
EOF

chmod +x /usr/local/bin/port-info

# Save domain
echo "$DOMAIN" > /etc/xray/domain

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Configure iptables
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables-save > /etc/iptables.rules

# Create iptables restore script
cat > /etc/systemd/system/iptables-restore.service << EOF
[Unit]
Description=Restore iptables rules
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables.rules
RemainAfterExit=yes

# Lanjutan dari script sebelumnya...

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
echo -e "${YELLOW}Starting services...${NC}"
systemctl daemon-reload
systemctl enable ssh
systemctl enable nginx
systemctl enable xray
systemctl enable dropbear
systemctl enable openvpn@server
systemctl enable shadowsocks-libev
systemctl enable noobzvpns
systemctl enable iptables-restore

systemctl start ssh
systemctl start nginx
systemctl start xray
systemctl start dropbear
systemctl start openvpn@server
systemctl start shadowsocks-libev
systemctl start noobzvpns
systemctl start iptables-restore

# Create web interface
mkdir -p /var/www/html
cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>VPN Server</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; text-align: center; padding: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #00ff88; }
        .info { background: #333; padding: 20px; border-radius: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>VPN Server Active</h1>
        <div class="info">
            <h3>Server Information</h3>
            <p>Domain: $DOMAIN</p>
            <p>Server IP: $MYIP</p>
            <p>Status: Online</p>
        </div>
        <div class="info">
            <h3>Available Services</h3>
            <p>SSH/OpenVPN/Dropbear: Active</p>
            <p>VMESS/VLESS/Trojan: Active</p>
            <p>Shadowsocks: Active</p>
            <p>NoobzVPN: Active</p>
        </div>
    </div>
</body>
</html>
EOF

# Create additional utility scripts
cat > /usr/local/bin/running-services << 'EOF'
#!/bin/bash
clear
echo "╭════════════════════════════════════════════════════════════╮"
echo "│                    RUNNING SERVICES                        │"
echo "╰════════════════════════════════════════════════════════════╯"
echo ""
services=("ssh" "nginx" "xray" "dropbear" "openvpn@server" "shadowsocks-libev" "noobzvpns")
for service in "${services[@]}"; do
    status=$(systemctl is-active $service)
    if [[ $status == "active" ]]; then
        echo -e "[$service] : \033[0;32mRUNNING\033[0m"
    else
        echo -e "[$service] : \033[0;31mSTOPPED\033[0m"
    fi
done
echo ""
read -p "Press enter to continue..."
menu
EOF

chmod +x /usr/local/bin/running-services

cat > /usr/local/bin/change-domain << 'EOF'
#!/bin/bash
clear
echo "Change Domain"
echo ""
read -p "Enter new domain: " new_domain

if [[ -z "$new_domain" ]]; then
    echo "Domain cannot be empty!"
    exit 1
fi

# Update domain file
echo "$new_domain" > /etc/xray/domain

# Generate new certificates
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$new_domain" \
    -keyout /etc/xray/tls/server.key \
    -out /etc/xray/tls/server.crt

# Update nginx config
sed -i "s/server_name .*/server_name $new_domain;/g" /etc/nginx/sites-available/default

# Restart services
systemctl restart nginx
systemctl restart xray

echo "Domain changed to: $new_domain"
read -p "Press enter to continue..."
menu
EOF

chmod +x /usr/local/bin/change-domain

cat > /usr/local/bin/backup-restore << 'EOF'
#!/bin/bash
clear
echo "╭════════════════════════════════════════════════════════════╮"
echo "│                    BACKUP & RESTORE                        │"
echo "╰════════════════════════════════════════════════════════════╯"
echo ""
echo "[1] Backup Data"
echo "[2] Restore Data"
echo "[0] Back to Menu"
echo ""
read -p "Select option: " backup_option

case $backup_option in
    1)
        echo "Creating backup..."
        mkdir -p /root/backup
        tar -czf /root/backup/backup-$(date +%Y%m%d-%H%M%S).tar.gz \
            /etc/xray \
            /etc/vmess \
            /etc/vless \
            /etc/trojan \
            /etc/shadowsocks \
            /etc/ssh-clients \
            /etc/passwd \
            /etc/shadow
        echo "Backup created in /root/backup/"
        ;;
    2)
        echo "Available backups:"
        ls -la /root/backup/*.tar.gz 2>/dev/null || echo "No backups found"
        ;;
    0)
        menu
        ;;
esac
read -p "Press enter to continue..."
menu
EOF

chmod +x /usr/local/bin/backup-restore

# Create UDP custom installer
cat > /usr/local/bin/udp-install << 'EOF'
#!/bin/bash
echo "Installing UDP Custom..."

# Download and install UDP custom
cd /tmp
wget -O udp-custom.tar.gz "https://github.com/Apeachsan91/udp/releases/download/1.4.9/udp-custom-linux-amd64.tar.gz"
tar -xf udp-custom.tar.gz
mv udp-custom /usr/local/bin/
chmod +x /usr/local/bin/udp-custom

# Create config
cat > /etc/udp-custom.json << EOL
{
    "listen": ":36712",
    "stream_buffer": 33554432,
    "receive_buffer": 83886080,
    "auth": {
        "mode": "passwords",
        "config": {
            "passwords": ["tes", "tes2"]
        }
    }
}
EOL

# Create systemd service
cat > /etc/systemd/system/udp-custom.service << EOL
[Unit]
Description=UDP Custom
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udp-custom -c /etc/udp-custom.json
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable udp-custom
systemctl start udp-custom

echo "UDP Custom installed successfully!"
read -p "Press enter to continue..."
menu
EOF

chmod +x /usr/local/bin/udp-install

# Create bot menu (placeholder)
cat > /usr/local/bin/bot-menu << 'EOF'
#!/bin/bash
clear
echo "╭════════════════════════════════════════════════════════════╮"
echo "│                      TELEGRAM BOT                          │"
echo "╰════════════════════════════════════════════════════════════╯"
echo ""
echo "Bot features:"
echo "- Auto create accounts"
echo "- Check account status"
echo "- Account management"
echo ""
echo "To setup bot, you need:"
echo "1. Telegram Bot Token"
echo "2. Admin Chat ID"
echo ""
echo "This feature is under development"
read -p "Press enter to continue..."
menu
EOF

chmod +x /usr/local/bin/bot-menu

# Create remaining menu scripts
for script in delete-ssh extend-ssh check-ssh list-ssh lock-ssh unlock-ssh; do
    cat > /usr/local/bin/$script << 'EOF'
#!/bin/bash
echo "This feature is under development"
read -p "Press enter to continue..."
ssh-menu
EOF
    chmod +x /usr/local/bin/$script
done

# Create speedtest script
cat > /usr/local/bin/speedtest-cli << 'EOF'
#!/bin/bash
echo "Installing speedtest..."
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash
apt-get install speedtest -y
echo "Running speedtest..."
speedtest
read -p "Press enter to continue..."
menu
EOF

chmod +x /usr/local/bin/speedtest-cli

# Create update script
cat > /usr/local/bin/update-script << 'EOF'
#!/bin/bash
echo "Updating script..."
cd /tmp
wget -O update.sh "https://raw.githubusercontent.com/your-repo/vpn-script/main/update.sh"
chmod +x update.sh
./update.sh
EOF

chmod +x /usr/local/bin/update-script

# Create remaining utility scripts
for script in fix-cert change-banner restart-banner extract-menu; do
    cat > /usr/local/bin/$script << 'EOF'
#!/bin/bash
echo "This feature is under development"
read -p "Press enter to continue..."
menu
EOF
    chmod +x /usr/local/bin/$script
done

# Set up cron jobs for account expiry check
cat > /usr/local/bin/check-expired << 'EOF'
#!/bin/bash
# Check expired SSH accounts
while IFS=':' read -r username password expiry; do
    if [[ $(date -d "$expiry" +%s) -lt $(date +%s) ]]; then
        userdel -f "$username" 2>/dev/null
        sed -i "/^$username:/d" /etc/ssh-clients/clients.txt
    fi
done < /etc/ssh-clients/clients.txt

# Check expired VMESS accounts  
while IFS=':' read -r username uuid expiry; do
    if [[ $(date -d "$expiry" +%s) -lt $(date +%s) ]]; then
        sed -i "/^$username:/d" /etc/vmess/clients.txt
    fi
done < /etc/vmess/clients.txt 2>/dev/null
EOF

chmod +x /usr/local/bin/check-expired

# Add to crontab
(crontab -l 2>/dev/null; echo "0 0 * * * /usr/local/bin/check-expired") | crontab -

# Create startup script
cat > /etc/profile.d/menu.sh << 'EOF'
#!/bin/bash
if [ "$PS1" ]; then
    if [[ $EUID -eq 0 ]]; then
        echo ""
        echo "Welcome to VPN Server Management"
        echo "Type 'menu' to access the control panel"
        echo ""
    fi
fi
EOF

chmod +x /etc/profile.d/menu.sh

# Final setup
echo -e "${GREEN}Installation completed!${NC}"
echo -e "${YELLOW}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${YELLOW}│                    INSTALLATION COMPLETE                   │${NC}"
echo -e "${YELLOW}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${GREEN}Server Information:${NC}"
echo -e "${CYAN}Domain/IP: $DOMAIN${NC}"
echo -e "${CYAN}SSH Port: 22${NC}"
echo -e "${CYAN}Dropbear: 109, 143, 69${NC}"
echo -e "${CYAN}SSL: 443, 777${NC}"
echo -e "${CYAN}OpenVPN: 1194${NC}"
echo -e "${CYAN}VMESS: 443${NC}"
echo -e "${CYAN}VLESS: 8443${NC}"
echo -e "${CYAN}Trojan: 9443${NC}"
echo -e "${CYAN}Shadowsocks: 8388${NC}"
echo -e "${CYAN}NoobzVPN: 8080, 8443${NC}"
echo ""
echo -e "${YELLOW}Type 'menu' to access control panel${NC}"
echo -e "${YELLOW}Reboot recommended after installation${NC}"
echo ""

# Create reboot prompt
read -p "Reboot now? (y/n): " reboot_choice
if [[ $reboot_choice == "y" || $reboot_choice == "Y" ]]; then
    reboot
fi
