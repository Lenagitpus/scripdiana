#!/bin/bash
# Auto Installer VPN Multi-Protocol with Full Cloudflare Support
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

clear

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Banner
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│                VPN AUTO INSTALLER + CLOUDFLARE             │${NC}"
echo -e "${CYAN}│                  HAPPY NEW YEAR 2025                      │${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo ""

# Get server information
MYIP=$(curl -sS ipv4.icanhazip.com)
DOMAIN=""

echo -e "${YELLOW}╭═══════════════════════════════════════════════════════════╮${NC}"
echo -e "${YELLOW}│                    DOMAIN CONFIGURATION                   │${NC}"
echo -e "${YELLOW}╰═══════════════════════════════════════════════════════════╯${NC}"
echo -e "${CYAN}[1] Use Cloudflare Domain (Recommended)${NC}"
echo -e "${CYAN}[2] Use Custom Domain${NC}"
echo -e "${CYAN}[3] Use Server IP Only${NC}"
echo ""
read -p "Select option [1-3]: " domain_choice

case $domain_choice in
    1)
        echo -e "${YELLOW}Cloudflare Domain Setup${NC}"
        echo -e "${GREEN}Benefits: CDN, DDoS Protection, SSL, Better Performance${NC}"
        echo ""
        read -p "Enter your Cloudflare domain: " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            echo -e "${RED}Domain is required for Cloudflare setup!${NC}"
            exit 1
        fi
        USE_CLOUDFLARE=true
        ;;
    2)
        echo -e "${YELLOW}Custom Domain Setup${NC}"
        read -p "Enter your domain: " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            DOMAIN=$MYIP
        fi
        USE_CLOUDFLARE=false
        ;;
    3)
        DOMAIN=$MYIP
        USE_CLOUDFLARE=false
        echo -e "${YELLOW}Using server IP: $DOMAIN${NC}"
        ;;
    *)
        DOMAIN=$MYIP
        USE_CLOUDFLARE=false
        ;;
esac

echo -e "${GREEN}Domain configured: $DOMAIN${NC}"
echo -e "${GREEN}Cloudflare: $([ "$USE_CLOUDFLARE" = true ] && echo "Enabled" || echo "Disabled")${NC}"
sleep 3

# Update system
echo -e "${YELLOW}Updating system...${NC}"
apt update -y && apt upgrade -y
apt install -y wget curl nano zip unzip tar gzip jq bc

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
apt install -y software-properties-common build-essential cmake
apt install -y nginx haproxy dropbear stunnel4 python3 python3-pip
apt install -y openvpn easy-rsa shadowsocks-libev htop gotop

# Create directories
mkdir -p /etc/xray/{tls,clients}
mkdir -p /etc/{vmess,vless,trojan,shadowsocks,ssh-clients}
mkdir -p /var/log/xray
mkdir -p /root/backup
mkdir -p /etc/bot

# Install Xray
echo -e "${YELLOW}Installing Xray...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate certificates
echo -e "${YELLOW}Generating SSL certificates...${NC}"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$DOMAIN" \
    -keyout /etc/xray/tls/server.key \
    -out /etc/xray/tls/server.crt

# Generate UUIDs and passwords
VMESS_UUID=$(cat /proc/sys/kernel/random/uuid)
VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
TROJAN_PASS=$(openssl rand -base64 16)

# Configure Xray with Cloudflare-optimized settings
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
        "clients": []
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
          "path": "/Multi-Path",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      }
    },
    {
      "port": 80,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/Multi-Path",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      }
    },
    {
      "port": 8080,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/Multi-Path",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      }
    },
    {
      "port": 8880,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/Multi-Path",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      }
    },
    {
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": [],
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
          "path": "/Multi-Path",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      }
    },
    {
      "port": 2082,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/Multi-Path",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      }
    },
    {
      "port": 9443,
      "protocol": "trojan",
      "settings": {
        "clients": []
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
          "path": "/Multi-Path",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      }
    },
    {
      "port": 2083,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/Multi-Path",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      }
    },
    {
      "port": 2096,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/tls/server.crt",
              "keyFile": "/etc/xray/tls/server.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "vmess-grpc"
        }
      }
    },
    {
      "port": 2087,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/tls/server.crt",
              "keyFile": "/etc/xray/tls/server.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "vless-grpc"
        }
      }
    },
    {
      "port": 2053,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/tls/server.crt",
              "keyFile": "/etc/xray/tls/server.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "trojan-grpc"
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

# Configure Nginx for Cloudflare
if [ "$USE_CLOUDFLARE" = true ]; then
cat > /etc/nginx/sites-available/default << EOF
# Cloudflare real IP restoration
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
real_ip_header CF-Connecting-IP;

server {
    listen 80;
    server_name $DOMAIN;
    
    location /Multi-Path {
        proxy_pass http://127.0.0.1:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location / {
        root /var/www/html;
        index index.html;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/xray/tls/server.crt;
    ssl_certificate_key /etc/xray/tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    
    location /Multi-Path {
        proxy_pass https://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_ssl_verify off;
    }
    
    location / {
        root /var/www/html;
        index index.html;
    }
}
EOF
else
cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location /Multi-Path {
        proxy_pass http://127.0.0.1:80;
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

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/xray/tls/server.crt;
    ssl_certificate_key /etc/xray/tls/server.key;
    
    location /Multi-Path {
        proxy_pass https://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_ssl_verify off;
    }
    
    location / {
        root /var/www/html;
        index index.html;
    }
}
EOF
fi

# Configure Dropbear
echo -e "${YELLOW}Configuring Dropbear...${NC}"
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
echo 'DROPBEAR_EXTRA_ARGS="-p 109 -p 69"' >> /etc/default/dropbear

# Configure OpenVPN
echo -e "${YELLOW}Configuring OpenVPN...${NC}"
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

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

cat > /etc/noobzvpns.json << EOF
{
    "tcp_std": [8080],
    "tcp_ssl": [8443],
    "ssl_cert": "/etc/xray/tls/server.crt",
    "ssl_key": "/etc/xray/tls/server.key",
    "ssl_version": "AUTO"
}
EOF

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

# Install SlowDNS
echo -e "${YELLOW}Installing SlowDNS...${NC}"
cd /tmp
wget -O slowdns.tar.gz "https://github.com/fisabiliyusri/SlowDNS/releases/download/1.0/slowdns-linux-amd64.tar.gz"
tar -xf slowdns.tar.gz
mv slowdns /usr/local/bin/
chmod +x /usr/local/bin/slowdns

# Generate SlowDNS keys
slowdns-keygen > /etc/slowdns/keys.txt
SLOWDNS_PUBKEY=$(cat /etc/slowdns/keys.txt | grep "Public Key" | cut -d: -f2 | tr -d ' ')
SLOWDNS_PRIVKEY=$(cat /etc/slowdns/keys.txt | grep "Private Key" | cut -d: -f2 | tr -d ' ')

# Create SlowDNS configs for multiple ports
for port in 443 80 8080 53 5300; do
cat > /etc/slowdns/slowdns-$port.conf << EOF
{
    "server": "0.0.0.0:$port",
    "private_key": "$SLOWDNS_PRIVKEY",
    "upstream": "8.8.8.8:53"
}
EOF

cat > /etc/systemd/system/slowdns-$port.service << EOF
[Unit]
Description=SlowDNS Server Port $port
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/slowdns -c /etc/slowdns/slowdns-$port.conf
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
done

# Install UDP Custom
echo -e "${YELLOW}Installing UDP Custom...${NC}"
cd /tmp
wget -O udp-custom.tar.gz "https://github.com/Apeachsan91/udp/releases/download/1.4.9/udp-custom-linux-amd64.tar.gz"
tar -xf udp-custom.tar.gz
mv udp-custom /usr/local/bin/
chmod +x /usr/local/bin/udp-custom

cat > /etc/udp-custom.json << EOF
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
EOF

cat > /etc/systemd/system/udp-custom.service << EOF
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
EOF

# Create improved SSH account creator with proper formatting
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
mkdir -p /etc/ssh-clients
echo "$username:$password:$(date -d "$days days" +"%Y-%m-%d")" >> /etc/ssh-clients/clients.txt

# Get server info
DOMAIN=$(cat /etc/xray/domain 2>/dev/null || curl -sS ipv4.icanhazip.com)
SLOWDNS_PUBKEY=$(cat /etc/slowdns/keys.txt 2>/dev/null | grep "Public Key" | cut -d: -f2 | tr -d ' ' || echo "N/A")

clear
echo -e "${GREEN}SSH ACCOUNT${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW} Username         : $username${NC}"
echo -e "${YELLOW} Password         : $password${NC}"
echo -e "${YELLOW} Expired          : $(date -d "$days days" +"%d %b, %Y")${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}SERVER INFORMATION${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}IP           : $MYIP${NC}"
echo -e "${YELLOW}Host         : $DOMAIN${NC}"
echo -e "${YELLOW}OpenSSH      : 22${NC}"
echo -e "${YELLOW}SSH-WS       : 80${NC}"
echo -e "${YELLOW}SSH-SSL-WS   : 443${NC}"
echo -e "${YELLOW}Dropbear     : 109, 143${NC}"
echo -e "${YELLOW}SSL/TLS      : 447 , 777${NC}"
echo -e "${YELLOW}SlowDNS      : 443,80,8080,53,5300${NC}"
echo -e "${YELLOW}UDPGW        : 7100-7300${NC}"
echo -e "${YELLOW}UDP CUSTOM   : 1-65535${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Nameserver   : $DOMAIN${NC}"
echo -e "${YELLOW}PubKey       : $SLOWDNS_PUBKEY${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}SLOWDNS-443  : $DOMAIN:443@$username:$password${NC}"
echo -e "${YELLOW}SLOWDNS-80   : $DOMAIN:80@$username:$password${NC}"
echo -e "${YELLOW}SLOWDNS-8080 : $DOMAIN:8080@$username:$password${NC}"
echo -e "${YELLOW}SLOWDNS-53   : $DOMAIN:53@$username:$password${NC}"
echo -e "${YELLOW}SLOWDNS-5300 : $DOMAIN:5300@$username:$password${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}SSH-80       : $DOMAIN:80@$username:$password${NC}"
echo -e "${YELLOW}SSH-443      : $DOMAIN:443@$username:$password${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}UDP CUSTOM   : $DOMAIN:1-65535@$username:$password${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Payload 1    : GET wss://bug.com [protocol][crlf]Host: $DOMAIN[crlf]Upgrade: websocket[crlf][crlf]${NC}"
echo -e "${YELLOW}Payload 2    : GET / HTTP/1.1[crlf]Host: $DOMAIN[crlf]Upgrade: websocket[crlf][crlf]${NC}"
echo -e "${YELLOW}Payload 3    : GET / HTTP/1.1[crlf]Host: bug.com.$DOMAIN[crlf]Upgrade: websocket[crlf][crlf]${NC}"
echo ""
read -p "Press enter to continue..."
ssh-menu
EOF

chmod +x /usr/local/bin/create-ssh

# Create improved VMESS account creator with proper formatting
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

# Add client to Xray config
jq --arg id "$uuid" '.inbounds[0].settings.clients += [{"id": $id, "alterId": 0}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[1].settings.clients += [{"id": $id, "alterId": 0}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[2].settings.clients += [{"id": $id, "alterId": 0}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[3].settings.clients += [{"id": $id, "alterId": 0}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[8].settings.clients += [{"id": $id, "alterId": 0}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json

# Save to client list
mkdir -p /etc/vmess
echo "$username:$uuid:$exp_date" >> /etc/vmess/clients.txt

# Get domain
DOMAIN=$(cat /etc/xray/domain 2>/dev/null || curl -sS ipv4.icanhazip.com)

# Create VMESS configs
# Create VMESS configs
vmess_tls_config="{
  \"v\": \"2\",
  \"ps\": \"$username\",
  \"add\": \"$DOMAIN\",
  \"port\": \"443\",
  \"id\": \"$uuid\",
  \"aid\": \"0\",
  \"net\": \"ws\",
  \"path\": \"/Multi-Path\",
  \"type\": \"none\",
  \"host\": \"$DOMAIN\",
  \"tls\": \"tls\"
}"

vmess_ntls_config="{
  \"v\": \"2\",
  \"ps\": \"$username\",
  \"add\": \"$DOMAIN\",
  \"port\": \"80\",
  \"id\": \"$uuid\",
  \"aid\": \"0\",
  \"net\": \"ws\",
  \"path\": \"/Multi-Path\",
  \"type\": \"none\",
  \"host\": \"$DOMAIN\",
  \"tls\": \"none\"
}"

vmess_grpc_config="{
  \"v\": \"2\",
  \"ps\": \"$username\",
  \"add\": \"$DOMAIN\",
  \"port\": \"2096\",
  \"id\": \"$uuid\",
  \"aid\": \"0\",
  \"net\": \"grpc\",
  \"path\": \"vmess-grpc\",
  \"type\": \"none\",
  \"host\": \"$DOMAIN\",
  \"tls\": \"tls\"
}"

vmess_tls_link="vmess://$(echo -n "$vmess_tls_config" | base64 -w 0)"
vmess_ntls_link="vmess://$(echo -n "$vmess_ntls_config" | base64 -w 0)"
vmess_grpc_link="vmess://$(echo -n "$vmess_grpc_config" | base64 -w 0)"

# Create OpenClash config
mkdir -p /var/www/html/configs
cat > /var/www/html/configs/vmess-$username.txt << EOL
proxies:
  - name: "$username-WS-TLS"
    type: vmess
    server: $DOMAIN
    port: 443
    uuid: $uuid
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /Multi-Path
      headers:
        Host: $DOMAIN
        
  - name: "$username-WS-NTLS"
    type: vmess
    server: $DOMAIN
    port: 80
    uuid: $uuid
    alterId: 0
    cipher: auto
    tls: false
    network: ws
    ws-opts:
      path: /Multi-Path
      headers:
        Host: $DOMAIN
        
  - name: "$username-GRPC"
    type: vmess
    server: $DOMAIN
    port: 2096
    uuid: $uuid
    alterId: 0
    cipher: auto
    tls: true
    network: grpc
    grpc-opts:
      grpc-service-name: vmess-grpc
EOL

# Restart Xray
systemctl restart xray

clear
echo -e "${GREEN}VMESS ACCOUNT${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW} Remarks          : $username${NC}"
echo -e "${YELLOW} Domain           : $DOMAIN${NC}"
echo -e "${YELLOW} Port TLS         : 443${NC}"
echo -e "${YELLOW} Port none TLS    : 80, 8080, 8880${NC}"
echo -e "${YELLOW} id               : $uuid${NC}"
echo -e "${YELLOW} alterId          : 0${NC}"
echo -e "${YELLOW} Security         : auto${NC}"
echo -e "${YELLOW} Network          : ws${NC}"
echo -e "${YELLOW} Path             : /Multi-Path${NC}"
echo -e "${YELLOW} Dynamic          : https://bugmu.com/path${NC}"
echo -e "${YELLOW} ServiceName      : vmess-grpc${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} VMESS WS ACCOUNT${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$vmess_tls_link${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} VMESS NONTLS ACCOUNT${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$vmess_ntls_link${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} VMESS GRPC ACCOUNT${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$vmess_grpc_link${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} Format OpenClash : https://$DOMAIN:81/configs/vmess-$username.txt${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} Exp Until    : $(date -d "$days days" +"%d %b, %Y")${NC}"
echo ""
read -p "Press enter to continue..."
vmess-menu
EOF

chmod +x /usr/local/bin/create-vmess
# Create VLESS account creator
cat > /usr/local/bin/create-vless << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${GREEN}Create VLESS Account${NC}"
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

# Add client to Xray config
jq --arg id "$uuid" '.inbounds[4].settings.clients += [{"id": $id}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[5].settings.clients += [{"id": $id}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[9].settings.clients += [{"id": $id}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json

# Save to client list
mkdir -p /etc/vless
echo "$username:$uuid:$exp_date" >> /etc/vless/clients.txt

# Get domain
DOMAIN=$(cat /etc/xray/domain 2>/dev/null || curl -sS ipv4.icanhazip.com)

# Create VLESS links
vless_tls_link="vless://$uuid@$DOMAIN:8443?encryption=none&security=tls&type=ws&host=$DOMAIN&path=%2FMulti-Path#$username-TLS"
vless_ntls_link="vless://$uuid@$DOMAIN:2082?encryption=none&security=none&type=ws&host=$DOMAIN&path=%2FMulti-Path#$username-NTLS"
vless_grpc_link="vless://$uuid@$DOMAIN:2087?encryption=none&security=tls&type=grpc&serviceName=vless-grpc#$username-GRPC"

# Create OpenClash config
mkdir -p /var/www/html/configs
cat > /var/www/html/configs/vless-$username.txt << EOL
proxies:
  - name: "$username-WS-TLS"
    type: vless
    server: $DOMAIN
    port: 8443
    uuid: $uuid
    tls: true
    network: ws
    ws-opts:
      path: /Multi-Path
      headers:
        Host: $DOMAIN
        
  - name: "$username-WS-NTLS"
    type: vless
    server: $DOMAIN
    port: 2082
    uuid: $uuid
    tls: false
    network: ws
    ws-opts:
      path: /Multi-Path
      headers:
        Host: $DOMAIN
        
  - name: "$username-GRPC"
    type: vless
    server: $DOMAIN
    port: 2087
    uuid: $uuid
    tls: true
    network: grpc
    grpc-opts:
      grpc-service-name: vless-grpc
EOL

# Restart Xray
systemctl restart xray

clear
echo -e "${GREEN}VLESS ACCOUNT${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW} Remarks          : $username${NC}"
echo -e "${YELLOW} Domain           : $DOMAIN${NC}"
echo -e "${YELLOW} Port TLS         : 8443${NC}"
echo -e "${YELLOW} Port none TLS    : 2082${NC}"
echo -e "${YELLOW} Port GRPC        : 2087${NC}"
echo -e "${YELLOW} id               : $uuid${NC}"
echo -e "${YELLOW} Encryption       : none${NC}"
echo -e "${YELLOW} Network          : ws${NC}"
echo -e "${YELLOW} Path             : /Multi-Path${NC}"
echo -e "${YELLOW} ServiceName      : vless-grpc${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} VLESS WS TLS${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$vless_tls_link${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} VLESS WS NTLS${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$vless_ntls_link${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} VLESS GRPC${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$vless_grpc_link${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} Format OpenClash : https://$DOMAIN:81/configs/vless-$username.txt${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} Exp Until    : $(date -d "$days days" +"%d %b, %Y")${NC}"
echo ""
read -p "Press enter to continue..."
vless-menu
EOF

chmod +x /usr/local/bin/create-vless

# Create TROJAN account creator
cat > /usr/local/bin/create-trojan << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${GREEN}Create TROJAN Account${NC}"
echo ""

read -p "Username: " username
read -p "Expired (days): " days

if [[ -z "$username" || -z "$days" ]]; then
    echo -e "${RED}All fields are required!${NC}"
    exit 1
fi

# Generate password
password=$(openssl rand -base64 16)
exp_date=$(date -d "$days days" +"%Y-%m-%d")

# Add client to Xray config
jq --arg pass "$password" '.inbounds[6].settings.clients += [{"password": $pass}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg pass "$password" '.inbounds[7].settings.clients += [{"password": $pass}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg pass "$password" '.inbounds[10].settings.clients += [{"password": $pass}]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json

# Save to client list
mkdir -p /etc/trojan
echo "$username:$password:$exp_date" >> /etc/trojan/clients.txt

# Get domain
DOMAIN=$(cat /etc/xray/domain 2>/dev/null || curl -sS ipv4.icanhazip.com)

# Create TROJAN links
trojan_tls_link="trojan://$password@$DOMAIN:9443?security=tls&type=ws&host=$DOMAIN&path=%2FMulti-Path#$username-TLS"
trojan_ntls_link="trojan://$password@$DOMAIN:2083?security=none&type=ws&host=$DOMAIN&path=%2FMulti-Path#$username-NTLS"
trojan_grpc_link="trojan://$password@$DOMAIN:2053?security=tls&type=grpc&serviceName=trojan-grpc#$username-GRPC"

# Create OpenClash config
mkdir -p /var/www/html/configs
cat > /var/www/html/configs/trojan-$username.txt << EOL
proxies:
  - name: "$username-WS-TLS"
    type: trojan
    server: $DOMAIN
    port: 9443
    password: $password
    sni: $DOMAIN
    network: ws
    ws-opts:
      path: /Multi-Path
      headers:
        Host: $DOMAIN
        
  - name: "$username-WS-NTLS"
    type: trojan
    server: $DOMAIN
    port: 2083
    password: $password
    network: ws
    ws-opts:
      path: /Multi-Path
      headers:
        Host: $DOMAIN
        
  - name: "$username-GRPC"
    type: trojan
    server: $DOMAIN
    port: 2053
    password: $password
    sni: $DOMAIN
    network: grpc
    grpc-opts:
      grpc-service-name: trojan-grpc
EOL

# Restart Xray
systemctl restart xray

clear
echo -e "${GREEN}TROJAN ACCOUNT${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW} Remarks          : $username${NC}"
echo -e "${YELLOW} Domain           : $DOMAIN${NC}"
echo -e "${YELLOW} Port TLS         : 9443${NC}"
echo -e "${YELLOW} Port none TLS    : 2083${NC}"
echo -e "${YELLOW} Port GRPC        : 2053${NC}"
echo -e "${YELLOW} Password         : $password${NC}"
echo -e "${YELLOW} Network          : ws${NC}"
echo -e "${YELLOW} Path             : /Multi-Path${NC}"
echo -e "${YELLOW} ServiceName      : trojan-grpc${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} TROJAN WS TLS${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$trojan_tls_link${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} TROJAN WS NTLS${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$trojan_ntls_link${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} TROJAN GRPC${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$trojan_grpc_link${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} Format OpenClash : https://$DOMAIN:81/configs/trojan-$username.txt${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} Exp Until    : $(date -d "$days days" +"%d %b, %Y")${NC}"
echo ""
read -p "Press enter to continue..."
trojan-menu
EOF

chmod +x /usr/local/bin/create-trojan

# Create complete VLESS menu
cat > /usr/local/bin/vless-menu << 'EOF'
#!/bin/bash

# Colors  
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│                       VLESS MENU                           │${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${YELLOW}  [1] Create VLESS Account${NC}"
echo -e "${YELLOW}  [2] Delete VLESS Account${NC}"
echo -e "${YELLOW}  [3] Extend VLESS Account${NC}"
echo -e "${YELLOW}  [4] Check VLESS Config${NC}"
echo -e "${YELLOW}  [5] List VLESS Accounts${NC}"
echo -e "${YELLOW}  [0] Back to Main Menu${NC}"
echo ""
read -p "Select option: " vless_option

case $vless_option in
    1) create-vless ;;
    2) delete-vless ;;
    3) extend-vless ;;
    4) check-vless ;;
    5) list-vless ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option${NC}" ;;
esac
EOF

chmod +x /usr/local/bin/vless-menu

# Create complete TROJAN menu
cat > /usr/local/bin/trojan-menu << 'EOF'
#!/bin/bash

# Colors  
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear
echo -e "${CYAN}╭════════════════════════════════════════════════════════════╮${NC}"
echo -e "${CYAN}│                      TROJAN MENU                           │${NC}"
echo -e "${CYAN}╰════════════════════════════════════════════════════════════╯${NC}"
echo -e "${YELLOW}  [1] Create TROJAN Account${NC}"
echo -e "${YELLOW}  [2] Delete TROJAN Account${NC}"
echo -e "${YELLOW}  [3] Extend TROJAN Account${NC}"
echo -e "${YELLOW}  [4] Check TROJAN Config${NC}"
echo -e "${YELLOW}  [5] List TROJAN Accounts${NC}"
echo -e "${YELLOW}  [0] Back to Main Menu${NC}"
echo ""
read -p "Select option: " trojan_option

case $trojan_option in
    1) create-trojan ;;
    2) delete-trojan ;;
    3) extend-trojan ;;
    4) check-trojan ;;
    5) list-trojan ;;
    0) menu ;;
    *) echo -e "${RED}Invalid option${NC}" ;;
esac
EOF

chmod +x /usr/local/bin/trojan-menu

# Create delete scripts
cat > /usr/local/bin/delete-ssh << 'EOF'
#!/bin/bash

clear
echo -e "${GREEN}Delete SSH Account${NC}"
echo ""

if [[ ! -f /etc/ssh-clients/clients.txt ]]; then
    echo -e "${RED}No SSH accounts found!${NC}"
    read -p "Press enter to continue..."
    ssh-menu
    exit 1
fi

echo -e "${YELLOW}Current SSH Accounts:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat /etc/ssh-clients/clients.txt | cut -d: -f1 | nl
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Enter username to delete: " username

if [[ -z "$username" ]]; then
    echo -e "${RED}Username cannot be empty!${NC}"
    exit 1
fi

# Check if user exists
if ! grep -q "^$username:" /etc/ssh-clients/clients.txt; then
    echo -e "${RED}User $username not found!${NC}"
    exit 1
fi

# Delete user
userdel -f "$username" 2>/dev/null
sed -i "/^$username:/d" /etc/ssh-clients/clients.txt

echo -e "${GREEN}User $username has been deleted!${NC}"
read -p "Press enter to continue..."
ssh-menu
EOF

chmod +x /usr/local/bin/delete-ssh

cat > /usr/local/bin/delete-vmess << 'EOF'
#!/bin/bash

clear
echo -e "${GREEN}Delete VMESS Account${NC}"
echo ""

if [[ ! -f /etc/vmess/clients.txt ]]; then
    echo -e "${RED}No VMESS accounts found!${NC}"
    read -p "Press enter to continue..."
    vmess-menu
    exit 1
fi

echo -e "${YELLOW}Current VMESS Accounts:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat /etc/vmess/clients.txt | cut -d: -f1 | nl
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Enter username to delete: " username

if [[ -z "$username" ]]; then
    echo -e "${RED}Username cannot be empty!${NC}"
    exit 1
fi

# Get UUID
uuid=$(grep "^$username:" /etc/vmess/clients.txt | cut -d: -f2)

if [[ -z "$uuid" ]]; then
    echo -e "${RED}User $username not found!${NC}"
    exit 1
fi

# Remove from Xray config
jq --arg id "$uuid" '.inbounds[0].settings.clients = [.inbounds[0].settings.clients[] | select(.id != $id)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[1].settings.clients = [.inbounds[1].settings.clients[] | select(.id != $id)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[2].settings.clients = [.inbounds[2].settings.clients[] | select(.id != $id)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[3].settings.clients = [.inbounds[3].settings.clients[] | select(.id != $id)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[8].settings.clients = [.inbounds[8].settings.clients[] | select(.id != $id)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json

# Remove from client list
sed -i "/^$username:/d" /etc/vmess/clients.txt

# Remove OpenClash config
rm -f /var/www/html/configs/vmess-$username.txt

# Restart Xray
systemctl restart xray

echo -e "${GREEN}VMESS account $username has been deleted!${NC}"
read -p "Press enter to continue..."
vmess-menu
EOF

chmod +x /usr/local/bin/delete-vmess

cat > /usr/local/bin/delete-vless << 'EOF'
#!/bin/bash

clear
echo -e "${GREEN}Delete VLESS Account${NC}"
echo ""

if [[ ! -f /etc/vless/clients.txt ]]; then
    echo -e "${RED}No VLESS accounts found!${NC}"
    read -p "Press enter to continue..."
    vless-menu
    exit 1
fi

echo -e "${YELLOW}Current VLESS Accounts:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat /etc/vless/clients.txt | cut -d: -f1 | nl
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Enter username to delete: " username

if [[ -z "$username" ]]; then
    echo -e "${RED}Username cannot be empty!${NC}"
    exit 1
fi

# Get UUID
uuid=$(grep "^$username:" /etc/vless/clients.txt | cut -d: -f2)

if [[ -z "$uuid" ]]; then
    echo -e "${RED}User $username not found!${NC}"
    exit 1
fi

# Remove from Xray config
jq --arg id "$uuid" '.inbounds[4].settings.clients = [.inbounds[4].settings.clients[] | select(.id != $id)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[5].settings.clients = [.inbounds[5].settings.clients[] | select(.id != $id)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg id "$uuid" '.inbounds[9].settings.clients = [.inbounds[9].settings.clients[] | select(.id != $id)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json

# Remove from client list
sed -i "/^$username:/d" /etc/vless/clients.txt

# Remove OpenClash config
rm -f /var/www/html/configs/vless-$username.txt

# Restart Xray
systemctl restart xray

echo -e "${GREEN}VLESS account $username has been deleted!${NC}"
read -p "Press enter to continue..."
vless-menu
EOF

chmod +x /usr/local/bin/delete-vless

cat > /usr/local/bin/delete-trojan << 'EOF'
#!/bin/bash

clear
echo -e "${GREEN}Delete TROJAN Account${NC}"
echo ""

if [[ ! -f /etc/trojan/clients.txt ]]; then
    echo -e "${RED}No TROJAN accounts found!${NC}"
    read -p "Press enter to continue..."
    trojan-menu
    exit 1
fi

echo -e "${YELLOW}Current TROJAN Accounts:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat /etc/trojan/clients.txt | cut -d: -f1 | nl
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Enter username to delete: " username

if [[ -z "$username" ]]; then
    echo -e "${RED}Username cannot be empty!${NC}"
    exit 1
fi

# Get password
password=$(grep "^$username:" /etc/trojan/clients.txt | cut -d: -f2)

if [[ -z "$password" ]]; then
    echo -e "${RED}User $username not found!${NC}"
    exit 1
fi

# Remove from Xray config
jq --arg pass "$password" '.inbounds[6].settings.clients = [.inbounds[6].settings.clients[] | select(.password != $pass)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg pass "$password" '.inbounds[7].settings.clients = [.inbounds[7].settings.clients[] | select(.password != $pass)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json
jq --arg pass "$password" '.inbounds[10].settings.clients = [.inbounds[10].settings.clients[] | select(.password != $pass)]' /etc/xray/config.json > /tmp/config.json && mv /tmp/config.json /etc/xray/config.json

# Remove from client list
sed -i "/^$username:/d" /etc/trojan/clients.txt

# Remove OpenClash config
rm -f /var/www/html/configs/trojan-$username.txt

# Restart Xray
systemctl restart xray

echo -e "${GREEN}TROJAN account $username has been deleted!${NC}"
read -p "Press enter to continue..."
trojan-menu
EOF

chmod +x /usr/local/bin/delete-trojan

# Create list scripts
cat > /usr/local/bin/list-ssh << 'EOF'
#!/bin/bash

clear
echo -e "${GREEN}SSH Account List${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
