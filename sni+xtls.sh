#!/bin/bash

echo "----------------------------------------------------------------------------------------------------------------------------------------------"
echo
echo "   该脚本用于快速安装nginx+sni+xtls,仅供测试"
echo
echo "----------------------------------------------------------------------------------------------------------------------------------------------"
sleep 2

# Check if user is root
if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this script, please use root to install"
    exit 1
fi

# Check os
source /etc/os-release
if [ "$ID" == "debian" ] || [ "$ID" == "ubuntu" ] || [ "$ID" == "centos" ];then
  echo -e "你的系统版本为$ID，可以继续"
else 
  echo -e "${red}未支持该系统版本，请联系脚本作者！${plain}\n" && exit 1
fi
sleep 1

echo
echo "正在清除影响因素..."
sleep 1
rm -rf /etc/nginx/conf.d/h5ai.conf
rm -rf /usr/local/etc/xray && rm -rf /etc/systemd/system/xray* && rm -rf /usr/local/bin/xray
rm -rf /html/we.dog
echo "已清理完成！"
sleep 1

read -p "请输入域名（保证域名已解析到本机） :" DOMIN
echo -e "\n"
echo "域名为:$DOMIN"

UUID=$(cat /proc/sys/kernel/random/uuid)

echo
echo "正在配置中..."
sleep 1

if [ "$ID" == "centos" ] ; then
setenforce 0
iptables -F && iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables-save
systemctl stop firewalld && systemctl disable firewalld
yum -y install net-tools
kill -9 $(netstat -nlp | grep :443 | awk '{print $7}' | awk -F"/" '{ print $1 }')
kill -9 $(netstat -nlp | grep :80 | awk '{print $7}' | awk -F"/" '{ print $1 }')
kill -9 $(netstat -nlp | grep :40000 | awk '{print $7}' | awk -F"/" '{ print $1 }')
yum -y install epel-release && yum install wget git nginx nginx-mod-stream certbot curl -y && rm -rf /html/* && mkdir -p /html/we.dog && cd /html/we.dog && git clone https://github.com/Pearlulu/h5ai_dplayer.git && mv h5ai_dplayer/_h5ai ./ && rm -rf /etc/nginx/sites-enabled/default
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install && sed -i 's/nobody/root/g' /etc/systemd/system/xray.service
chattr -i  /etc/selinux/config && sed -i 's/enforcing/disabled/g' /etc/selinux/config && chattr +i  /etc/selinux/config
systemctl stop nginx && echo 1 | certbot certonly --standalone -d $DOMIN --agree-tos --email ppcert@gmail.com
myFile="/etc/letsencrypt/live/$DOMIN/fullchain.pem"
if [ ! -f "$myFile" ]; then
echo "----------------------------------------------------------------------------------------------------------------------------------------------"
echo
echo "你的证书申请失败，如果域名刚解析到本机，请等几分钟后继续申请，若为控制面板80、443端口未开，请开启后继续！！！"
echo
echo "----------------------------------------------------------------------------------------------------------------------------------------------"
sleep 2
exit 1
fi
else
iptables -F && iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables-save
systemctl stop ufw && systemctl disable ufw
apt update
apt install net-tools -y
kill -9 $(netstat -nlp | grep :443 | awk '{print $7}' | awk -F"/" '{ print $1 }')
kill -9 $(netstat -nlp | grep :80 | awk '{print $7}' | awk -F"/" '{ print $1 }')
kill -9 $(netstat -nlp | grep :40000 | awk '{print $7}' | awk -F"/" '{ print $1 }')
apt install wget git nginx certbot curl -y && rm -rf /html/* && mkdir -p /html/we.dog && cd /html/we.dog && git clone https://github.com/Pearlulu/h5ai_dplayer.git && mv h5ai_dplayer/_h5ai ./ && rm -rf /etc/nginx/sites-enabled/default
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install && sed -i 's/nobody/root/g' /etc/systemd/system/xray.service
systemctl stop nginx && echo 1 | certbot certonly --standalone -d $DOMIN --agree-tos --email ppcert@gmail.com
myFile="/etc/letsencrypt/live/$DOMIN/fullchain.pem"
if [ ! -f "$myFile" ]; then
echo "----------------------------------------------------------------------------------------------------------------------------------------------"
echo
echo "你的证书申请失败，如果域名刚解析到本机，请等几分钟后继续申请，若为控制面板80、443端口未开，请开启后继续！！！"
echo
echo "----------------------------------------------------------------------------------------------------------------------------------------------"
sleep 2
exit 1
fi
fi
sleep 1
# 安装php
if [ "$ID" == "centos" ] ; then
echo "centos安装php建议编译！3s考虑清楚退出"
sleep 4
yum install http://rpms.remirepo.net/enterprise/remi-release-7.rpm -y
yum -y install yum-utils && yum-config-manager --disable "remi-php*" && yum-config-manager --enable remi-php74 && yum install php-fpm php-mysql php-common php-curl php-cli php-mbstring php-xml -y && systemctl restart php-fpm && systemctl enable php-fpm
else
apt install php-fpm php-mysql php-common php-curl php-cli php-mbstring php-xml -y &&  sed -i '80i listen = 127.0.0.1:9000' /etc/php/*/fpm/pool.d/www.conf && systemctl restart php*
fi

echo
echo "已配置完成，正在写入config..."
sleep 1
cat >> /etc/nginx/nginx.conf <<EOF
stream {
    map \$ssl_preread_server_name \$backend_name {
        $DOMIN h5ai;
        default h5ai;
    }
    upstream h5ai {
        server 127.0.0.1:40000;
    }
    server {
        listen 443 reuseport;
        listen [::]:443 reuseport;
        proxy_pass  \$backend_name;
        ssl_preread on;
    }
}
EOF

sleep 1
cat > /etc/nginx/conf.d/h5ai.conf <<"EOF"
server { 
                listen 127.0.0.1:39999;  
                root /html/we.dog; 
 index index.html index.htm index.nginx-debian.html index.php /_h5ai/public/index.php;
                 location ~* \.php$ {
                    fastcgi_index   index.php;
                    fastcgi_pass    127.0.0.1:9000;
                    include         fastcgi_params;
                    fastcgi_param   SCRIPT_FILENAME    $document_root$fastcgi_script_name;
                    fastcgi_param   SCRIPT_NAME        $fastcgi_script_name;
    }
} 
EOF
cat >> /etc/nginx/conf.d/h5ai.conf <<EOF
server { 
        return 301 https://$DOMIN; 
                listen 80; 
                server_name $DOMIN; 
}
EOF

sleep 1
cat > /usr/local/etc/xray/config.json <<EOF
{
    "log": {
        "loglevel": "warning"
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:cn"
                ],
                "outboundTag": "block"
            }
        ]
    },
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 40000,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                               {
                        "dest": 39999,
                        "alpn": "h2"
                      }
                    ]
                },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMIN/privkey.pem"
                        }
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }            
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ]
}
EOF

echo
echo "已写入完成，正在启动与设置证书自更"
sleep 2
systemctl daemon-reload && systemctl restart xray && systemctl enable xray && systemctl restart nginx
systemctl enable nginx && touch cronfile && echo '15 2 * */2 * root certbot renew --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"' > ./cronfile && crontab -u root ./cronfile
sleep 1
wget -N --no-check-certificate -q -O /html/we.dog/$UUID.yaml "https://raw.githubusercontent.com/huahsui/sni-h5ai-xtls/main/clash.yaml" && sed -i '32 i\  - {name: tcp+xtls, server: '$DOMIN', port: 443, type: vless, uuid: '$UUID', flow: xtls-rprx-vision, skip-cert-verify: false, servername: '$DOMIN'}' /html/we.dog/$UUID.yaml
sleep 1
clear

# 开启bbr
if [ "$ID" == "debian" ] || [ "$ID" == "ubuntu" ];then
sed -i '/net\.core\.default_qdisc=fq/d' /etc/sysctl.conf
sed -i '/net\.ipv4\.tcp_congestion_control=bbr/d' /etc/sysctl.conf
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
echo "   你的bbr已启用"
else 
echo -e "${red}未支持该系统版本，bbr启动失败，请自行启动！！！${plain}\n"
fi
sleep 2

cat > /html/client.json <<EOF
{
    "log": {
        "loglevel": "warning"
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "domain": [
                    "geosite:cn",
                    "geosite:private"
                ],
                "outboundTag": "direct"
            },
            {
                "type": "field",
                "ip": [
                    "geoip:cn",
                    "geoip:private"
                ],
                "outboundTag": "direct"
            }
        ]
    },
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {
                "udp": true
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        },
        {
            "listen": "127.0.0.1",
            "port": 10809,
            "protocol": "http",
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "$DOMIN",
                        "port": 443,
                        "users": [
                            {
                                "id": "$UUID",
                                "encryption": "none",
                                "flow": "xtls-rprx-vision"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "$DOMIN",
                    "allowInsecure": false,
                    "fingerprint": "chrome"
                }
            },
            "tag": "proxy"
        },
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF

echo
echo
echo "   恭喜，你的tcp+xtls已配置成功 "
echo
echo "----------------------------------------------------------------------------------------------------------------------------------------------"
echo
echo
echo "   客户端配置文件在 https://$DOMIN/client.json 请直接下载并在xray最新内核中使用,或使用v2rayN使用自定义配置 "
echo
echo "   你的h5ai的账号和密码都是admin,记得上 /html/we.dog/_h5ai/public/login.php 修改 "
echo
echo "----------------------------------------------------------------------------------------------------------------------------------------------"
echo
# END
