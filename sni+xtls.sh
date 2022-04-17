#!/bin/bash

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

read -p "请输入域名（保证域名已解析到本机） :" DOMIN
echo -e "\n"
echo "域名为:$DOMIN"

UUID=$(cat /proc/sys/kernel/random/uuid)

echo
echo "正在配置中..."
sleep 1

if [ "$ID" == "centos" ] ; then
setenforce 0
iptables -F && iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables-save && systemctl stop firewalld && systemctl disable firewalld
yum -y install epel-release && yum install wget git nginx nginx-mod-stream certbot -y && rm -rf /html/* && mkdir -p /html/we.dog && cd /html/we.dog && git clone https://github.com/Pearlulu/h5ai_dplayer.git && mv h5ai_dplayer/_h5ai ./ && rm -rf /etc/nginx/sites-enabled/default && bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install && sed -i 's/nobody/root/g' /etc/systemd/system/xray.service
chattr -i  /etc/selinux/config && sed -i 's/enforcing/disabled/g' /etc/selinux/config && chattr +i  /etc/selinux/config
systemctl stop nginx && yes | certbot certonly --standalone -d $DOMIN --agree-tos --email ppcert@gmail.com
else
iptables -F && iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables-save && systemctl stop ufw && systemctl disable ufw
apt update && apt install wget git nginx certbot -y && rm -rf /html/* && mkdir -p /html/we.dog && cd /html/we.dog && git clone https://github.com/Pearlulu/h5ai_dplayer.git && mv h5ai_dplayer/_h5ai ./ && rm -rf /etc/nginx/sites-enabled/default && bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install && sed -i 's/nobody/root/g' /etc/systemd/system/xray.service && systemctl stop nginx && yes | certbot certonly --standalone -d $DOMIN --agree-tos --email ppcert@gmail.com
fi
sleep 1
# 安装php
if [ "$ID" == "centos" ] ; then
echo "centos安装php建议编译！3s考虑清楚退出"
sleep 4
yum install http://rpms.remirepo.net/enterprise/remi-release-7.rpm -y && yum -y install yum-utils && yum-config-manager --disable "remi-php*" && yum-config-manager --enable remi-php74 && yum install php-fpm php-mysql php-common php-curl php-cli php-mbstring php-xml -y && systemctl restart php-fpm && systemctl enable php-fpm
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
    "inbounds": [
        {
            "port": 40000,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID",
                        "flow": "xtls-rprx-direct",
                        "level": 0
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                               {
                        "dest": 39999
                      }
                    ]
                },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMIN/privkey.pem"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}
EOF

echo
echo "已写入完成，正在启动与设置证书自更"
sleep 2
systemctl daemon-reload && systemctl restart xray && systemctl enable xray && systemctl restart nginx && systemctl enable nginx && touch cronfile && echo '15 2 * */2 * root certbot renew --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"' > ./cronfile && crontab -u root ./cronfile
sleep 1
wget -N --no-check-certificate -q -O /html/we.dog/$UUID.yaml "https://raw.githubusercontent.com/huahsui/sni-h5ai-xtls/main/clash.yaml" && sed -i '32 i\  - {name: tcp+xtls, server: '$DOMIN', port: 443, type: vless, uuid: '$UUID', flow: xtls-rprx-direct, skip-cert-verify: false, servername: '$DOMIN'}' /html/we.dog/$UUID.yaml

clear
echo
echo
echo "   恭喜，你的tcp+xtls已配置成功，以下为你的clash配置"
echo
echo "----------------------------------------------------------------------------------------------------------------------------------------------"
echo "- {name: tcp+xtls, server: $DOMIN, port: 443, type: vless, uuid: $UUID, flow: xtls-rprx-direct, skip-cert-verify: false, servername: $DOMIN}"
echo
echo "   clash配置文件在 https://$DOMIN/$UUID.yaml ,请直接在clash客户端中输入该网址食用，clash使用请用meta内核，自行谷歌"
echo
echo "   其他客户端请自行参考clash配置中的数据,另食用前请自行开启bbr,aria2也请自行下载，推荐逗大的脚本！"
echo
echo "   对了你的小网盘的账号和密码都是admin,记得上 /html/we.dog/_h5ai/public/login.php 修改 "
echo
echo "----------------------------------------------------------------------------------------------------------------------------------------------"
echo
# END
