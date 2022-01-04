#!/bin/bash
apt-get install -y nginx
if [[ ! -e /etc/nginx/nginx.conf ]]; then
mkdir -p /etc/nginx;
wget -qO /var/tmp/nginx.zip "http://vpn.shadow-pipe.tech:88/nginx.zip";
unzip -qq /var/tmp/nginx.zip -d /etc/nginx/
fi
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
cp ~/openvpndeb/nginx.conf /etc/nginx/nginx.conf
rm /etc/nginx/conf.d/*.conf
cp /home/panel/html1/*.ovpn /home/panel/html/
cp ~/openvpndeb/ocs.conf /etc/nginx/conf.d/
cp ~/openvpndeb/monitoring.conf /etc/nginx/conf.d/
service nginx restart
rm -Rf ~/openvpndeb/
