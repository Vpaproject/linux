#!/bin/bash
#Debian 9 Installer
OpenVPN_Port1='1103'
OpenVPN_Port2='25222'
apt-get update -y
clear
service apache2 stop
function rootako () {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}
function checktuntap () {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkdebian () {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ "$ID" == "debian" || "$ID" == "raspbian" ]]; then
			if [[ ! $VERSION_ID =~ (10) ]]; then
				echo ' Your version of Debian is not supported.'
				echo ""
				echo "However, if you're using Debian >= 9 or unstable/testing then you can continue."
				echo "Keep in mind they are not supported, though."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ "$CONTINUE" = "n" ]]; then
					exit 1
				fi
			fi
		fi		
else
		echo "Looks like you aren't running this installer on a Debian"
		exit 1
	fi
}
function initialCheck () {
	if ! rootako; then
		echo "Sorry, you need to run this as root"
		exit 1
	fi
	if ! checktuntap; then
		echo "TUN is not available"
		exit 1
	fi
	checkdebian
}

function copymenu () {
cp menu/* /usr/local/sbin/
chmod +x /usr/local/sbin/*
}

function updatesoure () {
cat <<EOF >/etc/rc.local
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.


exit 0
EOF
chmod +x /etc/rc.local
systemctl start rc-local
}

function BadVPN () {
wget -O /usr/bin/badvpn-udpgw "https://github.com/johndesu090/AutoScriptDeb8/raw/master/Files/BadVPN/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://github.com/johndesu090/AutoScriptDeb8/raw/master/Files/BadVPN/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
sed -i '$ i\bash delete_expired &> /dev/null' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
}

function webmin () {
apt-get install -y openssl
}

function dropssl () {
apt-get -y install stunnel4 dropbear
openssl genrsa -out key.pem 4096
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 -batch
cat key.pem cert.pem > /etc/stunnel/stunnel.pem
}

function endropstun () {
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
}

function settime () {
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime
}

function certandkey () {
	cp ~/linux/ca.crt /etc/openvpn/
	cp ~/linux/server.key /etc/openvpn/
	cp ~/linux/server.req /etc/openvpn/
	cp ~/linux/server.crt /etc/openvpn/
	cp ~/linux/dh.pem /etc/openvpn/
        cp ~/linux/client.crt /etc/openvpn/
        cp ~/linux/client.key /etc/openvpn/
        cp ~/linux/ta.key /etc/openvpn/
        cp ~/linux/tls-auth.key /etc/openvpn/
        cp ~/linux/crl.pem /etc/openvpn/        
}

 # Installing OpenVPN by pulling its repository inside sources.list file 
 #rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" >/etc/apt/sources.list.d/openvpn.list && apt-key del E158C569 && wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
 wget -qO security-openvpn-net.asc "https://keys.openpgp.org/vks/v1/by-fingerprint/F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7" && gpg --import security-openvpn-net.asc
 apt-get update -y
 apt-get install openvpn -y

 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf1' > /etc/openvpn/server_tcp.conf
# KinGmapua
port MyOvpnPort1
proto tcp
dev tun
dev-type tun
sndbuf 0
rcvbuf 0
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
tls-auth ta.key 0
dh dh.pem
topology subnet
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
auth SHA256
comp-lzo
user nobody
group nogroup
persist-tun
status openvpn-status.log
verb 2
mute 3
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
myOpenVPNconf1
cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# KinGmapua
port MyOvpnPort2
proto udp
dev tun
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "redirect-gateway def1 bypass-dhcp" 
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
tls-auth tls-auth.key 0
dh dh.pem
auth SHA256
cipher AES-128-CBC
tls-server
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
status openvpn.log
verb 3
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
myOpenVPNconf2
# setting openvpn server port
 sed -i "s|MyOvpnPort1|$OpenVPN_Port1|g" /etc/openvpn/server_tcp.conf
 sed -i "s|MyOvpnPort2|$OpenVPN_Port2|g" /etc/openvpn/server_udp.conf

 # Getting some OpenVPN plugins for unix authentication
 wget -qO /etc/openvpn/b.zip 'https://raw.githubusercontent.com/Bonveio/BonvScripts/master/openvpn_plugin64'
 unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
 rm -f /etc/openvpn/b.zip
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf && sysctl --system &> /dev/null && echo 1 > /proc/sys/net/ipv4/ip_forward

 # Installing Firewalld
 apt install firewalld -y
 systemctl start firewalld
 systemctl enable firewalld
 firewall-cmd --quiet --set-default-zone=public
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/tcp
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/udp
 firewall-cmd --quiet --reload
 firewall-cmd --quiet --add-masquerade
 firewall-cmd --quiet --permanent --add-masquerade
 firewall-cmd --quiet --permanent --add-service=ssh
 firewall-cmd --quiet --permanent --add-service=openvpn
 firewall-cmd --quiet --permanent --add-service=http
 firewall-cmd --quiet --permanent --add-service=https
 firewall-cmd --quiet --permanent --add-service=privoxy
 firewall-cmd --quiet --permanent --add-service=squid
 firewall-cmd --quiet --reload
 
 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_tcp
 systemctl enable openvpn@server_udp
 systemctl restart openvpn@server_tcp
 systemctl restart openvpn@server_udp


function clientovpn () {
echo "client" > /etc/openvpn/client-template.txt
	if [[ "$PROTOCOL" = 'udp' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template.txt
	elif [[ "$PROTOCOL" = 'tcp' ]]; then
		echo "proto tcp" >> /etc/openvpn/client-template.txt
	fi
	echo "dev tun
client
proto tcp
dev tun
remote $IP $PORT
http-proxy $IP 8888
http-proxy-retry
route-method exe
resolv-retry infinite
nobind
persist-key
persist-tun
comp-lzo
cipher AES-256-CBC
auth SHA256
push "redirect-gateway def1 bypass-dhcp"
push-peer-info
ping 10
ping-restart 60
hand-window 70
server-poll-timeout 4
reneg-sec 2592000
sndbuf 0
rcvbuf 0
remote-cert-tls server
key-direction 1
<auth-user-pass>
sam
sam
</auth-user-pass>
verb 3" >> /etc/openvpn/client-template.txt
mkdir -p /home/panel/html
mv /etc/openvpn/client-template.txt /home/panel/html/client.ovpn
echo '<ca>' >> /home/panel/html/client.ovpn
cat /etc/openvpn/ca.crt >> /home/panel/html/client.ovpn
echo '</ca>' >> /home/panel/html/client.ovpn
echo '<cert>' >> /home/panel/html/client.ovpn
cat /etc/openvpn/client.crt >> /home/panel/html/client.ovpn
echo '</cert>' >> /home/panel/html/client.ovpn
echo '<key>' >> /home/panel/html/client.ovpn
cat /etc/openvpn/client.key >> /home/panel/html/client.ovpn
echo '</key>' >> /home/panel/html/client.ovpn
echo '<tls-auth>' >> /home/panel/html/client.ovpn
cat /etc/openvpn/ta.key >> /home/panel/html/client.ovpn
echo '</tls-auth>' >> /home/panel/html/client.ovpn

}

function noload () {
echo "client" > /etc/openvpn/client-template1.txt
	if [[ "$PROTOCOL" = 'udp' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template1.txt
	elif [[ "$PROTOCOL" = 'tcp' ]]; then
		echo "proto tcp" >> /etc/openvpn/client-template1.txt
	fi
	echo "remote $IP $PORT
dev tun
persist-key
persist-tun
dev tun
bind
float
lport 110
remote-cert-tls server
verb 0
auth-user-pass
redirect-gateway def1
cipher none
auth none
auth-nocache
setenv CLIENT_CERT 0
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
log /dev/null" >> /etc/openvpn/client-template1.txt
cp /etc/openvpn/client-template1.txt /home/panel/html/PisoVPN-SunNoLoad.ovpn
echo '<ca>' >> /home/panel/html/PisoVPN-SunNoLoad.ovpn
cat /etc/openvpn/ca.crt >> /home/panel/html/PisoVPN-SunNoLoad.ovpn
echo '</ca>' >> /home/panel/html/PisoVPN-SunNoLoad.ovpn
}

function stunconf () {
cat > /etc/stunnel/stunnel.conf <<-END
sslVersion = all
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openssh]
accept = 444
connect = 127.0.0.1:222

[dropbear]
accept = 443
connect = 127.0.0.1:442
END
}

function privoxconfig () {
rm -f /etc/privoxy/config
cat>>/etc/privoxy/config<<EOF
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:$PORTS
listen-address 0.0.0.0:8000
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 $IP
EOF
rm -rf /etc/squid
wget -O squid.zip https://raw.githubusercontent.com/Vpaproject/linux/main/squid.zip
unzip squid.zip -d /etc/squid
sed -i "s|IP|$IP|g" /etc/squid/squid.conf
rm -rf *.zip
}

function restartall () {
service uwsgi restart
service nginx restart
service vnstat restart
service dropbear restart
service sshd restart
service privoxy restart
service squid restart
service openvpn restart
service stunnel4 restart
sudo systemctl start squid
sudo systemctl enable squid
}

function setall () {
rm /etc/issue.net
cat ~/linux/bann3r > /etc/issue.net
cat ~/linux/banner > /etc/motd
cp ~/linux/banner /etc/
sed -i 's@#Banner[[:space:]]none@Banner /etc/banner@g' /etc/ssh/sshd_config
sed -i 's@PrintMotd[[:space:]]no@PrintMotd yes@g' /etc/ssh/sshd_config
sed -i 's@#PrintLastLog[[:space:]]yes@PrintLastLog no@g' /etc/ssh/sshd_config
sed -i 's@#PermitRootLogin[[:space:]]prohibit-password@PermitRootLogin yes@g' /etc/ssh/sshd_config
sed -i 's@#PubkeyAuthentication[[:space:]]yes@PubkeyAuthentication no@g' /etc/ssh/sshd_config
sed -i 's@PasswordAuthentication[[:space:]]no@PasswordAuthentication yes@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
sed -i 's@#Port[[:space:]]22@Port 22\nPort 222@g' /etc/ssh/sshd_config
sed -i 's@#AddressFamily[[:space:]]any@AddressFamily inet@g' /etc/ssh/sshd_config
sed -i 's@#ListenAddress[[:space:]]0@ListenAddress 0@g' /etc/ssh/sshd_config
service dropbear restart
}

function installQuestions () {
	apt install -y sudo
	EXT_INT=$(cut -d' ' -f5 <(ip -4 route ls default))
	IP=$(ip -4 addr ls $EXT_INT | head -2 | tail -1 | cut -d' ' -f6 | cut -d'/' -f1)
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		IP=$(curl https://ipinfo.io/ip)
	fi
	echo ""
	echo 'Your IP is '"$IP" '.. What port do you want OpenVPN to listen to?'
	echo "   1) Default: 1196"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ "$PORT_CHOICE" =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
		1)
			PORT="1196"
		;;
		2)
			until [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
				read -rp "Custom port [1-65535]: " -e -i 1196 PORT
			done
		;;
		3)
			
			PORT=$(shuf -i49152-65535 -n1)
			echo "Random Port: $PORT"
		;;
	esac
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "UDP is faster. Unless it is not available, you shouldn't use TCP."
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ "$PROTOCOL_CHOICE" =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 2 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
		1)
			PROTOCOL="udp"
		;;
		2)
			PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "What Privoxy port do you want?"
	echo "   1) Default: 8080"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ "$PORT_PRIVO" =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_PRIVO
	done
	case $PORT_PRIVO in
		1)
			PORTS="8080"
		;;
		2)
			until [[ "$PORTS" =~ ^[0-9]+$ ]] && [ "$PORTS" -ge 1 ] && [ "$PORTS" -le 65535 ]; do
				read -rp "Custom port [1-65535]: " -e -i 8080 PORTS
			done
		;;
		3)
			
			PORTS=$(shuf -i49152-65535 -n1)
			echo "Random Port: $PORTS"
		;;
	esac
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	echo "You will be able to generate a client at the end of the installation."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}

function installall () {
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
		apt-get update
		apt-get install openvpn iptables wget ca-certificates curl unzip screenfetch gnupg telnet telnetd nginx privoxy squid3 vnstat ufw build-essential -y
	echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/20-openvpn.conf
	sysctl --system
}

function monitoring () {
apt-get install -y gcc libgeoip-dev python-virtualenv python-dev geoip-database-extra uwsgi uwsgi-plugin-python
cd /srv
git clone https://github.com/furlongm/openvpn-monitor.git
cd openvpn-monitor
virtualenv .
. bin/activate
pip install -r requirements.txt
cp openvpn-monitor.conf.example openvpn-monitor.conf
sed -i "s@host=localhost@host=127.0.0.1@g" openvpn-monitor.conf
sed -i 's@port=5555@port=7505@g' openvpn-monitor.conf
cd ~/linux/
cp openvpn-monitor.ini /etc/uwsgi/apps-available/
ln -s /etc/uwsgi/apps-available/openvpn-monitor.ini /etc/uwsgi/apps-enabled/
cp ~/linux/openvpn-monitor.py /srv/openvpn-monitor/openvpn-monitor.py -f
}

initialCheck
installQuestions
installall
settime
copymenu
updatesoure
BadVPN
webmin
dropssl
certandkey
endropstun
serverconf
disableipv6
setiptables
clientovpn
noload
stunconf
privoxconfig
setall
monitoring
sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn@.service
cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service
if [[ ! -e /etc/nginx/nginx.conf ]]; then
mkdir -p /etc/nginx;
wget -qO /var/tmp/nginx.zip "https://raw.githubusercontent.com/rayvynlee/linux/master/nginx.zip";
unzip -qq /var/tmp/nginx.zip -d /etc/nginx/
fi
cd ~/linux
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
cp ~/linux/nginx.conf /etc/nginx/nginx.conf
rm /etc/nginx/conf.d/*.conf
cp ~/linux/ocs.conf /etc/nginx/conf.d/
cp ~/linux/monitoring.conf /etc/nginx/conf.d/
cp ~/linux/index.html /home/panel/html/
systemctl daemon-reload
systemctl restart openvpn@server
systemctl enable openvpn@server
vnstat -u -i eth0
restartall
clear
show_ports
apt-get install lolcat ruby bc -y
wget https://github.com/busyloop/lolcat/archive/master.zip
unzip master.zip
cd lolcat-master/bin
gem install lolcat
cd /root
#cron for daily reboot
echo "0 5 * * * root /sbin/reboot" > /etc/cron.d/reboot
#cron for expired users
#echo "0 1 * * * root /usr/local/sbin/delete_expired" > /etc/cron.d/delete_expired
#cron for limit registration per day.
echo "0 1 * * * root /usr/local/sbin/reg_limit" > /etc/cron.d/reg_limit
service cron restart
systemctl enable privoxy.service
systemctl enable squid.service
bash reg_limit
history -c
rm -rf ~/linux/
userdel -r debian
# tail -f /var/log/syslog
reboot
