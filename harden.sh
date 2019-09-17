#!/bin/bash
#set -e

PROXY="$1"
SMTP_USER=""
SMTP_PASSWD=""
SMTP_HOST=""
SMTP_PORT=""
SSH_PORT=""
SENDER="`id -un`@`hostname`"
RECVER=""
NORMAL_USER_NAME=""
USER_PASS=""
HTTP_PROXY="http_proxy=$PROXY"
HTTPS_PROXY="https_proxy=$PROXY"


echo "=================================================="
echo " 1. bash_history appendable only "
echo " 2. default umask "
echo " 3. password expire period "
echo " 4. sshd harden "
echo "=================================================="

[ ! -f ~/.bash_history ] && touch ~/.bash_history && chattr +a ~/.bash_history

sed -i "s/UMASK.*/UMASK 027/g" /etc/login.defs
sed -i "s/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/" /etc/login.defs

echo "Protocol 2" >> /etc/ssh/sshd_config
sed -i "s/\#LogLevel.*/LogLevel VERBOSE/g" /etc/ssh/sshd_config
sed -i "s/\#MaxAuthTries.*/MaxAuthTries 3/g" /etc/ssh/sshd_config
sed -i "s/\#MaxSessions.*/MaxSessions 2/g" /etc/ssh/sshd_config
sed -i "s/\#Port.*/Port 7310/g" /etc/ssh/sshd_config
sed -i "s/\#TCPKeepAlive.*/TCPKeepAlive no/g" /etc/ssh/sshd_config
sed -i "s/\#AllowAgentForwarding.*/AllowAgentForwarding no/g" /etc/ssh/sshd_config
sed -i "s/\#AllowTcpForwarding.*/AllowTcpForwarding no/g" /etc/ssh/sshd_config
sed -i "s/\#ClientAliveCountMax.*/ClientAliveCountMax 2/g" /etc/ssh/sshd_config
sed -i "s/\#X11Forwarding.*/X11Forwarding no/g" /etc/ssh/sshd_config


echo "=================================================="
echo " 5. sysctl harden "
echo "=================================================="

sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w kernel.sysrq=0
sysctl -w kernel.yama.ptrace_scope=2
sysctl -w net.ipv4.tcp_timestamps=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w kernel.kptr_restrict=2
sysctl -w kernel.core_uses_pid=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w vm.panic_on_oom=1
sysctl -w kernel.panic=10
sysctl -w fs.suid_dumpable=0

sysctl --system

echo "=================================================="
echo "6. bash_history variable harden"
echo "=================================================="

cat >> /etc/profile << EOF

HISTFILE=~/.bash_history
HISTSIZE=10000
HISTFILESIZE=999999
# Don't let the users enter commands that are ignored
# in the history file
HISTIGNORE=""
HISTCONTROL=""
readonly HISTFILE
readonly HISTSIZE
readonly HISTFILESIZE
readonly HISTIGNORE
readonly HISTCONTROL
export HISTFILE HISTSIZE HISTFILESIZE HISTIGNORE HISTCONTROL
EOF

if [ "$PROXY" != "" ] ; then

	echo "=================================================="
	echo "x. setting up proxy"
	echo "=================================================="

	printf "Acquire::http::Proxy \"$PROXY\";\nAcquire::https::Proxy \"$PROXY\";" \
		> /etc/apt/apt.conf.d/02-proxy
	echo "Acquire::Retries \"5\";" > /etc/apt/apt.conf.d/80-retries
	printf "Acquire::http::Timeout \"10\";\nAcquire::http::Timeout \"10\";" > \
		/etc/apt/apt.conf.d/99-timeout-http
	printf "Acquire::http::Timeout \"10\";\nAcquire::ftp::Timeout \"10\";" > \
		/etc/apt/apt.conf.d/99-timeout-ftp

fi

echo "=================================================="
echo "7. adding debian repo"
echo "=================================================="


sed -i "s/^deb cdrom/#deb cdrom/g" /etc/apt/sources.list
grep "^deb http://security.debian.org" /etc/apt/sources.list > /dev/null 2>&1

[ "$?" != "0" ] && \
	echo "deb http://security.debian.org/ stretch/updates main" >> \
		/etc/apt/sources.list && \
	echo "deb-src http://security.debian.org/ stretch/updates main" >> \
		/etc/apt/sources.list

grep "^deb http://deb.debian.org" /etc/apt/sources.list > /dev/null 2>&1
[ "$?" != "0" ] && \
	echo "deb http://deb.debian.org/debian/ stretch main" >> \
		/etc/apt/sources.list && \
	echo "deb-src http://deb.debian.org/debian/ stretch main" >> \
		/etc/apt/sources.list

apt update

echo "=================================================="
echo "8. install tools "
echo "=================================================="

DEBAIN_FRONTEND=noninteractive apt install -y \
	build-essential ca-certificates apt-utils gnupg2 unattended-upgrades apparmor apparmor-profiles apparmor-utils sudo bc libopts25 ntp

DEBAIN_FRONTEND=noninteractive apt install -y \
	curl git wget vim libpam-cracklib etckeeper fail2ban net-tools traceroute screen iptables-persistent

DEBAIN_FRONTEND=noninteractive apt install -y \
	apt-transport-https dirmngr auditd debsecan debsums 

DEBAIN_FRONTEND=noninteractive apt install -y \
	debian-goodies needrestart chkrootkit rkhunter

git config --global user.name "`id -un`"
git config --global user.email "$SENDER"


echo "=================================================="
echo "9. setting up postfix"
echo "=================================================="

echo "postfix postfix/main_mailer_type select 'Internet Site'" | debconf-set-selections
echo "postfix postfix/mailname	string `hostname`" | debconf-set-selections

apt install -y postfix

printf "[$SMTP_HOST]:$SMTP_PORT $SMTP_USER:$SMTP_PASSWD" > /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
RELAY="[$SMTP_HOST]:$SMTP_PORT"
sed -i "s/^relayhost =.*/relayhost = ${RELAY}/g" /etc/postfix/main.cf
sed -i "s/inet_interfaces =.*/inet_interfaces = loopback-only/g" /etc/postfix/main.cf
#sed -i "s/root:.*/root: ${RECVER}/g" /etc/aliases

echo "smtp_sasl_auth_enable = yes" >> /etc/postfix/main.cf
echo "smtp_sasl_security_options = noanonymous" >> /etc/postfix/main.cf
echo "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd" >> /etc/postfix/main.cf
echo "smtp_use_tls = yes" >> /etc/postfix/main.cf
echo "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt" >> /etc/postfix/main.cf

grep "root:" /etc/aliases
[ "$?" != "0" ] && echo "root: $RECVER" >> /etc/aliases
newaliases
systemctl restart postfix
mail -s "postfix test mail" -aFrom:$SENDER $RECVER <<< "postfix test mail"

echo "=================================================="
echo "10. setting up chkrootkit and rkhunter"
echo "=================================================="

sed -i "s/RUN_DAILY=.*/RUN_DAILY=\"true\"/g" /etc/chkrootkit.conf
sed -i "s/RUN_DAILY_OPTS=.*/RUN_DAILY_OPTS=\"\"/g" /etc/chkrootkit.conf
sed -i "s/DIFF_MODE=.*/DIFF_MODE=\"true\"/g" /etc/chkrootkit.conf
cp -a /var/log/chkrootkit/log.today /var/log/chkrootkit/log.expected

sed -i "s/^CRON_DAILY_RUN.*/CRON_DAILY_RUN=\"true\"/g" /etc/default/rkhunter
sed -i "s/^CRON_DB_UPDATE.*/CRON_DB_UPDATE=\"true\"/g" /etc/default/rkhunter
sed -i "s/^UPDATE_MIRRORS.*/UPDATE_MIRRORS=1/g" /etc/rkhunter.conf
sed -i "s/^MIRRORS_MODE=.*/MIRRORS_MODE=0/g" /etc/rkhunter.conf
sed -i "s/^WEB_CMD=.*/WEB_CMD=\"\"/g" /etc/rkhunter.conf


echo "=================================================="
echo "11. setting up fail2ban"
echo "=================================================="

cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -ie "0,/port.*= ssh/ s/port.*= ssh/port = ssh/" \
	/etc/fail2ban/jail.local
sed -i "s/^\[sshd\]/\[sshd\]\nenabled = true/" \
	/etc/fail2ban/jail.local

systemctl restart fail2ban

# https://wiki.debian.org/SetupGuides/SecurePersonalComputer


echo "=================================================="
echo "12. setting up accounting tools, [logwatch, sysstat, acct, audit]"
echo "=================================================="

DEBIAN_FRONTEND=noninteractive apt install -y sysstat
sed -i "s/ENABLED=.*$/ENABLED='true'/" /etc/default/sysstat

systemctl restart sysstat

DEBIAN_FRONTEND=noninteractive apt install -y acct

DEBIAN_FRONTEND=noninteractive apt install -y logwatch
cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/
sed -i "s/^Detail =.*/Detail = HIGH/g" /etc/logwatch/conf/logwatch.conf
sed -i "s/^Output =.*/Output = mail/g" /etc/logwatch/conf/logwatch.conf

[ ! -d /etc/audit ] && mkdir /etc/audit
[ -d ./auditd ] && rm -rf ./auditd

if [ "$PROXY" != "" ] ; then
	git config --global http.proxy $PROXY
	git config --global https.proxy $PROXY
fi

git clone https://github.com/Neo23x0/auditd
cp auditd/audit.rules /etc/audit/
systemctl restart auditd

PROXY_OPT=""
if [ "$PROXY" != "" ] ; then
	PROXY_OPT="--keyserver-options http-proxy=$PROXY"
fi

apt-key adv --keyserver keyserver.ubuntu.com $PROXY_OPT --recv-keys C80E383C3DE9F082E01391A0366C67DE91CA5D5F

echo 'Acquire::Languages "none";' | \
	tee /etc/apt/apt.conf.d/99disable-translations
echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | \
	tee /etc/apt/sources.list.d/cisofy-lynis.list

cat >> /etc/apt/preferences.d/lynis << EOF
Package: lynis
Pin: origin packages.cisofy.com
Pin-Priority: 600
EOF

LYNIS_CRON=/etc/cron.daily/lynis
[ -f $LYNIS_CRON ] && rm $LYNIS_CRON

cat >> $LYNIS_CRON << EOF
#!/bin/sh
AUDITOR="automated"
DATE=\$(date +%Y%m%d)
HOST=\$(hostname)
LOG_DIR="/var/log/lynis"
REPORT="\$LOG_DIR/report-\${HOST}.\${DATE}.html"
DATA="\$LOG_DIR/report-data-\${HOST}.\${DATE}.txt"

lynis audit system --auditor "\${AUDITOR}" | ansi2html > \${REPORT}
cat \${REPORT} | mail -s "lynis report of \$DATE" -aFrom:${SENDER} ${RECVER}
mv /var/log/lynis-report.dat \${DATA}
EOF

chmod +x /etc/cron.daily/lynis

apt update && DEBIAN_FRONTEND=noninteractive apt install -y kbtin lynis

pushd .
cd /etc
etckeeper init
etckeeper commit -m "initial commit"
popd

echo "=================================================="
echo "14. setup new user"
echo "=================================================="
#NORM_USER_NAME="$(< /dev/urandom tr -cd 'a-z' | head -c 6)""$(< /dev/urandom tr -cd '0-9' | head -c 2)"
#USER_PASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)"
echo -e "${USER_PASS}\\n${USER_PASS}" | adduser "$NORM_USER_NAME" -q --gecos "First Last,RoomNumber,WorkPhone,HomePhone"
usermod -aG sudo "$NORM_USER_NAME"


echo "=================================================="
echo "13. setup iptables"
echo "=================================================="

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -p tcp --dport 7310 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 25 -m state --state NEW -j ACCEPT
iptables -A INPUT -p udp --dport 68 -m state --state NEW -j ACCEPT
iptables -A INPUT -p udp --dport 123 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT

ldconfig
apt-get clean
apt-get autoremove -y
rm -rf /var/lib/apt/lists/* /tmp/*ystemctl 
systemctl restart sshd
