#!/bin/bash
yum install epel-release -y
yum install fail2ban -y
systemctl restart fail2ban
mkdir conf-Fail2ban
cd conf-Fail2ban
wget https://github.com/mekbuk/zimbra-fail2ban/archive/master.zip
unzip master.zip
cd zimbra-fail2ban-master/
\cp -fr action.d/* /etc/fail2ban/action.d/

#dans /etc/fail2ban/action.d/iptables-allports.conf
sed -i 's/actionban = iptables -I fail2ban-<name> 1 -s <ip> -j <blocktype>/actionban = iptables -I fail2ban-<name> 1 -s <ip> -j DROP/g' /etc/fail2ban/action.d/iptables-allports.conf
\cp -rf filter.d/* /etc/fail2ban/filter.d/

touch /etc/fail2ban/jail.local
cat <<EOT  >> /etc/fail2ban/jail.local
[DEFAULT]
# "ignoreip" can be an IP address, a CIDR mask or a DNS host. Fail2ban will not
# ban a host which matches an address in this list. Several addresses can be
# defined using space separator.
ignoreip = 127.0.0.1/8 91.151.65.10/32 94.185.

# "bantime" is the number of seconds that a host is banned.
bantime  = 86400

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime = 3600
maxretry = 3

# "backend" specifies the backend used to get files modification.
# Available options are "pyinotify", "gamin", "polling" and "auto".
# This option can be overridden in each jail as well.
#
# pyinotify: requires pyinotify (a file alteration monitor) to be installed.
#            If pyinotify is not installed, Fail2ban will use auto.
# gamin:     requires Gamin (a file alteration monitor) to be installed.
#            If Gamin is not installed, Fail2ban will use auto.
# polling:   uses a polling algorithm which does not require external libraries.
# auto:      will try to use the following backends, in order:
#            pyinotify, gamin, polling.
backend = auto

# "usedns" specifies if jails should trust hostnames in logs,#   warn when reverse DNS lookups are performed, or ignore all hostnames in logs
#
# yes:   if a hostname is encountered, a reverse DNS lookup will be performed.
# warn:  if a hostname is encountered, a reverse DNS lookup will be performed,
#        but it will be logged as a warning.
# no:    if a hostname is encountered, will not be used for banning,
#        but it will be logged as info.
usedns = warn

# Destination email address used solely for the interpolations in
# jail.{conf,local} configuration files.
destemail = votre email
#
# Name of the sender for mta actions
sendername = Fail2Ban

#
# ACTIONS
#
# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = iptables-multiport

# email action. Since 0.8.1 upstream fail2ban uses sendmail
# MTA for the mailing. Change mta configuration parameter to mail
# if you want to revert to conventional 'mail'.
mta = sendmail

# Default protocol
protocol = tcp

# Specify chain where jumps would need to be added in iptables-* actions
chain = INPUT

#
# Action shortcuts. To be used to define action parameter
# The simplest action to take: ban only
action_ = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]

# ban & send an e-mail with whois report to the destemail.
action_mw = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
             %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s", sendername="%(sendername)s"]

# ban & send an e-mail with whois report and relevant log lines
# to the destemail.
action_mwl = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
              %(mta)s-whois-lines[name=%(__name__)s, dest="%(destemail)s", logpath=%(logpath)s, chain="%(chain)s", sendername="%(sendername)s"]

# Choose default action.  To change, just override value of 'action' with the
# interpolation to the chosen action shortcut (e.g.  action_mw, action_mwl, etc) in jail.local
# globally (section [DEFAULT]) or per specific section
action = %(action_)s
EOT

cat jail.d/zimbra.conf >> /etc/fail2ban/jail.local
sed -i 's/bantime = 7200/bantime = -1/g' /etc/fail2ban/jail.local
sed -i 's/maxretry = 5/maxretry = 3/g' /etc/fail2ban/jail.local
systemctl enable fail2ban
systemctl start fail2ban


------------------------------------------------------------------------------------

In /etc/fail2ban/filter.d/zimbra.conf the regex should look like this:

failregex =     \[ip=<HOST>;\] account – authentication failed for .* \(no such account\)$
                \[ip=<HOST>;\] security – cmd=Auth; .* error=authentication failed for .*, invalid password;$
                \[ip=<HOST>;\] security – cmd=AdminAuth; .* error=authentication failed for .*, invalid password;$
                \[ip=<HOST>;\] security – cmd=Auth; .* error=authentication failed for .*, account lockout$
                \[ip=<HOST>;\] account – authentication failed for .* \(account lockout\)$
                ;oip=<HOST>;.* security – cmd=Auth; .* protocol=soap; error=authentication failed for .* invalid password;$
                \[oip=<HOST>;.* SoapEngine – handler exception: authentication failed for .*, account not found$
                \[oip=<HOST>;.* SoapEngine – handler exception: authentication failed for .*, invalid password$
                WARN .*ip=<HOST>;ua=ZimbraWebClient .* security – cmd=AdminAuth; .* error=authentication failed for .*;$
                WARN  \[.*\] \[name=.*;ip=<HOST>;ua=.*;\] security - cmd=Auth; account=.*; protocol=.*; error=.*, invalid password;
                INFO .*ip=<HOST>;ua=zclient.*\] .* authentication failed for \[.*\], (invalid password|account not found)+:
                
run as zimbra ( su zimbra )
whitelist the ip loopback from wan/lan
zmprov mcf +zimbraHttpThrottleSafeIPs 172.0.0.1
zmprov mcf +zimbraHttpThrottleSafeIPs x.x.x.x
zmprov mcf +zimbraMailTrustedIP x.x.x.x
zmprov mcf +zimbraMailTrustedIP 127.0.0.1
zmmailboxdctl restart
