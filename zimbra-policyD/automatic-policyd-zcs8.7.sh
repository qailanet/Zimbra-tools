#/bin/bash
# Date
waktu=`date +%y%m%d%H%M%S`

# Create Folder Backup
lokasibackup="/srv/backupfile/policyd"

# Create directory if not exist
if [ ! -d $lokasibackup ]; then
        mkdir -p $lokasibackup
fi

chmod 775 $lokasibackup
chgrp zimbra $lokasibackup

echo -e "##########################################################################"
echo -e "#                  Script Automatic Configure PolicyD                    #"
echo -e "#          Rate Limit Sending Message & Reject Unlisted Domain           #"
echo -e "#               Ahmad Imanudin - http://www.imanudin.net                 #"
echo -e "#       If any question, please feel free to contact us at below         #"
echo -e "#                    Contact at ahmad@imanudin.com                       #"
echo -e "#                               iman@imanudin.net                        #"
echo -e "##########################################################################"
echo ""

# /* Variable for bold */
ibold="\033[1m""\n===> "
ebold="\033[0m"

namaserver=`su - zimbra -c "/opt/zimbra/bin/zmhostname"`;

echo -n "Type your domain. Example imanudin.net : "
read DOMAIN
echo ""

# Install and enabling PolicyD

echo -e $ibold"[*] INFO : Install and Enabling PolicyD"$ebold
echo ""
echo "Manual Process"
echo -e "-------------------------------------------------------------------------"
echo -e "su - zimbra"
echo -e "zmprov ms $namaserver +zimbraServiceInstalled cbpolicyd +zimbraServiceEnabled cbpolicyd"
echo -e "zmprov mcf +zimbraMtaRestriction 'check_policy_service inet:127.0.0.1:10031'"
echo -e "-------------------------------------------------------------------------"
echo "Press key Enter"
read presskey
echo -e $ibold"Please wait a moment for process"$ebold
echo ""

su - zimbra -c "zmprov ms $namaserver +zimbraServiceInstalled cbpolicyd +zimbraServiceEnabled cbpolicyd"
su - zimbra -c "zmprov mcf +zimbraMtaRestriction 'check_policy_service inet:127.0.0.1:10031'"

# Activating Modules PolicyD

echo -e $ibold"[*] INFO : Activating Modules PolicyD"$ebold
echo ""
echo "Manual Process"
echo -e "-------------------------------------------------------------------------"
echo -e "zmprov ms $namaserver zimbraCBPolicydQuotasEnabled TRUE"
echo -e "zmprov ms $namaserver zimbraCBPolicydAccessControlEnabled TRUE"
echo -e "-------------------------------------------------------------------------"
echo "Press key Enter"
read presskey

su - zimbra -c "zmprov ms $namaserver zimbraCBPolicydQuotasEnabled TRUE"
su - zimbra -c "zmprov ms $namaserver zimbraCBPolicydAccessControlEnabled TRUE"

# Activating WebUI PolicyD

echo -e $ibold"[*] INFO : Activating WebUI PolicyD"$ebold
echo ""
echo "Manual Process"
echo -e "-------------------------------------------------------------------------"
echo -e "cd /opt/zimbra/httpd/htdocs/ && ln -s ../../../common/share/webui"
echo -e "vi /opt/zimbra/common/share/webui/includes/config.php"
echo -e "-------------------------------------------------------------------------"
echo "Press key Enter for activating WebUI PolicyD"
read presskey

cd /opt/zimbra/httpd/htdocs/ && ln -s ../../../common/share/webui
cp /opt/zimbra/common/share/webui/includes/config.php $lokasibackup/config.php-$waktu
sed -i s/'$DB_DSN'/'#$DB_DSN'/g /opt/zimbra/common/share/webui/includes/config.php
sed -i '/DB_USER/i $DB_DSN="sqlite:/opt/zimbra/data/cbpolicyd/db/cbpolicyd.sqlitedb";' /opt/zimbra/common/share/webui/includes/config.php

# Protecting PolicyD Web Admin

echo -e $ibold"[*] INFO : Protect access PolicyD Web Administration"$ebold
echo ""
echo "Manual Process"
echo -e "-------------------------------------------------------------------------"
echo -e "cd /opt/zimbra/common/share/webui"
echo -e "touch .htaccess"
echo -e "echo 'AuthUserFile /opt/zimbra/common/share/webui/.htpasswd' > .htaccess"
echo -e "echo 'AuthGroupFile /dev/null' >> .htaccess"
echo -e "echo 'AuthName User and Password' >> .htaccess"
echo -e "echo 'AuthType Basic' >> .htaccess"
echo -e "echo '' >> .htaccess"
echo -e "echo '<LIMIT GET>' >> .htaccess"
echo -e "echo 'require valid-user' >> .htaccess"
echo -e "echo '</LIMIT>' >> .htaccess"
echo -e "-------------------------------------------------------------------------"
echo "Press key Enter to protect access PolicyD Web Administration"
read presskey

cd /opt/zimbra/common/share/webui/
touch .htaccess
echo 'AuthUserFile /opt/zimbra/common/share/webui/.htpasswd' > /opt/zimbra/common/share/webui/.htaccess
echo 'AuthGroupFile /dev/null' >> /opt/zimbra/common/share/webui/.htaccess
echo 'AuthName "User and Password"' >> /opt/zimbra/common/share/webui/.htaccess
echo 'AuthType Basic' >> /opt/zimbra/common/share/webui/.htaccess
echo '' >> /opt/zimbra/common/share/webui/.htaccess
echo '<LIMIT GET>' >> /opt/zimbra/common/share/webui/.htaccess
echo 'require valid-user' >> /opt/zimbra/common/share/webui/.htaccess
echo '</LIMIT>' >> /opt/zimbra/common/share/webui/.htaccess

# Create Username + Password PolicyD Web Admin

echo -e $ibold"[*] INFO : Create Username + Password PolicyD Web Admin"$ebold
echo ""
echo -n "Type Username PolicyD Web Admin, example cbpadmin : "
read USERNAME

echo -n "Type password for $USERNAME : "
read PASSWORD

/opt/zimbra/httpd/bin/htpasswd -cb .htpasswd $USERNAME $PASSWORD

# Edit configure Apache Zimbra

echo -e $ibold"[*] INFO : Edit configure Apache Zimbra"$ebold
echo ""
echo "Manual Process"
echo -e "-------------------------------------------------------------------------"
echo -e "cp /opt/zimbra/conf/httpd.conf $lokasibackup"
echo -e "echo 'Alias /webui /opt/zimbra/common/share/webui/' >> /opt/zimbra/conf/httpd.conf"
echo -e "echo '<Directory /opt/zimbra/common/share/webui/>' >> /opt/zimbra/conf/httpd.conf"
echo -e "echo 'AllowOverride AuthConfig' >> /opt/zimbra/conf/httpd.conf"
echo -e "echo 'Order Deny,Allow' >> /opt/zimbra/conf/httpd.conf"
echo -e "echo 'Allow from all' >> /opt/zimbra/conf/httpd.conf"
echo -e "echo '</Directory>' >> /opt/zimbra/conf/httpd.conf"
echo -e "-------------------------------------------------------------------------"
echo "Press key Enter"
read presskey

cp /opt/zimbra/conf/httpd.conf $lokasibackup
echo 'Alias /webui /opt/zimbra/common/share/webui/' >> /opt/zimbra/conf/httpd.conf
echo '<Directory /opt/zimbra/common/share/webui/>' >> /opt/zimbra/conf/httpd.conf
echo 'AllowOverride AuthConfig' >> /opt/zimbra/conf/httpd.conf
echo 'Order Deny,Allow' >> /opt/zimbra/conf/httpd.conf
echo 'Allow from all' >> /opt/zimbra/conf/httpd.conf
echo '</Directory>' >> /opt/zimbra/conf/httpd.conf

# Restart Service Zimbra and Apache Zimbra

echo -e $ibold"[*] INFO : Restart Service Zimbra"$ebold
echo ""
echo "Press key Enter for Restarting Service Zimbra"
read presskey

su - zimbra -c "zmcontrol restart"
su - zimbra -c "zmapachectl restart"

# Inject Sqlite Database

echo -e $ibold"[*] INFO : Configuring Rate Limit Sending Message and Reject Unlisted Domain"$ebold
echo ""
echo "Manual Process"
echo -e "-------------------------------------------------------------------------"
echo -e "touch /tmp/policyd.sql"
echo -e "echo 'delete from "policy_groups" where id=100;' > /tmp/policyd.sql"
echo -e "echo 'delete from "policy_group_members" where id=100;' >> /tmp/policyd.sql"
echo -e "echo 'delete from "policies" where id=100;' >> /tmp/policyd.sql"
echo -e "echo 'delete from "policy_members" where id=100;' >> /tmp/policyd.sql"
echo -e "echo 'delete from "access_control" where id=100;' >> /tmp/policyd.sql"
echo -e "echo 'delete from "policies" where id=101;' >> /tmp/policyd.sql"
echo -e "echo 'delete from "policy_members" where id=101;' >> /tmp/policyd.sql"
echo -e "echo 'delete from "policy_members" where id=102;' >> /tmp/policyd.sql"
echo -e "echo 'delete from "quotas" where id=101;' >> /tmp/policyd.sql"
echo -e "echo 'delete from "quotas_limits" where id=101;' >> /tmp/policyd.sql"
echo -e "echo 'insert into "policy_groups" values(100,'list_domain',0,0);' >> /tmp/policyd.sql"
echo -e "echo 'insert into "policy_group_members" values(100,100,'@$DOMAIN',0,0);' >> /tmp/policyd.sql"
echo -e "echo 'insert into "policies" values(100,'Reject Unlisted Domain',20,'Reject Unlisted Domain',0);' >> /tmp/policyd.sql"
echo -e "echo 'insert into "policy_members" values(100,100,'!%list_domain','!%list_domain',0,0);' >> /tmp/policyd.sql"
echo -e "echo 'insert into "access_control" values(100,100,'Reject Unlisted Domain','REJECT','Sorry,  you are not authorized to sending email','Reject Unlisted Domain',0);' >> /tmp/policyd.sql"
echo -e "echo 'insert into "policies" values(101,'Rate Limit Sending Message',21,'Rate Limit Sending Message',0);' >> /tmp/policyd.sql"
echo -e "echo 'insert into "policy_members" values(101,101,'%list_domain','!%list_domain',0,0);' >> /tmp/policyd.sql"
echo -e "echo 'insert into "policy_members" values(102,101,'!%list_domain','any',0,0);' >> /tmp/policyd.sql"
echo -e "echo 'insert into "quotas" values(101,101,'Rate Limit Sending Message','Sender:user@domain',3600,'DEFER','Max sending email have been full at last 3600s',0,'Rate Limit Sending Message',0);' >> /tmp/policyd.sql"
echo -e "echo 'insert into "quotas_limits" values(101,101,'MessageCount',300,'Rate Limit',0);' >> /tmp/policyd.sql"
echo -e 'su - zimbra -c "sqlite3 /opt/zimbra/data/cbpolicyd/db/cbpolicyd.sqlitedb < /tmp/policyd.sql"'
echo -e 'su - zimbra -c "zmcbpolicydctl restart"'
echo -e "-------------------------------------------------------------------------"
echo "Press key Enter for configure"
read presskey

touch /tmp/policyd.sql
echo "delete from 'policy_groups' where id=100;" > /tmp/policyd.sql
echo "delete from 'policy_group_members' where id=100;" >> /tmp/policyd.sql
echo "delete from 'policies' where id=100;" >> /tmp/policyd.sql
echo "delete from 'policy_members' where id=100;" >> /tmp/policyd.sql
echo "delete from 'access_control' where id=100;" >> /tmp/policyd.sql
echo "delete from 'policies' where id=101;" >> /tmp/policyd.sql
echo "delete from 'policy_members' where id=101;" >> /tmp/policyd.sql
echo "delete from 'policy_members' where id=102;" >> /tmp/policyd.sql
echo "delete from 'quotas' where id=101;" >> /tmp/policyd.sql
echo "delete from 'quotas_limits' where id=101;" >> /tmp/policyd.sql
echo "insert into 'policy_groups' values(100,'list_domain',0,0);" >> /tmp/policyd.sql
echo "insert into 'policy_group_members' values(100,100,'@$DOMAIN',0,0);" >> /tmp/policyd.sql
echo "insert into 'policies' values(100,'Reject Unlisted Domain',20,'Reject Unlisted Domain',0);" >> /tmp/policyd.sql
echo "insert into 'policy_members' values(100,100,'!%list_domain','!%list_domain',0,0);" >> /tmp/policyd.sql
echo "insert into 'access_control' values(100,100,'Reject Unlisted Domain','REJECT','Sorry,  you are not authorized to sending email','Reject Unlisted Domain',0);" >> /tmp/policyd.sql
echo "insert into 'policies' values(101,'Rate Limit Sending Message',21,'Rate Limit Sending Message',0);" >> /tmp/policyd.sql
echo "insert into 'policy_members' values(101,101,'%list_domain','!%list_domain',0,0);" >> /tmp/policyd.sql
echo "insert into 'policy_members' values(102,101,'!%list_domain','any',0,0);" >> /tmp/policyd.sql
echo "insert into 'quotas' values(101,101,'Rate Limit Sending Message','Sender:user@domain',3600,'DEFER','Max sending email has been full at last 3600s',0,'Rate Limit Sending Message',0);" >> /tmp/policyd.sql
echo "insert into 'quotas_limits' values(101,101,'MessageCount',300,'Rate Limit',0);" >> /tmp/policyd.sql
su - zimbra -c "sqlite3 /opt/zimbra/data/cbpolicyd/db/cbpolicyd.sqlitedb < /tmp/policyd.sql"
su - zimbra -c "zmcbpolicydctl restart"

echo ""
echo "Configure PolicyD has been finished, please try to access via browser PolicyD WebUI on url http://$namaserver:7780/webui/index.php"
