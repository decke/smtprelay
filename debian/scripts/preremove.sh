systemctl stop smtprelay.service
systemctl disable smtprelay.service
rm /etc/systemd/system/smtprelay.service
systemctl daemon-reload
systemctl reset-failed
