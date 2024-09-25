cat <<EOF
smtprelay has been installed as a systemd service.

The configuration file is in /etc/smtprelay.ini, you need to configurate before start.

To start/stop smtprelay:

sudo systemctl start smtprelay.service
sudo systemctl stop smtprelay.service

To enable/disable smtprelay starting automatically on boot:

sudo systemctl enable smtprelay.service
sudo systemctl disable smtprelay.service

To reload smtprelay:

sudo systemctl restart smtprelay.service

To view smtprelay logs, first need to configure journal format in smtprelay.ini
    log_format = journal
later you can visualize with:

journalctl -f -u smtprelay

EOF