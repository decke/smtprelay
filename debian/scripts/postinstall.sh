cat <<EOF
smtprelay has been installed as a systemd service.

To start/stop smtprelay:

sudo systemctl start smtprelay.service
sudo systemctl stop smtprelay.service

To enable/disable smtprelay starting automatically on boot:

sudo systemctl enable smtprelay.service
sudo systemctl disable smtprelay.service

To reload smtprelay:

sudo systemctl restart smtprelay.service

To view smtprelay logs:

journalctl -f -u smtprelay

EOF