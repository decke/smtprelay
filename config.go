package main

import (
	"flag"

	"github.com/vharitonsky/iniflags"
)

const (
	VERSION = "1.4.0"
)

var (
	logFile           = flag.String("logfile", "/var/log/smtprelay.log", "Path to logfile")
	hostName          = flag.String("hostname", "localhost.localdomain", "Server hostname")
	welcomeMsg        = flag.String("welcome_msg", "", "Welcome message for SMTP session")
	listen            = flag.String("listen", "127.0.0.1:25 [::1]:25", "Address and port to listen for incoming SMTP")
	localCert         = flag.String("local_cert", "", "SSL certificate for STARTTLS/TLS")
	localKey          = flag.String("local_key", "", "SSL private key for STARTTLS/TLS")
	localForceTLS     = flag.Bool("local_forcetls", false, "Force STARTTLS (needs local_cert and local_key)")
	allowedNets       = flag.String("allowed_nets", "127.0.0.1/8 ::1/128", "Networks allowed to send mails")
	allowedSender     = flag.String("allowed_sender", "", "Regular expression for valid FROM EMail addresses")
	allowedRecipients = flag.String("allowed_recipients", "", "Regular expression for valid TO EMail addresses")
	allowedUsers      = flag.String("allowed_users", "", "Path to file with valid users/passwords")
	remoteHost        = flag.String("remote_host", "smtp.gmail.com:587", "Outgoing SMTP server")
	remoteUser        = flag.String("remote_user", "", "Username for authentication on outgoing SMTP server")
	remotePass        = flag.String("remote_pass", "", "Password for authentication on outgoing SMTP server")
	remoteAuth        = flag.String("remote_auth", "plain", "Auth method on outgoing SMTP server (plain, login)")
	remoteSender      = flag.String("remote_sender", "", "Sender e-mail address on outgoing SMTP server")
	versionInfo       = flag.Bool("version", false, "Show version information")
)

func ConfigLoad() {
	iniflags.Parse()
}
