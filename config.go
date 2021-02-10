package main

import (
	"flag"
	"os"

	"github.com/vharitonsky/iniflags"
)

const (
	VERSION = "1.4.0"
)

var (
	logFile       = flag.String("logfile", "/dev/stdout", "Path to logfile")
	hostName      = flag.String("hostname", "localhost.localdomain", "Server hostname")
	welcomeMsg    = flag.String("welcome_msg", "", "Welcome message for SMTP session")
	listen        = flag.String("listen", "127.0.0.1:25 [::1]:25", "Address and port to listen for incoming SMTP")
	metricsListen = flag.String("metrics_listen", ":8080", "Address and port to listen for metrics exposition")
	localCert     = flag.String("local_cert", "", "SSL certificate for STARTTLS/TLS")
	localKey      = flag.String("local_key", "", "SSL private key for STARTTLS/TLS")
	localForceTLS = flag.Bool("local_forcetls", false, "Force STARTTLS (needs local_cert and local_key)")
	// set allowed_nets to "" to allow any Networks (i.e disable network check)
	allowedNets = flag.String("allowed_nets", "127.0.0.1/8 ::1/128", "Networks allowed to send mails, use \"\" to disable")
	// set "" to allow any sender (i.e disable sender check)
	allowedSender = flag.String("allowed_sender", "", "Regular expression for valid FROM EMail addresses")
	// set "" to allow any recipients (i.e disable recipients check)
	allowedRecipients = flag.String("allowed_recipients", "", "Regular expression for valid TO EMail addresses")
	// set "" to allow any user (i.e disable users check)
	allowedUsers = flag.String("allowed_users", "", "Path to file with valid users/passwords")
	remoteHost   = flag.String("remote_host", "smtp.gmail.com:587", "Outgoing SMTP server")
	remoteUser   = flag.String("remote_user", "", "Username for authentication on outgoing SMTP server")
	// REMOTE_PASS env var can also be used to set remotePass
	remotePass   = flag.String("remote_pass", "", "Password for authentication on outgoing SMTP server")
	remoteAuth   = flag.String("remote_auth", "plain", "Auth method on outgoing SMTP server (plain, login)")
	remoteSender = flag.String("remote_sender", "", "Sender e-mail address on outgoing SMTP server")
	versionInfo  = flag.Bool("version", false, "Show version information")
	logLevel     = flag.String("log_level", "debug", "Minimum log level to output")
)

func ConfigLoad() {
	iniflags.Parse()

	setupLogger()

	// if remotePass is not set, try reading it from env var
	if *remotePass == "" {
		log.Debug("remote_pass not set, trying REMOTE_PASS env var")
		*remotePass = os.Getenv("REMOTE_PASS")
		if *remotePass != "" {
			log.Debug("found data in REMOTE_PASS env var")
		} else {
			log.Debug("no data found in REMOTE_PASS env var")
		}
	}
}
