package main

import (
	"flag"
	"net"

	"github.com/vharitonsky/iniflags"
	"github.com/sirupsen/logrus"
)

var (
	appVersion = "unknown"
	buildTime  = "unknown"
)

var (
	logFile           = flag.String("logfile", "", "Path to logfile")
	logFormat         = flag.String("log_format", "default", "Log output format")
	logLevel          = flag.String("log_level", "info", "Minimum log level to output")
	hostName          = flag.String("hostname", "localhost.localdomain", "Server hostname")
	welcomeMsg        = flag.String("welcome_msg", "", "Welcome message for SMTP session")
	listen            = flag.String("listen", "127.0.0.1:25 [::1]:25", "Address and port to listen for incoming SMTP")
	localCert         = flag.String("local_cert", "", "SSL certificate for STARTTLS/TLS")
	localKey          = flag.String("local_key", "", "SSL private key for STARTTLS/TLS")
	localForceTLS     = flag.Bool("local_forcetls", false, "Force STARTTLS (needs local_cert and local_key)")
	allowedNetsStr    = flag.String("allowed_nets", "127.0.0.0/8 ::1/128", "Networks allowed to send mails")
	allowedNets       = []*net.IPNet{}
	allowedSender     = flag.String("allowed_sender", "", "Regular expression for valid FROM EMail addresses")
	allowedRecipients = flag.String("allowed_recipients", "", "Regular expression for valid TO EMail addresses")
	allowedUsers      = flag.String("allowed_users", "", "Path to file with valid users/passwords")
	remoteHost        = flag.String("remote_host", "", "Outgoing SMTP server")
	remoteUser        = flag.String("remote_user", "", "Username for authentication on outgoing SMTP server")
	remotePass        = flag.String("remote_pass", "", "Password for authentication on outgoing SMTP server")
	remoteAuth        = flag.String("remote_auth", "plain", "Auth method on outgoing SMTP server (plain, login)")
	remoteSender      = flag.String("remote_sender", "", "Sender e-mail address on outgoing SMTP server")
	versionInfo       = flag.Bool("version", false, "Show version information")
)


func setupAllowedNetworks() {
	for _, netstr := range splitstr(*allowedNetsStr, ' ') {
		baseIP, allowedNet, err := net.ParseCIDR(netstr)
		if err != nil {
			log.WithField("netstr", netstr).
				WithError(err).
				Fatal("Invalid CIDR notation in allowed_nets")
		}

		// Reject any network specification where any host bits are set,
		// meaning the address refers to a host and not a network.
		if !allowedNet.IP.Equal(baseIP) {
			log.WithFields(logrus.Fields{
				"given_net": netstr,
				"proper_net": allowedNet,
			}).Fatal("Invalid network in allowed_nets (host bits set)")
		}

		allowedNets = append(allowedNets, allowedNet)
	}
}

func ConfigLoad() {
	iniflags.Parse()

	// Set up logging as soon as possible
	setupLogger()

	if (*remoteHost == "") {
		log.Warn("remote_host not set; mail will not be forwarded!")
	}

	setupAllowedNetworks()
}
