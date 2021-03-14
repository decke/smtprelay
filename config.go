package main

import (
	"flag"
	"net"
	"regexp"
	"net/smtp"

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
	allowedSenderStr  = flag.String("allowed_sender", "", "Regular expression for valid FROM EMail addresses")
	allowedSender     *regexp.Regexp
	allowedRecipStr   = flag.String("allowed_recipients", "", "Regular expression for valid TO EMail addresses")
	allowedRecipients *regexp.Regexp
	allowedUsers      = flag.String("allowed_users", "", "Path to file with valid users/passwords")
	remoteHost        = flag.String("remote_host", "", "Outgoing SMTP server")
	remoteUser        = flag.String("remote_user", "", "Username for authentication on outgoing SMTP server")
	remotePass        = flag.String("remote_pass", "", "Password for authentication on outgoing SMTP server")
	remoteAuthStr     = flag.String("remote_auth", "none", "Auth method on outgoing SMTP server (none, plain, login)")
	remoteAuth        smtp.Auth
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

func setupAllowedPatterns() {
	var err error

	if (*allowedSenderStr != "") {
		allowedSender, err = regexp.Compile(*allowedSenderStr)
		if err != nil {
			log.WithField("allowed_sender", *allowedSenderStr).
				WithError(err).
				Fatal("allowed_sender pattern invalid")
		}
	}

	if (*allowedRecipStr != "") {
		allowedRecipients, err = regexp.Compile(*allowedRecipStr)
		if err != nil {
			log.WithField("allowed_recipients", *allowedRecipStr).
				WithError(err).
				Fatal("allowed_recipients pattern invalid")
		}
	}
}


func setupRemoteAuth() {
	logger := log.WithField("remote_auth", *remoteAuthStr)

	// Remote auth disabled?
	switch *remoteAuthStr {
	case "", "none":
		if *remoteUser != "" {
			logger.Fatal("remote_user given but not used")
		}
		if *remotePass != "" {
			logger.Fatal("remote_pass given but not used")
		}

		// No auth; use empty default
		return
	}

	// We need a username, password, and remote host
	if *remoteUser == "" {
		logger.Fatal("remote_user required but empty")
	}
	if *remotePass == "" {
		logger.Fatal("remote_pass required but empty")
	}
	if *remoteHost == "" {
		logger.Fatal("remote_auth without remote_host is pointless")
	}

	host, _, err := net.SplitHostPort(*remoteHost)
	if err != nil {
		logger.WithField("remote_host", *remoteHost).
			   Fatal("Invalid remote_host")
	}

	switch *remoteAuthStr {
	case "plain":
		remoteAuth = smtp.PlainAuth("", *remoteUser, *remotePass, host)
	case "login":
		remoteAuth = LoginAuth(*remoteUser, *remotePass)
	default:
		logger.Fatal("Invalid remote_auth type")
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
	setupAllowedPatterns()
	setupRemoteAuth()
}
