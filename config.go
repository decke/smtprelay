package main

import (
	"flag"
	"net"
	"net/smtp"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vharitonsky/iniflags"
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
	listenStr         = flag.String("listen", "127.0.0.1:25 [::1]:25", "Address and port to listen for incoming SMTP")
	listenAddrs       = []protoAddr{}
	localCert         = flag.String("local_cert", "", "SSL certificate for STARTTLS/TLS")
	localKey          = flag.String("local_key", "", "SSL private key for STARTTLS/TLS")
	localForceTLS     = flag.Bool("local_forcetls", false, "Force STARTTLS (needs local_cert and local_key)")
	readTimeoutStr    = flag.String("read_timeout", "60s", "Socket timeout for read operations")
	readTimeout       time.Duration
	writeTimeoutStr   = flag.String("write_timeout", "60s", "Socket timeout for write operations")
	writeTimeout      time.Duration
	dataTimeoutStr    = flag.String("data_timeout", "5m", "Socket timeout for DATA command")
	dataTimeout       time.Duration
	maxConnections    = flag.Int("max_connections", 100, "Max concurrent connections, use -1 to disable")
	maxMessageSize    = flag.Int("max_message_size", 10240000, "Max message size in bytes")
	maxRecipients     = flag.Int("max_recipients", 100, "Max RCPT TO calls for each envelope")
	allowedNetsStr    = flag.String("allowed_nets", "127.0.0.0/8 ::1/128", "Networks allowed to send mails")
	allowedNets       = []*net.IPNet{}
	allowedSenderStr  = flag.String("allowed_sender", "", "Regular expression for valid FROM EMail addresses")
	allowedSender     *regexp.Regexp
	allowedRecipStr   = flag.String("allowed_recipients", "", "Regular expression for valid TO EMail addresses")
	allowedRecipients *regexp.Regexp
	allowedUsers      = flag.String("allowed_users", "", "Path to file with valid users/passwords")
	command           = flag.String("command", "", "Path to pipe command")
	remoteHost        = flag.String("remote_host", "", "Outgoing SMTP server")
	remoteSkipVerify  = flag.Bool("remote_skip_verify", false, "Ignore invalid remote certificates")
	remoteUser        = flag.String("remote_user", "", "Username for authentication on outgoing SMTP server")
	remotePass        = flag.String("remote_pass", "", "Password for authentication on outgoing SMTP server")
	remoteAuthStr     = flag.String("remote_auth", "none", "Auth method on outgoing SMTP server (none, plain, login)")
	remoteAuth        smtp.Auth
	remoteSender      = flag.String("remote_sender", "", "Sender e-mail address on outgoing SMTP server")
	versionInfo       = flag.Bool("version", false, "Show version information")
)

func localAuthRequired() bool {
	return *allowedUsers != ""
}

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
				"given_net":  netstr,
				"proper_net": allowedNet,
			}).Fatal("Invalid network in allowed_nets (host bits set)")
		}

		allowedNets = append(allowedNets, allowedNet)
	}
}

func setupAllowedPatterns() {
	var err error

	if *allowedSenderStr != "" {
		allowedSender, err = regexp.Compile(*allowedSenderStr)
		if err != nil {
			log.WithField("allowed_sender", *allowedSenderStr).
				WithError(err).
				Fatal("allowed_sender pattern invalid")
		}
	}

	if *allowedRecipStr != "" {
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
	if *remoteAuthStr == "" || *remoteAuthStr == "none" {
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

type protoAddr struct {
	protocol string
	address  string
}

func splitProto(s string) protoAddr {
	idx := strings.Index(s, "://")
	if idx == -1 {
		return protoAddr{
			address: s,
		}
	}
	return protoAddr{
		protocol: s[0:idx],
		address:  s[idx+3:],
	}
}

func setupListeners() {
	for _, listenAddr := range strings.Split(*listenStr, " ") {
		pa := splitProto(listenAddr)

		if localAuthRequired() && pa.protocol == "" {
			log.WithField("address", pa.address).
				Fatal("Local authentication (via allowed_users file) " +
					"not allowed with non-TLS listener")
		}

		listenAddrs = append(listenAddrs, pa)
	}
}

func setupTimeouts() {
	var err error

	readTimeout, err = time.ParseDuration(*readTimeoutStr)
	if err != nil {
		log.WithField("read_timeout", *readTimeoutStr).
			WithError(err).
			Fatal("read_timeout duration string invalid")
	}
	if readTimeout.Seconds() < 1 {
		log.WithField("read_timeout", *readTimeoutStr).
			Fatal("read_timeout less than one second")
	}

	writeTimeout, err = time.ParseDuration(*writeTimeoutStr)
	if err != nil {
		log.WithField("write_timeout", *writeTimeoutStr).
			WithError(err).
			Fatal("write_timeout duration string invalid")
	}
	if writeTimeout.Seconds() < 1 {
		log.WithField("write_timeout", *writeTimeoutStr).
			Fatal("write_timeout less than one second")
	}

	dataTimeout, err = time.ParseDuration(*dataTimeoutStr)
	if err != nil {
		log.WithField("data_timeout", *dataTimeoutStr).
			WithError(err).
			Fatal("data_timeout duration string invalid")
	}
	if dataTimeout.Seconds() < 1 {
		log.WithField("data_timeout", *dataTimeoutStr).
			Fatal("data_timeout less than one second")
	}
}

func ConfigLoad() {
	iniflags.Parse()

	// Set up logging as soon as possible
	setupLogger()

	if *remoteHost == "" && *command == "" {
		log.Warn("no remote_host or command set; mail will not be forwarded!")
	}

	setupAllowedNetworks()
	setupAllowedPatterns()
	setupRemoteAuth()
	setupListeners()
	setupTimeouts()
}
