package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3"
)

var (
	appVersion = "unknown"
	buildTime  = "unknown"
)

var (
	flagset = flag.NewFlagSet("smtprelay", flag.ContinueOnError)

	// config flags
	logFile          = flagset.String("logfile", "", "Path to logfile")
	logFormat        = flagset.String("log_format", "default", "Log output format")
	logLevel         = flagset.String("log_level", "info", "Minimum log level to output")
	hostName         = flagset.String("hostname", "localhost.localdomain", "Server hostname")
	welcomeMsg       = flagset.String("welcome_msg", "", "Welcome message for SMTP session")
	listenStr        = flagset.String("listen", "127.0.0.1:25 [::1]:25", "Address and port to listen for incoming SMTP")
	localCert        = flagset.String("local_cert", "", "SSL certificate for STARTTLS/TLS")
	localKey         = flagset.String("local_key", "", "SSL private key for STARTTLS/TLS")
	localForceTLS    = flagset.Bool("local_forcetls", false, "Force STARTTLS (needs local_cert and local_key)")
	readTimeoutStr   = flagset.String("read_timeout", "60s", "Socket timeout for read operations")
	writeTimeoutStr  = flagset.String("write_timeout", "60s", "Socket timeout for write operations")
	dataTimeoutStr   = flagset.String("data_timeout", "5m", "Socket timeout for DATA command")
	maxConnections   = flagset.Int("max_connections", 100, "Max concurrent connections, use -1 to disable")
	maxMessageSize   = flagset.Int("max_message_size", 10240000, "Max message size in bytes")
	maxRecipients    = flagset.Int("max_recipients", 100, "Max RCPT TO calls for each envelope")
	allowedNetsStr   = flagset.String("allowed_nets", "127.0.0.0/8 ::1/128", "Networks allowed to send mails")
	allowedSenderStr = flagset.String("allowed_sender", "", "Regular expression for valid FROM EMail addresses")
	allowedRecipStr  = flagset.String("allowed_recipients", "", "Regular expression for valid TO EMail addresses")
	allowedUsers     = flagset.String("allowed_users", "", "Path to file with valid users/passwords")
	command          = flagset.String("command", "", "Path to pipe command")
	remotesStr       = flagset.String("remotes", "", "Outgoing SMTP servers")
	strictSender     = flagset.Bool("strict_sender", false, "Use only SMTP servers with Sender matches to From")

	// additional flags
	_           = flagset.String("config", "", "Path to config file (ini format)")
	versionInfo = flagset.Bool("version", false, "Show version information")

	// internal
	listenAddrs       = []protoAddr{}
	readTimeout       time.Duration
	writeTimeout      time.Duration
	dataTimeout       time.Duration
	allowedNets       = []*net.IPNet{}
	allowedSender     *regexp.Regexp
	allowedRecipients *regexp.Regexp
	remotes           = []*Remote{}
)

func localAuthRequired() bool {
	return *allowedUsers != ""
}

func setupAllowedNetworks() {
	for _, netstr := range splitstr(*allowedNetsStr, ' ') {
		baseIP, allowedNet, err := net.ParseCIDR(netstr)
		if err != nil {
			log.Fatal().
				Str("netstr", netstr).
				Err(err).
				Msg("Invalid CIDR notation in allowed_nets")
		}

		// Reject any network specification where any host bits are set,
		// meaning the address refers to a host and not a network.
		if !allowedNet.IP.Equal(baseIP) {
			log.Fatal().
				Str("given_net", netstr).
				Str("proper_net", allowedNet.String()).
				Msg("Invalid network in allowed_nets (host bits set)")
		}

		allowedNets = append(allowedNets, allowedNet)
	}
}

func setupAllowedPatterns() {
	var err error

	if *allowedSenderStr != "" {
		allowedSender, err = regexp.Compile(*allowedSenderStr)
		if err != nil {
			log.Fatal().
				Str("allowed_sender", *allowedSenderStr).
				Err(err).
				Msg("allowed_sender pattern invalid")
		}
	}

	if *allowedRecipStr != "" {
		allowedRecipients, err = regexp.Compile(*allowedRecipStr)
		if err != nil {
			log.Fatal().
				Str("allowed_recipients", *allowedRecipStr).
				Err(err).
				Msg("allowed_recipients pattern invalid")
		}
	}
}

func setupRemotes() {
	logger := log.With().Str("remotes", *remotesStr).Logger()

	if *remotesStr != "" {
		for _, remoteURL := range strings.Split(*remotesStr, " ") {
			r, err := ParseRemote(remoteURL)
			if err != nil {
				logger.Fatal().Msg(fmt.Sprintf("error parsing url: '%s': %v", remoteURL, err))
			}

			remotes = append(remotes, r)
		}
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
			log.Fatal().
				Str("address", pa.address).
				Msg("Local authentication (via allowed_users file) " +
					"not allowed with non-TLS listener")
		}

		listenAddrs = append(listenAddrs, pa)
	}
}

func setupTimeouts() {
	var err error

	readTimeout, err = time.ParseDuration(*readTimeoutStr)
	if err != nil {
		log.Fatal().
			Str("read_timeout", *readTimeoutStr).
			Err(err).
			Msg("read_timeout duration string invalid")
	}
	if readTimeout.Seconds() < 1 {
		log.Fatal().
			Str("read_timeout", *readTimeoutStr).
			Msg("read_timeout less than one second")
	}

	writeTimeout, err = time.ParseDuration(*writeTimeoutStr)
	if err != nil {
		log.Fatal().
			Str("write_timeout", *writeTimeoutStr).
			Err(err).
			Msg("write_timeout duration string invalid")
	}
	if writeTimeout.Seconds() < 1 {
		log.Fatal().
			Str("write_timeout", *writeTimeoutStr).
			Msg("write_timeout less than one second")
	}

	dataTimeout, err = time.ParseDuration(*dataTimeoutStr)
	if err != nil {
		log.Fatal().
			Str("data_timeout", *dataTimeoutStr).
			Err(err).
			Msg("data_timeout duration string invalid")
	}
	if dataTimeout.Seconds() < 1 {
		log.Fatal().
			Str("data_timeout", *dataTimeoutStr).
			Msg("data_timeout less than one second")
	}
}

func ConfigLoad() {
	// use .env file if it exists
	if _, err := os.Stat(".env"); err == nil {
		if err := ff.Parse(flagset, os.Args[1:],
			ff.WithEnvVarPrefix("smtprelay"),
			ff.WithConfigFile(".env"),
			ff.WithConfigFileParser(ff.EnvParser),
		); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	} else {
		// use env variables and smtprelay.ini file
		if err := ff.Parse(flagset, os.Args[1:],
			ff.WithEnvVarPrefix("smtprelay"),
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(IniParser),
		); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	// Set up logging as soon as possible
	setupLogger()

	if *versionInfo {
		fmt.Printf("smtprelay/%s (%s)\n", appVersion, buildTime)
		os.Exit(0)
	}

	if *remotesStr == "" && *command == "" {
		log.Warn().Msg("no remotes or command set; mail will not be forwarded!")
	}

	setupAllowedNetworks()
	setupAllowedPatterns()
	setupRemotes()
	setupListeners()
	setupTimeouts()
}

// IniParser is a parser for config files in classic key/value style format. Each
// line is tokenized as a single key/value pair. The first "=" delimited
// token in the line is interpreted as the flag name, and all remaining tokens
// are interpreted as the value. Any leading hyphens on the flag name are
// ignored.
func IniParser(r io.Reader, set func(name, value string) error) error {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue // skip empties
		}

		if line[0] == '#' || line[0] == ';' {
			continue // skip comments
		}

		var (
			name  string
			value string
			index = strings.IndexRune(line, '=')
		)
		if index < 0 {
			name, value = line, "true" // boolean option
		} else {
			name, value = strings.TrimSpace(line[:index]), strings.Trim(strings.TrimSpace(line[index+1:]), "\"")
		}

		if i := strings.Index(value, " #"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}

		if err := set(name, value); err != nil {
			return err
		}
	}
	return nil
}
