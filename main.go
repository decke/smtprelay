package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/chrj/smtpd"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
)

func connectionChecker(peer smtpd.Peer) error {
	// This can't panic because we only have TCP listeners
	peerIP := peer.Addr.(*net.TCPAddr).IP

	if len(allowedNets) == 0 {
		// Special case: empty string means allow everything
		return nil
	}

	for _, allowedNet := range allowedNets {
		if allowedNet.Contains(peerIP) {
			return nil
		}
	}

	log.Warn().
		Str("ip", peerIP.String()).
		Msg("Connection refused from address outside of allowed_nets")
	return smtpd.Error{Code: 421, Message: "Denied"}
}

func addrAllowed(addr string, allowedAddrs []string) bool {
	if allowedAddrs == nil {
		// If absent, all addresses are allowed
		return true
	}

	addr = strings.ToLower(addr)

	// Extract optional domain part
	domain := ""
	if idx := strings.LastIndex(addr, "@"); idx != -1 {
		domain = strings.ToLower(addr[idx+1:])
	}

	// Test each address from allowedUsers file
	for _, allowedAddr := range allowedAddrs {
		allowedAddr = strings.ToLower(allowedAddr)

		// Three cases for allowedAddr format:
		if idx := strings.Index(allowedAddr, "@"); idx == -1 {
			// 1. local address (no @) -- must match exactly
			if allowedAddr == addr {
				return true
			}
		} else {
			if idx != 0 {
				// 2. email address (user@domain.com) -- must match exactly
				if allowedAddr == addr {
					return true
				}
			} else {
				// 3. domain (@domain.com) -- must match addr domain
				allowedDomain := allowedAddr[idx+1:]
				if allowedDomain == domain {
					return true
				}
			}
		}
	}

	return false
}

func senderChecker(peer smtpd.Peer, addr string) error {
	// check sender address from auth file if user is authenticated
	if localAuthRequired() && peer.Username != "" {
		user, err := AuthFetch(peer.Username)
		if err != nil {
			// Shouldn't happen: authChecker already validated username+password
			log.Warn().
				Str("peer", peer.Addr.String()).
				Str("username", peer.Username).
				Err(err).
				Msg("could not fetch auth user")
			return smtpd.Error{Code: 451, Message: "Bad sender address"}
		}

		if !addrAllowed(addr, user.allowedAddresses) {
			log.Warn().
				Str("peer", peer.Addr.String()).
				Str("username", peer.Username).
				Str("sender_address", addr).
				Err(err).
				Msg("sender address not allowed for authenticated user")
			return smtpd.Error{Code: 451, Message: "Bad sender address"}
		}
	}

	if allowedSender == nil {
		// Any sender is permitted
		return nil
	}

	if allowedSender.MatchString(addr) {
		// Permitted by regex
		return nil
	}

	log.Warn().
		Str("sender_address", addr).
		Str("peer", peer.Addr.String()).
		Msg("sender address not allowed by allowed_sender pattern")
	return smtpd.Error{Code: 451, Message: "Bad sender address"}
}

func recipientChecker(peer smtpd.Peer, addr string) error {
	if allowedRecipients == nil {
		// Any recipient is permitted
		return nil
	}

	if allowedRecipients.MatchString(addr) {
		// Permitted by regex
		return nil
	}

	log.Warn().
		Str("peer", peer.Addr.String()).
		Str("recipient_address", addr).
		Msg("recipient address not allowed by allowed_recipients pattern")
	return smtpd.Error{Code: 451, Message: "Bad recipient address"}
}

func authChecker(peer smtpd.Peer, username string, password string) error {
	err := AuthCheckPassword(username, password)
	if err != nil {
		log.Warn().
			Str("peer", peer.Addr.String()).
			Str("username", username).
			Err(err).
			Msg("auth error")
		return smtpd.Error{Code: 535, Message: "Authentication credentials invalid"}
	}
	return nil
}

func mailHandler(peer smtpd.Peer, env smtpd.Envelope) error {
	peerIP := ""
	if addr, ok := peer.Addr.(*net.TCPAddr); ok {
		peerIP = addr.IP.String()
	}

	// Check for aliases
	aliasesMutex.RLock()
	for i, recipient := range env.Recipients {
		if alias, exists := aliasesList[recipient]; exists {
			env.Recipients[i] = alias
			log.Info().
				Str("original_recipient", recipient).
				Str("aliased_recipient", alias).
				Msg("Recipient address aliased")
		}
	}
	aliasesMutex.RUnlock()

	logger := log.With().
		Str("from", env.Sender).
		Strs("to", env.Recipients).
		Str("peer", peerIP).
		Str("uuid", generateUUID()).
		Logger()

	var envRemotes []*Remote

	if *strictSender {
		for _, remote := range remotes {
			if remote.Sender == env.Sender {
				envRemotes = append(envRemotes, remote)
			}
		}
	} else {
		envRemotes = remotes
	}

	if len(envRemotes) == 0 && *command == "" {
		logger.Warn().Msg("no remote_host or command set; discarding mail")
		return smtpd.Error{Code: 554, Message: "There are no appropriate remote_host or command"}
	}

	env.AddReceivedLine(peer)

	if *command != "" {
		cmdLogger := logger.With().Str("command", *command).Logger()

		var stdout bytes.Buffer
		var stderr bytes.Buffer

		environ := os.Environ()
		environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_FROM", env.Sender))
		environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_TO", env.Recipients))
		environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_PEER", peerIP))

		cmd := exec.Cmd{
			Env:  environ,
			Path: *command,
		}

		cmd.Stdin = bytes.NewReader(env.Data)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			cmdLogger.Error().Err(err).Msg(stderr.String())
			return smtpd.Error{Code: 554, Message: "External command failed"}
		}

		cmdLogger.Info().Msg("pipe command successful: " + stdout.String())
	}

	for _, remote := range envRemotes {
		logger = logger.With().Str("host", remote.Addr).Logger()
		logger.Info().Msg("delivering mail from peer using smarthost")

		err := SendMail(
			remote,
			env.Sender,
			env.Recipients,
			env.Data,
		)
		if err != nil {
			var smtpError smtpd.Error

			switch err := err.(type) {
			case *textproto.Error:
				smtpError = smtpd.Error{Code: err.Code, Message: err.Msg}

				logger.Error().
					Int("err_code", err.Code).
					Str("err_msg", err.Msg).
					Msg("delivery failed")
			default:
				smtpError = smtpd.Error{Code: 421, Message: "Forwarding failed"}

				logger.Error().
					Err(err).
					Msg("delivery failed")
			}

			return smtpError
		}

		logger.Debug().Msg("delivery successful")
	}

	return nil
}

func generateUUID() string {
	uniqueID, err := uuid.NewRandom()

	if err != nil {
		log.Error().
			Err(err).
			Msg("could not generate UUIDv4")

		return ""
	}

	return uniqueID.String()
}

func getTLSConfig() *tls.Config {
	// Certificate loading / validation
	if *localCert == "" || *localKey == "" {
		log.Fatal().
			Str("cert_file", *localCert).
			Str("key_file", *localKey).
			Msg("TLS certificate/key file not defined in config")
	}

	cert, err := tls.LoadX509KeyPair(*localCert, *localKey)
	if err != nil {
		log.Fatal().
			Err(err).
			Msg("cannot load X509 keypair")
	}

	// TLS profile configuration
	// tls.Config.CipherSuites only affects TLS 1.0–1.2.

	// Hardened: TLS 1.2 suites limited to modern AEAD + ECDHE.
	hardenedSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	// Extended: add CBC + RSA key exchange suites for legacy compatibility.
	extendedAdditionalSuites := []uint16{
		// CBC + ECDHE
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,

		// RSA key exchange
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}

	// Base config: Go defaults unless overridden.
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	profile := strings.ToLower(strings.TrimSpace(*tlsProfile))
	if profile == "" {
		profile = "default"
	}

	switch profile {
	case "default":
		// Go defaults (leave MinVersion/MaxVersion/CipherSuites unset).

	case "modern":
		// TLS 1.3 only.
		conf.MinVersion = tls.VersionTLS13
		conf.MaxVersion = tls.VersionTLS13

	case "hardened":
		// TLS 1.2+ with strict TLS 1.2 suite allowlist.
		conf.MinVersion = tls.VersionTLS12
		conf.CipherSuites = hardenedSuites

	case "extended":
		// TLS 1.2+ with hardened suites first, then compatibility fallbacks.
		conf.MinVersion = tls.VersionTLS12
		conf.CipherSuites = append(
			append([]uint16(nil), hardenedSuites...),
			extendedAdditionalSuites...,
		)

	case "legacy":
		// Last resort: TLS 1.0+ and everything Go exposes for TLS 1.0–1.2.
		conf.MinVersion = tls.VersionTLS10

		allSuites := []uint16{}
		for _, cs := range tls.CipherSuites() {
			allSuites = append(allSuites, cs.ID)
		}
		for _, cs := range tls.InsecureCipherSuites() {
			allSuites = append(allSuites, cs.ID)
		}
		conf.CipherSuites = allSuites

	default:
		log.Warn().
			Str("tls_profile", profile).
			Msg("unknown tls_profile; using default")
	}

	return conf
}

func watchAliasFile() {
	if *aliasFile == "" {
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error().
			Err(err).
			Msg("failed to create file watcher for alias file")
		return
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					log.Info().
						Str("file", event.Name).
						Msg("alias file changed, reloading")

					err := LoadAliases(*aliasFile)
					if err != nil {
						log.Error().
							Str("file", *aliasFile).
							Err(err).
							Msg("failed to reload alias file")
					} else {
						log.Info().
							Int("count", len(aliasesList)).
							Msg("alias file reloaded successfully")
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error().
					Err(err).
					Msg("file watcher error")
			}
		}
	}()

	err = watcher.Add(*aliasFile)
	if err != nil {
		log.Error().
			Str("file", *aliasFile).
			Err(err).
			Msg("failed to watch alias file")
	} else {
		log.Info().
			Str("file", *aliasFile).
			Msg("watching alias file for changes")
	}
}

func main() {
	ConfigLoad()

	log.Debug().
		Str("version", appVersion).
		Msg("starting smtprelay")

	// Load allowed users file
	if localAuthRequired() {
		err := AuthLoadFile(*allowedUsers)
		if err != nil {
			log.Fatal().
				Str("file", *allowedUsers).
				Err(err).
				Msg("cannot load allowed users file")
		}
	}

	// Start watching alias file for changes
	watchAliasFile()

	var servers []*smtpd.Server

	// Create a server for each desired listen address
	for _, listen := range listenAddrs {
		logger := log.With().Str("address", listen.address).Logger()

		server := &smtpd.Server{
			Hostname:          *hostName,
			WelcomeMessage:    *welcomeMsg,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			DataTimeout:       dataTimeout,
			MaxConnections:    *maxConnections,
			MaxMessageSize:    *maxMessageSize,
			MaxRecipients:     *maxRecipients,
			ConnectionChecker: connectionChecker,
			SenderChecker:     senderChecker,
			RecipientChecker:  recipientChecker,
			Handler:           mailHandler,
		}

		if localAuthRequired() {
			server.Authenticator = authChecker
		}

		var lsnr net.Listener
		var err error

		switch listen.protocol {
		case "":
			logger.Info().Msg("listening on address")
			lsnr, err = net.Listen("tcp", listen.address)

		case "starttls":
			server.TLSConfig = getTLSConfig()
			server.ForceTLS = *localForceTLS

			logger.Info().Msg("listening on address (STARTTLS)")
			lsnr, err = net.Listen("tcp", listen.address)

		case "tls":
			server.TLSConfig = getTLSConfig()

			logger.Info().Msg("listening on address (TLS)")
			lsnr, err = tls.Listen("tcp", listen.address, server.TLSConfig)

		default:
			logger.Fatal().
				Str("protocol", listen.protocol).
				Msg("unknown protocol in listen address")
		}

		if err != nil {
			logger.Fatal().
				Err(err).
				Msg("error starting listener")
		}
		servers = append(servers, server)

		go func() {
			server.Serve(lsnr)
		}()
	}

	handleSignals()

	// First close the listeners
	for _, server := range servers {
		logger := log.With().Str("address", server.Address().String()).Logger()
		logger.Debug().Msg("Shutting down server")
		err := server.Shutdown(false)
		if err != nil {
			logger.Warn().
				Err(err).
				Msg("Shutdown failed")
		}
	}

	// Then wait for the clients to exit
	for _, server := range servers {
		logger := log.With().Str("address", server.Address().String()).Logger()
		logger.Debug().Msg("Waiting for server")
		err := server.Wait()
		if err != nil {
			logger.Warn().
				Err(err).
				Msg("Wait failed")
		}
	}

	log.Debug().Msg("done")

	closeLogger()
}

func handleSignals() {
	// Wait for SIGINT, SIGQUIT, or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	sig := <-sigs

	log.Info().
		Str("signal", sig.String()).
		Msg("shutting down in response to received signal")
}
