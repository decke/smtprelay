package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/chrj/smtpd"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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

	log.WithFields(logrus.Fields{
		"ip": peerIP,
	}).Warn("Connection refused from address outside of allowed_nets")
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
	if *allowedUsers != "" && peer.Username != "" {
		user, err := AuthFetch(peer.Username)
		if err != nil {
			// Shouldn't happen: authChecker already validated username+password
			log.WithFields(logrus.Fields{
				"peer": peer.Addr,
				"username": peer.Username,
			}).WithError(err).Warn("could not fetch auth user")
			return smtpd.Error{Code: 451, Message: "Bad sender address"}
		}

		if !addrAllowed(addr, user.allowedAddresses) {
			log.WithFields(logrus.Fields{
				"peer": peer.Addr,
				"username": peer.Username,
				"sender_address": addr,
			}).Warn("sender address not allowed for authenticated user")
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

	log.WithFields(logrus.Fields{
		"sender_address": addr,
		"peer": peer.Addr,
	}).Warn("sender address not allowed by allowed_sender pattern")
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

	log.WithFields(logrus.Fields{
		"peer": peer.Addr,
		"recipient_address": addr,
	}).Warn("recipient address not allowed by allowed_recipients pattern")
	return smtpd.Error{Code: 451, Message: "Bad recipient address"}
}

func authChecker(peer smtpd.Peer, username string, password string) error {
	err := AuthCheckPassword(username, password)
	if err != nil {
		log.WithFields(logrus.Fields{
			"peer": peer.Addr,
			"username": username,
		}).WithError(err).Warn("auth error")
		return smtpd.Error{Code: 535, Message: "Authentication credentials invalid"}
	}
	return nil
}

func mailHandler(peer smtpd.Peer, env smtpd.Envelope) error {
	peerIP := ""
	if addr, ok := peer.Addr.(*net.TCPAddr); ok {
		peerIP = addr.IP.String()
	}

	logger := log.WithFields(logrus.Fields{
		"from": env.Sender,
		"to": env.Recipients,
		"peer": peerIP,
		"host": *remoteHost,
		"uuid": generateUUID(),
	})

	if (*remoteHost == "") {
		logger.Warning("remote_host not set; discarding mail")
		return nil
	}

	logger.Info("delivering mail from peer using smarthost")

	env.AddReceivedLine(peer)

	var sender string

	if *remoteSender == "" {
		sender = env.Sender
	} else {
		sender = *remoteSender
	}

	err := SendMail(
		*remoteHost,
		remoteAuth,
		sender,
		env.Recipients,
		env.Data,
	)
	if err != nil {
		var smtpError smtpd.Error

		switch err.(type) {
		case *textproto.Error:
			err := err.(*textproto.Error)
			smtpError = smtpd.Error{Code: err.Code, Message: err.Msg}

			logger.WithFields(logrus.Fields{
				"err_code": err.Code,
				"err_msg": err.Msg,
			}).Error("delivery failed")
		default:
			smtpError = smtpd.Error{Code: 554, Message: "Forwarding failed"}

			logger.WithError(err).
				Error("delivery failed")
		}

		return smtpError
	}

	logger.Debug("delivery successful")
	return nil
}

func generateUUID() string {
	uniqueID, err := uuid.NewRandom()

	if err != nil {
		log.WithError(err).
			Error("could not generate UUIDv4")

		return ""
	}

	return uniqueID.String()
}

func getTLSConfig() *tls.Config {
	// Ciphersuites as defined in stock Go but without 3DES and RC4
	// https://golang.org/src/crypto/tls/cipher_suites.go
	var tlsCipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // does not provide PFS
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // does not provide PFS
	}

	if *localCert == "" || *localKey == "" {
		log.WithFields(logrus.Fields{
			"cert_file": *localCert,
			"key_file": *localKey,
		}).Fatal("TLS certificate/key file not defined in config")
	}

	cert, err := tls.LoadX509KeyPair(*localCert, *localKey)
	if err != nil {
		log.WithField("error", err).
			Fatal("cannot load X509 keypair")
	}

	return &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites:             tlsCipherSuites,
		Certificates:             []tls.Certificate{cert},
	}
}

func main() {
	ConfigLoad()

	if *versionInfo {
		fmt.Printf("smtprelay/%s (%s)\n", appVersion, buildTime)
		os.Exit(0)
	}

	log.WithField("version", appVersion).
		Debug("starting smtprelay")

	// Load allowed users file
	if *allowedUsers != "" {
		err := AuthLoadFile(*allowedUsers)
		if err != nil {
			log.WithField("file", *allowedUsers).
				WithError(err).
				Fatal("cannot load allowed users file")
		}
	}

	// Create a server for each desired listen address
	for _, listenAddr := range strings.Split(*listen, " ") {
		server := &smtpd.Server{
			Hostname:          *hostName,
			WelcomeMessage:    *welcomeMsg,
			ConnectionChecker: connectionChecker,
			SenderChecker:     senderChecker,
			RecipientChecker:  recipientChecker,
			Handler:           mailHandler,
		}

		if *allowedUsers != "" {
			server.Authenticator = authChecker
		}

		var lsnr net.Listener
		var err error

		if strings.Index(listenAddr, "://") == -1 {
			log.WithField("address", listenAddr).
				Info("listening on address")

			lsnr, err = net.Listen("tcp", listenAddr)
		} else if strings.HasPrefix(listenAddr, "starttls://") {
			listenAddr = strings.TrimPrefix(listenAddr, "starttls://")

			server.TLSConfig = getTLSConfig()
			server.ForceTLS = *localForceTLS

			log.WithField("address", listenAddr).
				Info("listening on address (STARTTLS)")
			lsnr, err = net.Listen("tcp", listenAddr)
		} else if strings.HasPrefix(listenAddr, "tls://") {
			listenAddr = strings.TrimPrefix(listenAddr, "tls://")

			server.TLSConfig = getTLSConfig()

			log.WithField("address", listenAddr).
				Info("listening on address (TLS)")
			lsnr, err = tls.Listen("tcp", listenAddr, server.TLSConfig)
		} else {
			log.WithField("address", listenAddr).
				Fatal("unknown protocol in listen address")
		}

		if err != nil {
			log.WithFields(logrus.Fields{
				"address": listenAddr,
			}).WithError(err).Fatal("error starting listener")
		}
		defer lsnr.Close()

		go server.Serve(lsnr)
	}

	for true {
		time.Sleep(time.Minute)
	}
}
