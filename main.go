package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/chrj/smtpd"
)

func connectionChecker(peer smtpd.Peer) error {
	var peerIP net.IP
	if addr, ok := peer.Addr.(*net.TCPAddr); ok {
		peerIP = net.ParseIP(addr.IP.String())
	} else {
		return smtpd.Error{Code: 421, Message: "Denied"}
	}

	nets := strings.Split(*allowedNets, " ")

	for i := range nets {
		_, allowedNet, _ := net.ParseCIDR(nets[i])

		if allowedNet.Contains(peerIP) {
			return nil
		}
	}

	return smtpd.Error{Code: 421, Message: "Denied"}
}

func senderChecker(peer smtpd.Peer, addr string) error {
	// check sender address from auth file if user is authenticated
	if *allowedUsers != "" && peer.Username != "" {
		_, email, err := AuthFetch(peer.Username)
		if err != nil {
			return smtpd.Error{Code: 451, Message: "Bad sender address"}
		}

		if strings.ToLower(addr) != strings.ToLower(email) {
			return smtpd.Error{Code: 451, Message: "Bad sender address"}
		}
	}

	if *allowedSender == "" {
		return nil
	}

	re, err := regexp.Compile(*allowedSender)
	if err != nil {
		log.Printf("allowed_sender invalid: %v\n", err)
		return smtpd.Error{Code: 451, Message: "Bad sender address"}
	}

	if re.MatchString(addr) {
		return nil
	}

	return smtpd.Error{Code: 451, Message: "Bad sender address"}
}

func recipientChecker(peer smtpd.Peer, addr string) error {
	if *allowedRecipients == "" {
		return nil
	}

	re, err := regexp.Compile(*allowedRecipients)
	if err != nil {
		log.Printf("allowed_recipients invalid: %v\n", err)
		return smtpd.Error{Code: 451, Message: "Bad recipient address"}
	}

	if re.MatchString(addr) {
		return nil
	}

	return smtpd.Error{Code: 451, Message: "Bad recipient address"}
}

func authChecker(peer smtpd.Peer, username string, password string) error {
	err := AuthCheckPassword(username, password)
	if err != nil {
		log.Printf("Auth error: %v\n", err)
		return smtpd.Error{Code: 535, Message: "Authentication credentials invalid"}
	}
	return nil
}

func mailHandler(peer smtpd.Peer, env smtpd.Envelope) error {
	peerIP := ""
	if addr, ok := peer.Addr.(*net.TCPAddr); ok {
		peerIP = addr.IP.String()
	}

	log.Printf("new mail from=<%s> to=%s peer=[%s]\n", env.Sender,
		env.Recipients, peerIP)

	var auth smtp.Auth
	host, _, _ := net.SplitHostPort(*remoteHost)

	if *remoteUser != "" && *remotePass != "" {
		switch *remoteAuth {
		case "plain":
			auth = smtp.PlainAuth("", *remoteUser, *remotePass, host)
		case "login":
			auth = LoginAuth(*remoteUser, *remotePass)
		default:
			return smtpd.Error{Code: 530, Message: "Authentication method not supported"}
		}
	}

	env.AddReceivedLine(peer)

	log.Printf("delivering using smarthost %s\n", *remoteHost)

	var sender string

	if *remoteSender == "" {
		sender = env.Sender
	} else {
		sender = *remoteSender
	}

	err := SendMail(
		*remoteHost,
		auth,
		sender,
		env.Recipients,
		env.Data,
	)
	if err != nil {
		log.Printf("delivery failed: %v\n", err)
		return smtpd.Error{Code: 554, Message: "Forwarding failed"}
	}

	log.Printf("%s delivery successful\n", env.Recipients)

	return nil
}

func main() {
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
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // does not provide PFS
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // does not provide PFS
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	ConfigLoad()

	if *versionInfo {
		fmt.Printf("smtprelay/%s\n", VERSION)
		os.Exit(0)
	}

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Fatalf("Error opening logfile: %v", err)
		}
		defer f.Close()

		log.SetOutput(io.MultiWriter(os.Stdout, f))
	}

	listeners := strings.Split(*listen, " ")

	for i := range listeners {
		listener := listeners[i]

		server := &smtpd.Server{
			Hostname:          *hostName,
			WelcomeMessage:    *welcomeMsg,
			ConnectionChecker: connectionChecker,
			SenderChecker:     senderChecker,
			RecipientChecker:  recipientChecker,
			Handler:           mailHandler,
		}

		if *allowedUsers != "" {
			err := AuthLoadFile(*allowedUsers)
			if err != nil {
				log.Fatalf("Authentication file: %s\n", err)
			}

			server.Authenticator = authChecker
		}

		if strings.Index(listeners[i], "://") == -1 {
			log.Printf("Listen on %s ...\n", listener)
			go server.ListenAndServe(listener)
		} else if strings.HasPrefix(listeners[i], "starttls://") {
			listener = strings.TrimPrefix(listener, "starttls://")

			if *localCert == "" || *localKey == "" {
				log.Fatal("TLS certificate/key not defined in config")
			}

			cert, err := tls.LoadX509KeyPair(*localCert, *localKey)
			if err != nil {
				log.Fatal(err)
			}

			server.TLSConfig = &tls.Config{
				PreferServerCipherSuites: true,
				MinVersion:               tls.VersionTLS11,
				CipherSuites:             tlsCipherSuites,
				Certificates:             []tls.Certificate{cert},
			}
			server.ForceTLS = *localForceTLS

			log.Printf("Listen on %s (STARTSSL) ...\n", listener)
			lsnr, err := net.Listen("tcp", listener)
			if err != nil {
				log.Fatal(err)
			}
			defer lsnr.Close()

			go server.Serve(lsnr)
		} else if strings.HasPrefix(listeners[i], "tls://") {

			listener = strings.TrimPrefix(listener, "tls://")

			if *localCert == "" || *localKey == "" {
				log.Fatal("TLS certificate/key not defined in config")
			}

			cert, err := tls.LoadX509KeyPair(*localCert, *localKey)
			if err != nil {
				log.Fatal(err)
			}

			server.TLSConfig = &tls.Config{
				PreferServerCipherSuites: true,
				MinVersion:               tls.VersionTLS11,
				CipherSuites:             tlsCipherSuites,
				Certificates:             []tls.Certificate{cert},
			}

			log.Printf("Listen on %s (TLS) ...\n", listener)
			lsnr, err := tls.Listen("tcp", listener, server.TLSConfig)
			if err != nil {
				log.Fatal(err)
			}
			defer lsnr.Close()

			go server.Serve(lsnr)
		} else {
			log.Fatal("Unknown protocol in listener ", listener)
		}
	}

	for true {
		time.Sleep(time.Minute)
	}
}
