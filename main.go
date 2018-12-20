package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/chrj/smtpd"
	"github.com/vharitonsky/iniflags"
)

const (
	VERSION = "1.0.2-dev"
)

var (
	logFile    = flag.String("logfile", "/var/log/smtpd-proxy.log", "Path to logfile")
	hostName   = flag.String("hostname", "localhost.localdomain", "Server hostname")
	welcomeMsg = flag.String("welcome_msg", "", "Welcome message for SMTP session")
	listen     = flag.String("listen", "127.0.0.1:25 [::1]:25", "Address and port to listen for incoming SMTP")
	localCert  = flag.String("local_cert", "", "SSL certificate for STARTTLS/TLS")
	localKey   = flag.String("local_key", "", "SSL private key for STARTTLS/TLS")
	localForceTLS = flag.Bool("local_forcetls", false, "Force STARTTLS (needs local_cert and local_key)")
        allowedNets = flag.String("allowed_nets", "127.0.0.1/8 ::1/128", "Networks allowed to send mails")
	remoteHost = flag.String("remote_host", "smtp.gmail.com:587", "Outgoing SMTP server")
	remoteUser = flag.String("remote_user", "", "Username for authentication on outgoing SMTP server")
	remotePass = flag.String("remote_pass", "", "Password for authentication on outgoing SMTP server")
	versionInfo= flag.Bool("version", false, "Show version information")
)

func connectionChecker(peer smtpd.Peer) error {
	var peerIP net.IP
	if addr, ok := peer.Addr.(*net.TCPAddr); ok {
		peerIP = net.ParseIP(addr.IP.String())
	} else {
		return smtpd.Error{Code: 552, Message: "Denied"}
	}

	nets := strings.Split(*allowedNets, " ")

	for i := range(nets) {
		_, allowedNet, _ := net.ParseCIDR(nets[i])

		if allowedNet.Contains(peerIP) {
			return nil
		}
	}

	return smtpd.Error{Code: 552, Message: "Denied"}
}

func senderChecker(peer smtpd.Peer, addr string) error {
	return nil
}

func recipientChecker(peer smtpd.Peer, addr string) error {
	return nil
}

func mailHandler(peer smtpd.Peer, env smtpd.Envelope) error {

	var auth smtp.Auth
	host, _, _ := net.SplitHostPort(*remoteHost)

	if *remoteUser != "" && *remotePass != "" {
		auth = smtp.PlainAuth("", *remoteUser, *remotePass, host)
	}

	env.AddReceivedLine(peer)

	return smtp.SendMail(
		*remoteHost,
		auth,
		env.Sender,
		env.Recipients,
		env.Data,
	)
}

func main() {

	iniflags.Parse()

	if *versionInfo {
		fmt.Printf("smtpd-proxy/%s\n", VERSION)
		os.Exit(0)
	}

	logwriter := io.Writer(os.Stdout)

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_WRONLY | os.O_CREATE | os.O_APPEND, 0600)
		if err != nil {
			log.Fatalf("Error opening logfile: %v", err)
		}
		defer f.Close()

		logwriter = io.MultiWriter(os.Stdout, f)
		log.SetOutput(logwriter)
	}

	listeners := strings.Split(*listen, " ")

	for i := range(listeners) {
		listener := listeners[i]

		server := &smtpd.Server{
			Hostname:		*hostName,
			WelcomeMessage:		*welcomeMsg,
			ConnectionChecker:	connectionChecker,
			SenderChecker:		senderChecker,
			RecipientChecker:	recipientChecker,
			Handler:		mailHandler,
			ProtocolLogger:		log.New(logwriter, "INBOUND: ", log.Lshortfile),
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

			server.TLSConfig = &tls.Config {
				Certificates: [] tls.Certificate{cert},
			}
			server.ForceTLS = *localForceTLS

			log.Printf("Listen on %s (STARTSSL) ...\n", listener)
			lsnr, err := net.Listen("tcp", listener)
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

			server.TLSConfig = &tls.Config {
				Certificates: [] tls.Certificate{cert},
			}

			log.Printf("Listen on %s (TLS) ...\n", listener)
			lsnr, err := tls.Listen("tcp", listener, server.TLSConfig)
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
