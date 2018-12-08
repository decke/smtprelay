package main

import (
	"flag"
	"fmt"
	"net/smtp"

	"github.com/chrj/smtpd"
	"github.com/vharitonsky/iniflags"
)

var (
	hostName   = flag.String("hostname", "localhost.localdomain", "Server hostname")
	welcomeMsg = flag.String("welcome_msg", "", "Welcome message for SMTP session")
	localHost  = flag.String("local_host", "localhost", "Address to listen for incoming SMTP")
	localPort  = flag.Int("local_port", 25, "Port to listen")
	remoteHost = flag.String("remote_host", "smtp.gmail.com", "Outgoing SMTP host")
	remotePort = flag.Int("remote_port", 587, "Outgoing SMTP port")
	remoteUser = flag.String("remote_user", "", "Username for authentication on outgoing SMTP server")
	remotePass = flag.String("remote_pass", "", "Password for authentication on outgoing SMTP server")
)

func handler(peer smtpd.Peer, env smtpd.Envelope) error {

	return smtp.SendMail(
		fmt.Sprintf("%s:%d", *remoteHost, *remotePort),
		smtp.PlainAuth("", *remoteUser, *remotePass, *remoteHost),
		env.Sender,
		env.Recipients,
		env.Data,
	)
}

func main() {

	iniflags.Parse()

	server := &smtpd.Server{
		Hostname:	*hostName,
		WelcomeMessage: *welcomeMsg,
		Handler:        handler,
	}

	server.ListenAndServe(fmt.Sprintf("%s:%d", *localHost, *localPort))
}
