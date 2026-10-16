package main

import (
	"fmt"
	"net"
	"net/textproto"
	"testing"
	"time"
)

func TestSendMailIPv6Remote(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		result <- serveTestSMTP(listener)
	}()

	remote, err := ParseRemote("smtp://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := SendMail(remote, "sender@example.invalid", []string{"recipient@example.invalid"}, []byte("Subject: loopback test\r\n\r\nsynthetic fixture\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

// This sink accepts only the synthetic transaction used above, never relaying it.
func serveTestSMTP(listener net.Listener) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	text := textproto.NewConn(conn)
	if err := text.PrintfLine("220 loopback test"); err != nil {
		return err
	}
	commands := []struct{ command, response string }{
		{"EHLO " + *hostName, "250 loopback test"},
		{"MAIL FROM:<sender@example.invalid>", "250 OK"},
		{"RCPT TO:<recipient@example.invalid>", "250 OK"},
		{"DATA", "354 End with a dot"},
	}
	for _, step := range commands {
		line, err := text.ReadLine()
		if err != nil {
			return err
		}
		if line != step.command {
			return fmt.Errorf("command = %q, want %q", line, step.command)
		}
		if err := text.PrintfLine("%s", step.response); err != nil {
			return err
		}
	}
	data, err := text.ReadDotBytes()
	if err != nil {
		return err
	}
	if string(data) != "Subject: loopback test\n\nsynthetic fixture\n" {
		return fmt.Errorf("unexpected DATA: %q", data)
	}
	if err := text.PrintfLine("250 OK"); err != nil {
		return err
	}
	line, err := text.ReadLine()
	if err != nil {
		return err
	}
	if line != "QUIT" {
		return fmt.Errorf("command = %q, want QUIT", line)
	}
	return text.PrintfLine("221 Bye")
}
