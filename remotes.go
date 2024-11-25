package main

import (
	"fmt"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/memorystore"
)

type Remote struct {
	SkipVerify  bool
	Auth        smtp.Auth
	Scheme      string
	Hostname    string
	Port        string
	Addr        string
	Sender      string
	RateLimiter *limiter.Store
}

// ParseRemote creates a remote from a given url in the following format:
//
// smtp://[user[:password]@][netloc][:port][/remote_sender][?param1=value1&...]
// smtps://[user[:password]@][netloc][:port][/remote_sender][?param1=value1&...]
// starttls://[user[:password]@][netloc][:port][/remote_sender][?param1=value1&...]
//
// Supported Params:
// - skipVerify: can be "true" or empty to prevent ssl verification of remote server's certificate.
// - auth: can be "login" to trigger "LOGIN" auth instead of "PLAIN" auth
func ParseRemote(remoteURL string) (*Remote, error) {
	u, err := url.Parse(remoteURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "smtp" && u.Scheme != "smtps" && u.Scheme != "starttls" {
		return nil, fmt.Errorf("'%s' is not a supported relay scheme", u.Scheme)
	}

	hostname, port := u.Hostname(), u.Port()

	if port == "" {
		switch u.Scheme {
		case "smtp":
			port = "25"
		case "smtps":
			port = "465"
		case "starttls":
			port = "587"
		}
	}

	q := u.Query()
	r := &Remote{
		Scheme:   u.Scheme,
		Hostname: hostname,
		Port:     port,
		Addr:     fmt.Sprintf("%s:%s", hostname, port),
	}

	if u.User != nil {
		pass, _ := u.User.Password()
		user := u.User.Username()

		if hasAuth, authVal := q.Has("auth"), q.Get("auth"); hasAuth {
			if authVal != "login" {
				return nil, fmt.Errorf("Auth must be login or not present, received '%s'", authVal)
			}

			r.Auth = LoginAuth(user, pass)
		} else {
			r.Auth = smtp.PlainAuth("", user, pass, u.Hostname())
		}
	}

	if hasVal, skipVerify := q.Has("skipVerify"), q.Get("skipVerify"); hasVal && skipVerify != "false" {
		r.SkipVerify = true
	}

	if u.Path != "" {
		r.Sender = u.Path[1:]
	}

	if hasVal, rate := q.Has("rate"), q.Get("rate"); hasVal && strings.Contains(rate, "/") {
		i, err := strconv.ParseInt(strings.Split(rate, "/")[0], 10, 32)
		if err == nil {
			t, err := time.ParseDuration(strings.Split(rate, "/")[1])
			log.Infof("Configuring rate limiter %v/%v", i, t)
			if err == nil {
				store, err := memorystore.New(&memorystore.Config{
					Tokens:   uint64(i),
					Interval: t,
				})
				if err == nil {
					r.RateLimiter = &store
				}
			}
		}
	}

	return r, nil
}
