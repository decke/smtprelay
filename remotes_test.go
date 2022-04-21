package main

import (
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func AssertRemoteUrlEquals(t *testing.T, expected *Remote, remotUrl string) {
	actual, err := ParseRemote(remotUrl)
	assert.Nil(t, err)
	assert.NotNil(t, actual)
	assert.Equal(t, expected.Scheme, actual.Scheme, "Scheme %s", remotUrl)
	assert.Equal(t, expected.Addr, actual.Addr, "Addr %s", remotUrl)
	assert.Equal(t, expected.Hostname, actual.Hostname, "Hostname %s", remotUrl)
	assert.Equal(t, expected.Port, actual.Port, "Port %s", remotUrl)
	assert.Equal(t, expected.Sender, actual.Sender, "Sender %s", remotUrl)
	assert.Equal(t, expected.SkipVerify, actual.SkipVerify, "SkipVerify %s", remotUrl)

	if expected.Auth != nil || actual.Auth != nil {
		assert.NotNil(t, expected, "Auth %s", remotUrl)
		assert.NotNil(t, actual, "Auth %s", remotUrl)
		assert.IsType(t, expected.Auth, actual.Auth)
	}
}

func TestValidRemoteUrls(t *testing.T) {
	AssertRemoteUrlEquals(t, &Remote{
		Scheme:     "smtp",
		SkipVerify: false,
		Auth:       nil,
		Hostname:   "email.com",
		Port:       "25",
		Addr:       "email.com:25",
		Sender:     "",
	}, "smtp://email.com")

	AssertRemoteUrlEquals(t, &Remote{
		Scheme:     "smtp",
		SkipVerify: true,
		Auth:       nil,
		Hostname:   "email.com",
		Port:       "25",
		Addr:       "email.com:25",
		Sender:     "",
	}, "smtp://email.com?skipVerify")

	AssertRemoteUrlEquals(t, &Remote{
		Scheme:     "smtp",
		SkipVerify: false,
		Auth:       smtp.PlainAuth("", "user", "pass", ""),
		Hostname:   "email.com",
		Port:       "25",
		Addr:       "email.com:25",
		Sender:     "",
	}, "smtp://user:pass@email.com")

	AssertRemoteUrlEquals(t, &Remote{
		Scheme:     "smtp",
		SkipVerify: false,
		Auth:       LoginAuth("user", "pass"),
		Hostname:   "email.com",
		Port:       "25",
		Addr:       "email.com:25",
		Sender:     "",
	}, "smtp://user:pass@email.com?auth=login")

	AssertRemoteUrlEquals(t, &Remote{
		Scheme:     "smtp",
		SkipVerify: false,
		Auth:       LoginAuth("user", "pass"),
		Hostname:   "email.com",
		Port:       "25",
		Addr:       "email.com:25",
		Sender:     "sender@website.com",
	}, "smtp://user:pass@email.com/sender@website.com?auth=login")

	AssertRemoteUrlEquals(t, &Remote{
		Scheme:     "smtps",
		SkipVerify: false,
		Auth:       LoginAuth("user", "pass"),
		Hostname:   "email.com",
		Port:       "465",
		Addr:       "email.com:465",
		Sender:     "sender@website.com",
	}, "smtps://user:pass@email.com/sender@website.com?auth=login")

	AssertRemoteUrlEquals(t, &Remote{
		Scheme:     "smtps",
		SkipVerify: true,
		Auth:       LoginAuth("user", "pass"),
		Hostname:   "email.com",
		Port:       "8425",
		Addr:       "email.com:8425",
		Sender:     "sender@website.com",
	}, "smtps://user:pass@email.com:8425/sender@website.com?auth=login&skipVerify")

	AssertRemoteUrlEquals(t, &Remote{
		Scheme:     "starttls",
		SkipVerify: true,
		Auth:       LoginAuth("user", "pass"),
		Hostname:   "email.com",
		Port:       "8425",
		Addr:       "email.com:8425",
		Sender:     "sender@website.com",
	}, "starttls://user:pass@email.com:8425/sender@website.com?auth=login&skipVerify")
}

func TestMissingScheme(t *testing.T) {
	_, err := ParseRemote("http://user:pass@email.com:8425/sender@website.com")
	assert.NotNil(t, err, "Err must be present")
	assert.Equal(t, err.Error(), "'http' is not a supported relay scheme")
}
