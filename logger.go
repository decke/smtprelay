package main

import (
	"time"

	"github.com/sirupsen/logrus"
)

var (
	log *logrus.Entry
)

func setupLogger() {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat:   time.RFC3339Nano,
		DisableHTMLEscape: true,
	})

	log = logrus.NewEntry(logger)

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.SetLevel(logrus.DebugLevel)
		log.WithField("given_level", *logLevel).
			Warn("could not parse log level, defaulting to 'debug'")
	} else {
		logrus.SetLevel(level)
	}
}
