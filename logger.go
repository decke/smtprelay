package main

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	log *logrus.Entry
)

func setupLogger() {
	logger := logrus.New()
	writer, err := os.OpenFile(*logFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("cannot open log file: %s", err)
		os.Exit(1)
	}

	logger.SetOutput(writer)
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat:   time.RFC3339Nano,
		DisableHTMLEscape: true,
	})

	log = logrus.NewEntry(logger)

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.DebugLevel

		log.WithField("given_level", *logLevel).
			Warn("could not parse log level, defaulting to 'debug'")
	}

	logrus.SetLevel(level)
}
