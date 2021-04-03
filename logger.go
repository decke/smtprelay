package main

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	log *logrus.Logger
)

func setupLogger() {
	log = logrus.New()

	// Handle logfile
	if *logFile == "" {
		log.SetOutput(os.Stderr)
	} else {
		writer, err := os.OpenFile(*logFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			fmt.Printf("cannot open log file: %s\n", err)
			os.Exit(1)
		}

		log.SetOutput(writer)
	}

	// Handle log_format
	switch *logFormat {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat:   time.RFC3339Nano,
			DisableHTMLEscape: true,
		})
	case "plain":
		log.SetFormatter(&logrus.TextFormatter{
			DisableTimestamp: true,
		})
	case "", "default":
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	default:
		fmt.Fprintf(os.Stderr, "Invalid log_format: %s\n", *logFormat)
		os.Exit(1)
	}

	// Handle log_level
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.InfoLevel

		log.WithField("given_level", *logLevel).
			Warn("could not parse log level, defaulting to 'info'")
	}
	log.SetLevel(level)
}
