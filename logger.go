package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/DeRuina/timberjack"
	"github.com/rs/zerolog"
)

var (
	rotator *timberjack.Logger
	log     *zerolog.Logger
)

func setupLogger() {
	zerolog.TimeFieldFormat = time.RFC3339

	// Handle logfile
	var writer io.Writer
	if *logFile == "" {
		writer = os.Stderr
	} else {
		rotator = &timberjack.Logger{
			Filename:         *logFile,
			MaxSize:          10, // megabytes before rotation
			MaxBackups:       3,
			MaxAge:           30, // days
			Compress:         true,
			BackupTimeFormat: "20060102150405",
		}
		writer = rotator
	}

	// Handle log_format
	switch *logFormat {
	case "json":
		// zerolog default is JSON
	case "plain":
		writer = zerolog.ConsoleWriter{
			Out:        writer,
			NoColor:    true,
			TimeFormat: "",
			FormatTimestamp: func(i interface{}) string {
				return "" // avoid default time
			},
		}
	case "", "default":
		writer = zerolog.ConsoleWriter{
			Out:        writer,
			NoColor:    true,
			TimeFormat: time.RFC3339,
		}
	case "pretty":
		writer = zerolog.ConsoleWriter{
			Out:        writer,
			TimeFormat: time.RFC3339Nano,
		}
	default:
		fmt.Fprintf(os.Stderr, "Invalid log_format: %s\n", *logFormat)
		os.Exit(1)
	}

	l := zerolog.New(writer).With().Timestamp().Logger()
	log = &l

	// Handle log_level
	level, err := zerolog.ParseLevel(strings.ToLower(*logLevel))
	if err != nil {
		level = zerolog.InfoLevel
		log.Warn().Str("given_level", *logLevel).
			Msg("could not parse log level, defaulting to 'info'")
	}
	zerolog.SetGlobalLevel(level)
}

// Call this on shutdown if you want to close the rotator and stop timers cleanly
func closeLogger() {
	if rotator != nil {
		rotator.Close()
	}
}
