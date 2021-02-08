package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
)

var (
	requestsCounter prometheus.Counter
	failuresCounter *prometheus.CounterVec
)

func registerMetrics() {
	requestsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "smtprelay",
		Subsystem: "delivery",
		Name:      "requests_count",
		Help:      "count of message relay requests",
	})

	failuresCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "smtprelay",
		Subsystem: "delivery",
		Name:      "failures_count",
		Help:      "count of unsuccessfully delivered messages",
	}, []string{"error_code"})
}

func handleMetrics() {
	registerMetrics()

	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("cannot publish metrics: %s", err.Error())
	}
}
