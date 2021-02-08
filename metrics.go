package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
)

var (
	requestsCounter   prometheus.Counter
	errorsCounter     *prometheus.CounterVec
	durationHistogram *prometheus.HistogramVec
)

func registerMetrics() {
	requestsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "smtprelay",
		Name:      "requests_count",
		Help:      "count of message relay requests",
	})

	errorsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "smtprelay",
		Name:      "errors_count",
		Help:      "count of unsuccessfully relayed messages",
	}, []string{"error_code"})

	durationHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "smtprelay",
		Name:      "request_duration",
		Buckets:   prometheus.DefBuckets,
	}, []string{"error_code"})
}

func handleMetrics() {
	registerMetrics()

	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(*metricsListen, nil); err != nil {
		log.Fatalf("cannot publish metrics: %s", err.Error())
	}
}
