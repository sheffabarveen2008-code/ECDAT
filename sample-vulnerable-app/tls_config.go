package main

import (
	"crypto/tls"
	"net/http"
)

func SetupTLSConfig() *tls.Config {
	// Weak protocol configuration allowing TLS 1.0 and 1.1
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}
