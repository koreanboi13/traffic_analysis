package engine

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"go.uber.org/zap"
)

// Proxy wraps httputil.ReverseProxy to forward traffic to a backend.
type Proxy struct {
	reverseProxy *httputil.ReverseProxy
	logger       *zap.Logger
}

// NewProxy creates a reverse proxy that forwards all requests to backendURL.
// Uses the Rewrite field (not the deprecated Director).
func NewProxy(backendURL string, logger *zap.Logger) (*Proxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, fmt.Errorf("parse backend URL %q: %w", backendURL, err)
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.SetXForwarded()
			r.Out.Host = target.Host
		},
	}

	p := &Proxy{
		reverseProxy: rp,
		logger:       logger,
	}

	// Custom error handler: log proxy errors and return 502.
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("proxy error",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Error(err),
		)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	return p, nil
}

// ServeHTTP implements http.Handler — logs the request at Debug level and proxies it.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.logger.Debug("proxying request",
		zap.String("method", r.Method),
		zap.String("path", r.URL.RequestURI()),
		zap.String("remote", r.RemoteAddr),
	)
	p.reverseProxy.ServeHTTP(w, r)
}
