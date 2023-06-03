package https

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
)

// Path separator in URLs.
const URLSeparator = "/"

// Adapter is an HTTP(S) handler that invokes another HTTP(S) handler.
type Adapter func(h http.Handler) http.Handler

// Adapt returns an HTTP(S) handler enhanced by a number of adapters.
func Adapt(h http.Handler, adapters ...Adapter) http.Handler {
	for _, adapter := range adapters {
		h = adapter(h)
	}
	return h
}

// StripPrefix returns an adapter that calls http.StripPrefix
// to remove the given prefix from the request's URL path and invoke
// the handler h.
func StripPrefix(prefix string) Adapter {
	return func(h http.Handler) http.Handler {
		return http.StripPrefix(prefix, h)
	}
}

// RedirectRootToParentTree is an adapter that redirects a request with
// URL path /tree/ to /tree.
func RedirectRootToParentTree(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, URLSeparator) {
			path := strings.TrimSuffix(r.URL.Path, URLSeparator)
			u := &url.URL{Path: path, RawQuery: r.URL.RawQuery}
			http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
			return
		}

		// Call the next handler in the chain.
		h.ServeHTTP(w, r)
	})
}

// LogRequest logs an HTTPS request.
func (s *HTTPSServer) LogRequest(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logRequest(
			"accepted: %s => %s %s Referrer[%s] TLSv%s SNI[%s] ALPN[%s] Cipher[%d]",
			r.RemoteAddr,
			r.Method,
			r.URL.String(),
			r.Referer(),
			MapTLSVersion(r.TLS.Version),
			r.TLS.ServerName,
			r.TLS.NegotiatedProtocol,
			r.TLS.CipherSuite,
		)

		// Call the next handler in the chain.
		h.ServeHTTP(w, r)
	})
}

// VerifyResourceAllowed checks whether the resource represented by URL path is allowed.
func (s *HTTPSServer) VerifyResourceAllowed(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.allowedResources != nil && s.allowedResources.Contains(r.URL.Path) {
			// Call the next handler in the chain.
			h.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})
}

// AllowOnlyGET blocks non-GET requests.
func (s *HTTPSServer) AllowOnlyGET(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			s.warnRequest(
				"blocked: %s => %s %s reason: restricted method",
				r.RemoteAddr,
				r.Method,
				r.URL.String(),
			)
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Call the next handler in the chain.
		h.ServeHTTP(w, r)
	})
}

// MapTLSVersion maps the TLS version code to its string representation.
func MapTLSVersion(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "SSL"
	}
}
