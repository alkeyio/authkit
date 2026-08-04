package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture status code and bytes written.
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += n
	return n, err
}

// AccessLog returns a middleware that logs each request in nginx combined log format:
//
//	$remote_addr - - [$time_local] "$method $uri $proto" $status $bytes "$referer" "$user_agent"
func AccessLog(lg *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)

			addr := r.RemoteAddr
			if i := strings.LastIndex(addr, ":"); i > 0 {
				addr = addr[:i]
			}

			referer := r.Referer()
			if referer == "" {
				referer = "-"
			}

			lg.Info(fmt.Sprintf(`%s - - [%s] "%s %s %s" %d %d "%s" "%s"`,
				addr,
				time.Now().Format("02/Jan/2006:15:04:05 -0700"),
				r.Method, r.URL.RequestURI(), r.Proto,
				rw.status, rw.bytes,
				referer, r.UserAgent(),
			))
		})
	}
}
