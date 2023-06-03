package https

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cicovic-andrija/libgo/logging"
	"github.com/cicovic-andrija/libgo/set"
)

type HTTPSServer struct {
	httpsImpl        *http.Server
	serveMux         *http.ServeMux
	commonAdapters   []Adapter
	tlsCertPath      string
	tlsKeyPath       string
	started          bool
	startedAt        time.Time
	shutdownSem      *sync.WaitGroup
	generalLog       *logging.FileLog
	requestLog       *logging.FileLog
	allowedResources set.Strings
}

func (s *HTTPSServer) Handle(pattern string, handler http.Handler) {
	s.serveMux.Handle(
		pattern,
		Adapt(handler, s.commonAdapters...),
	)
	s.log("handler registered for %s", pattern)
}

func (s *HTTPSServer) ListenAndServeAsync(errorChannel chan error) {
	if !s.started {
		s.shutdownSem.Add(1)
		go func() {
			shutdownError := s.httpsImpl.ListenAndServeTLS(s.tlsCertPath, s.tlsKeyPath)
			s.shutdownSem.Done()
			if !errors.Is(shutdownError, http.ErrServerClosed) {
				errorChannel <- s.error("server stopped unexpectedly: %v", shutdownError)
			}
		}()

		s.startedAt = time.Now().UTC()
		s.started = true
		s.log("server started listening for connections on %s", s.httpsImpl.Addr)
	}
}

func (s *HTTPSServer) Shutdown() error {
	if s.started {
		s.log("server interrupted, shutting down...")
		shutdownErr := s.httpsImpl.Shutdown(context.TODO())
		s.shutdownSem.Wait()
		if shutdownErr != nil {
			return s.error("server shutdown: error encountered: %v", shutdownErr)
		}
		s.log("server was successfully shut down")
	}
	return nil
}

func (s *HTTPSServer) GetLogPath() string {
	return s.generalLog.LogPath()
}

func (s *HTTPSServer) GetRequestsLogPath() string {
	if s.requestLog != nil {
		return s.requestLog.LogPath()
	}
	return ""
}

func (s *HTTPSServer) log(format string, v ...interface{}) {
	s.generalLog.Output(logging.SevInfo, 2, format, v...)
}

func (s *HTTPSServer) logRequest(format string, v ...interface{}) {
	s.requestLog.Output(logging.SevInfo, 2, format, v...)
}

func (s *HTTPSServer) warnRequest(format string, v ...interface{}) {
	s.requestLog.Output(logging.SevWarn, 2, format, v...)
}

func (s *HTTPSServer) error(format string, v ...interface{}) error {
	err := fmt.Errorf(format, v...)
	s.generalLog.Output(logging.SevError, 2, format, v...)
	return err
}
