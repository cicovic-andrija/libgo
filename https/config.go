package https

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cicovic-andrija/libgo/fs"
	"github.com/cicovic-andrija/libgo/logging"
	"github.com/cicovic-andrija/libgo/set"
)

type Config struct {
	Network              NetworkConfig    `json:"network"`
	EnableFileServer     bool             `json:"enable_file_server"`
	FileServer           FileServerConfig `json:"file_server"`
	LogRequests          bool             `json:"log_requests"`
	LogsDirectory        string           `json:"logs_directory"`
	AllowOnlyGETRequests bool             `json:"allow_only_get_requests"`
}

type NetworkConfig struct {
	IPAcceptHost string `json:"ip_accept_host"`
	TCPPort      int    `json:"tcp_port"`
	TLSCertPath  string `json:"tls_cert_path"`
	TLSKeyPath   string `json:"tls_key_path"`
}

type FileServerConfig struct {
	URLPrefix string   `json:"url_prefix"`
	Directory string   `json:"directory"`
	Allowed   []string `json:"allowed"`
}

func NewServer(config *Config) (server *HTTPSServer, err error) {
	initError := func(format string, v ...interface{}) error {
		return fmt.Errorf("init: "+format, v...)
	}

	if config == nil {
		err = initError("empty config")
		return
	}

	var host string
	switch config.Network.IPAcceptHost {
	case "localhost":
		host = "127.0.0.1"
	case "any":
		host = "0.0.0.0"
	default:
		err = initError("invalid IP host descriptor")
		return
	}

	if config.Network.TCPPort < 0 || config.Network.TCPPort > 65535 {
		err = initError("invalid TCP port: %d", config.Network.TCPPort)
		return
	}

	if config.Network.TLSCertPath == "" {
		err = initError("TLS certificate not provided")
		return
	}

	if exists, _ := fs.FileExists(config.Network.TLSCertPath); !exists {
		err = initError("file not found: %s", config.Network.TLSCertPath)
		return
	}

	if config.Network.TLSKeyPath == "" {
		err = initError("TLS key not provided")
		return
	}

	if exists, _ := fs.FileExists(config.Network.TLSKeyPath); !exists {
		err = initError("file not found: %s", config.Network.TLSKeyPath)
		return
	}

	if config.EnableFileServer {
		if config.FileServer.Directory == "" {
			err = initError("file server directory not provided")
			return
		}
		if exists, _ := fs.DirectoryExists(config.FileServer.Directory); !exists {
			err = initError("directory not found: %s", config.FileServer.Directory)
			return
		}
		if config.FileServer.URLPrefix == "" {
			err = initError("file server URL prefix not provided")
			return
		}
	}

	if config.LogsDirectory == "" {
		err = initError("logs directory not provided")
		return
	}

	if exists, _ := fs.DirectoryExists(config.LogsDirectory); !exists {
		err = initError("directory not found: %s", config.LogsDirectory)
		return
	}

	var (
		generalLog *logging.FileLog = nil
		requestLog *logging.FileLog = nil
	)

	generalLog, err = logging.NewFileLog(filepath.Join(config.LogsDirectory, "https.log"))
	if err != nil {
		err = initError("failed to create log file: %v", err)
		return
	}

	if config.LogRequests {
		requestLog, err = logging.NewFileLog(filepath.Join(config.LogsDirectory, "requests.https.log"))
		if err != nil {
			err = initError("failed to create requests log file: %v", err)
			return
		}
	}

	serveMux := http.NewServeMux()

	server = &HTTPSServer{
		httpsImpl: &http.Server{
			Addr:     net.JoinHostPort(host, strconv.Itoa(config.Network.TCPPort)),
			Handler:  serveMux,
			ErrorLog: log.New(io.Discard, "", 0),
		},
		serveMux:       serveMux,
		commonAdapters: []Adapter{},
		tlsCertPath:    config.Network.TLSCertPath,
		tlsKeyPath:     config.Network.TLSKeyPath,
		started:        false,
		shutdownSem:    &sync.WaitGroup{},
		generalLog:     generalLog,
		requestLog:     requestLog,
	}

	if config.AllowOnlyGETRequests {
		server.commonAdapters = append(server.commonAdapters, server.AllowOnlyGET)
	}

	if config.LogRequests {
		server.commonAdapters = append(server.commonAdapters, server.LogRequest)
	}

	if config.EnableFileServer {
		server.allowedResources = set.NewStringSet()
		for _, resource := range config.FileServer.Allowed {
			server.allowedResources.Insert(resource)
		}

		// Register file server.
		fileServer := http.FileServer(http.Dir(config.FileServer.Directory))
		if strings.HasSuffix(config.FileServer.URLPrefix, URLSeparator) {
			server.Handle(
				config.FileServer.URLPrefix,
				Adapt(
					fileServer,
					server.VerifyResourceAllowed,
					StripPrefix(config.FileServer.URLPrefix),
					RedirectRootToParentTree,
				),
			)
			server.Handle(
				strings.TrimSuffix(config.FileServer.URLPrefix, URLSeparator),
				http.HandlerFunc(http.NotFound),
			)
		} else {
			server.Handle(
				config.FileServer.URLPrefix,
				Adapt(fileServer, StripPrefix(config.FileServer.URLPrefix)),
			)
		}

	}

	return
}
