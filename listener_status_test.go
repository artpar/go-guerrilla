package guerrilla

import (
	"encoding/json"
	"github.com/artpar/go-guerrilla/authenticators"
	"github.com/artpar/go-guerrilla/backends"
	"github.com/artpar/go-guerrilla/log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestListenerStatusesLifecycle(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	d := &Daemon{Config: &AppConfig{LogFile: "off", AllowedHosts: []string{"localhost"}, Servers: []ServerConfig{
		{ListenInterface: "127.0.0.1:0", Hostname: "localhost", IsEnabled: true, AuthTypes: []string{"LOGIN"}},
	}}}
	d.AddAuthenticator(func(_ backends.BackendConfig) authenticators.Authenticator {
		return &loginAuthenticator{calls: make(chan loginCredentials, 1)}
	})
	if got := d.ListenerStatuses(); len(got) != 0 {
		t.Fatalf("unstarted daemon: %#v", got)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()
	statuses := d.ListenerStatuses()
	if len(statuses) != 1 || statuses[0].State != "running" || statuses[0].BoundAddress == "" || statuses[0].BoundAddress == "127.0.0.1:0" {
		t.Fatalf("running: %#v", statuses)
	}
	statuses[0].AuthTypes[0] = "changed"
	if d.ListenerStatuses()[0].AuthTypes[0] != "LOGIN" {
		t.Fatal("snapshot aliases configuration")
	}
	conn, err := net.Dial("tcp", statuses[0].BoundAddress)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	stop := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
				d.ListenerStatuses()
			}
		}
	}()
	defer func() { close(stop); readers.Wait() }()
	cfg := *d.Config
	cfg.Servers = append([]ServerConfig{}, cfg.Servers...)
	cfg.Servers = append(cfg.Servers, ServerConfig{ListenInterface: occupied.Addr().String(), Hostname: "localhost", IsEnabled: true})
	if err := d.ReloadConfig(cfg); err != nil {
		t.Fatal(err)
	}
	statuses = d.ListenerStatuses()
	if len(statuses) != 2 {
		t.Fatalf("reload: %#v", statuses)
	}
	for _, status := range statuses {
		if status.ListenInterface == occupied.Addr().String() && (status.State != "failed" || status.ErrorCode != "listen_failed" || status.BoundAddress != "") {
			t.Fatalf("occupied listener: %#v", status)
		}
	}
	d.Shutdown()
	for _, status := range d.ListenerStatuses() {
		if status.State == "running" || status.BoundAddress != "" {
			t.Fatalf("shutdown: %#v", status)
		}
	}
}

func TestListenerStatusesUnexpectedStop(t *testing.T) {
	d := &Daemon{Config: &AppConfig{LogFile: "off", AllowedHosts: []string{"localhost"}, Servers: []ServerConfig{{ListenInterface: "127.0.0.1:0", Hostname: "localhost", IsEnabled: true}}}}
	d.AddAuthenticator(func(backends.BackendConfig) authenticators.Authenticator { return &loginAuthenticator{} })
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()
	s, err := d.g.(*guerrilla).findServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.statusMu.RLock()
	listener := s.listener
	s.statusMu.RUnlock()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status := d.ListenerStatuses()[0]
		if status.State == "failed" {
			if status.ErrorCode != "accept_failed" || status.BoundAddress != "" {
				t.Fatalf("unexpected close: %#v", status)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("unexpected listener close was not observed")
}

func TestListenerStatusTLSFailure(t *testing.T) {
	logger, err := log.GetLogger("off", "error")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := backends.New(backends.BackendConfig{"save_workers_size": 1}, logger)
	if err != nil {
		t.Fatal(err)
	}
	config := &ServerConfig{ListenInterface: "127.0.0.1:0", Hostname: "localhost", IsEnabled: true, MaxClients: 1,
		TLS: ServerTLSConfig{StartTLSOn: true, PrivateKeyFile: "/secret/backend/key", PublicKeyFile: "/secret/backend/cert"}}
	s, err := newServer(config, backend, &loginAuthenticator{}, logger)
	if err == nil {
		t.Fatal("missing TLS material was accepted")
	}
	status := s.listenerStatus()
	if status.State != "failed" || status.ErrorCode != "tls_configuration_failed" || status.CertificateLoaded {
		t.Fatalf("TLS failure: %#v", status)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "/secret") {
		t.Fatal("snapshot leaked TLS configuration paths")
	}
}

func TestListenerStatusesDisabledAndConcurrentStartup(t *testing.T) {
	d := &Daemon{Config: &AppConfig{LogFile: "off", Servers: []ServerConfig{{ListenInterface: "127.0.0.1:0", Hostname: "localhost", IsEnabled: false}}}}
	d.AddAuthenticator(func(backends.BackendConfig) authenticators.Authenticator { return &loginAuthenticator{} })
	stop := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
				d.ListenerStatuses()
			}
		}
	}()
	err := d.Start()
	close(stop)
	readers.Wait()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()
	statuses := d.ListenerStatuses()
	if len(statuses) != 1 || statuses[0].State != "disabled" || statuses[0].Enabled || statuses[0].BoundAddress != "" {
		t.Fatalf("disabled: %#v", statuses)
	}
}

func TestListenerStatusesStartupFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	d := &Daemon{Config: &AppConfig{LogFile: "off", Servers: []ServerConfig{{ListenInterface: occupied.Addr().String(), Hostname: "localhost", IsEnabled: true}}}}
	d.AddAuthenticator(func(backends.BackendConfig) authenticators.Authenticator { return &loginAuthenticator{} })
	if err := d.Start(); err == nil {
		d.Shutdown()
		t.Fatal("occupied listener did not fail startup")
	}
	defer d.Shutdown()
	statuses := d.ListenerStatuses()
	if len(statuses) != 1 || statuses[0].State != "failed" || statuses[0].ErrorCode != "listen_failed" || statuses[0].BoundAddress != "" {
		t.Fatalf("failed startup: %#v", statuses)
	}
}
