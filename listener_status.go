package guerrilla

import (
	"sort"
	"time"
)

// ListenerStatus describes an owned listener, not a probe of DNS, credentials,
// delivery, or a port that another process may have bound. It contains no secrets.
type ListenerStatus struct {
	ListenInterface   string    `json:"listen_interface"`
	BoundAddress      string    `json:"bound_address,omitempty"`
	Hostname          string    `json:"hostname"`
	Enabled           bool      `json:"enabled"`
	State             string    `json:"state"`
	ChangedAt         time.Time `json:"changed_at"`
	ErrorCode         string    `json:"error_code,omitempty"`
	TLSMode           string    `json:"tls_mode"`
	CertificateLoaded bool      `json:"certificate_loaded"`
	AuthRequired      bool      `json:"authentication_required"`
	AuthTypes         []string  `json:"authentication_mechanisms"`
}

// ListenerStatuses returns copied observations of listeners created by Start,
// including listeners created by reload. Before Start it returns an empty list.
// Lifecycle mutations must be serialized by the daemon owner, as for Start and
// ReloadConfig; snapshots may be read concurrently with those mutations.
func (d *Daemon) ListenerStatuses() []ListenerStatus {
	statuses := make([]ListenerStatus, 0)
	d.statusMu.RLock()
	app := d.g
	d.statusMu.RUnlock()
	if app == nil {
		return statuses
	}
	g := app.(*guerrilla)
	g.mapServers(func(s *server) { statuses = append(statuses, s.listenerStatus()) })
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].ListenInterface < statuses[j].ListenInterface })
	return statuses
}

func (s *server) getState() int {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.state
}

func (s *server) setState(state int, code string) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if s.state != state || s.errorCode != code {
		s.changedAt = time.Now().UTC()
	}
	s.state, s.errorCode = state, code
}

func (s *server) listenerStatus() ListenerStatus {
	sc := s.configStore.Load().(ServerConfig)
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	status := ListenerStatus{
		ListenInterface: sc.ListenInterface, Hostname: sc.Hostname, Enabled: sc.IsEnabled,
		ChangedAt: s.changedAt, ErrorCode: s.errorCode,
		AuthRequired: sc.AuthRequired, AuthTypes: append([]string{}, sc.AuthTypes...),
		CertificateLoaded: s.tlsConfigStore.Load() != nil, TLSMode: "none",
	}
	if sc.TLS.AlwaysOn {
		status.TLSMode = "implicit"
	} else if sc.TLS.StartTLSOn {
		status.TLSMode = "starttls"
	}
	switch s.state {
	case ServerStateNew:
		if sc.IsEnabled {
			status.State = "starting"
		} else {
			status.State = "disabled"
		}
	case ServerStateRunning:
		status.State = "running"
	case ServerStateStartError:
		status.State = "failed"
	case ServerStateStarting:
		status.State = "starting"
	case ServerStateStopping:
		status.State = "stopping"
	case ServerStateStopped:
		status.State = "stopped"
		if !sc.IsEnabled {
			status.State = "disabled"
		}
	}
	if s.listener != nil && (s.state == ServerStateRunning || s.state == ServerStateStopping) {
		status.BoundAddress = s.listener.Addr().String()
	}
	return status
}
