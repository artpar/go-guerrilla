package guerrilla

import (
	"encoding/base64"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/artpar/go-guerrilla/backends"
	"github.com/artpar/go-guerrilla/log"
	"github.com/artpar/go-guerrilla/mail"
)

type loginCredentials struct{ username, password string }

type loginAuthenticator struct {
	calls    chan loginCredentials
	username string
}

func (a *loginAuthenticator) VerifyLOGIN(username, password string) bool {
	a.calls <- loginCredentials{username, password}
	decoded, err := base64.StdEncoding.DecodeString(username)
	return err == nil && string(decoded) == a.username && password == base64.StdEncoding.EncodeToString([]byte("correct-password"))
}
func (*loginAuthenticator) VerifyCRAMMD5(string, string) bool         { return false }
func (*loginAuthenticator) GenerateCRAMMD5Challenge() (string, error) { return "", nil }
func (*loginAuthenticator) ExtractLoginFromAuthString(string) string  { return "" }
func (*loginAuthenticator) DecodeLogin(login string) (string, error) {
	value, err := base64.StdEncoding.DecodeString(login)
	return string(value), err
}
func (*loginAuthenticator) GetAdvertiseAuthentication(types []string) string {
	return "250-AUTH " + strings.Join(types, " ") + "\r\n"
}
func (*loginAuthenticator) GetMailSize(_ string, size int64) int64 { return size }

// Exercise the production SMTP state machine over a bounded connection, as in
// TestHandleClient, without binding a fixed port or relying on stored accounts.
func TestSMTPLOGIN(t *testing.T) {
	for _, initial := range []bool{false, true} {
		form := "challenge"
		if initial {
			form = "initial"
		}
		for _, tc := range []struct {
			name, username, password string
			disabled                 bool
		}{
			{name: "mixed-case", username: "Owner@example.test", password: "correct-password"},
			{name: "long", username: strings.Repeat("a", 120) + "@example.test", password: "correct-password"},
			{name: "wrong-password", username: "Owner@example.test", password: "wrong-password"},
			{name: "disabled", username: "AAA", password: "correct-password", disabled: true},
		} {
			t.Run(form+"/"+tc.name, func(t *testing.T) {
				logger, err := log.GetLogger("off", "error")
				if err != nil {
					t.Fatal(err)
				}
				backend, err := backends.New(backends.BackendConfig{"save_workers_size": 1}, logger)
				if err != nil {
					t.Fatal(err)
				}
				authenticator := &loginAuthenticator{calls: make(chan loginCredentials, 1), username: tc.username}
				allowed := []string{"LOGIN"}
				if tc.disabled {
					allowed = []string{"CRAM-MD5"}
				}
				s, err := newServer(&ServerConfig{
					Hostname: "localhost", MaxSize: 1024, Timeout: 5,
					MaxClients: 1, AuthTypes: allowed, AuthRequired: true,
				}, backend, authenticator, logger)
				if err != nil {
					t.Fatal(err)
				}
				connection, serverConnection := net.Pipe()
				if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					s.handleClient(NewClient(serverConnection, 1, logger, mail.NewPool(1)))
				}()
				defer func() {
					connection.Close()
					serverConnection.Close()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("SMTP handler did not stop")
					}
				}()
				protocol := textproto.NewConn(connection)
				read := func(code int) {
					t.Helper()
					if _, _, err := protocol.ReadResponse(code); err != nil {
						t.Fatal(err)
					}
				}
				send := func(command string) {
					t.Helper()
					if err := protocol.PrintfLine("%s", command); err != nil {
						t.Fatal(err)
					}
				}
				read(220)
				send("EHLO localhost")
				read(250)
				username := base64.StdEncoding.EncodeToString([]byte(tc.username))
				command := "aUtH lOgIn"
				if initial {
					command += " " + username
				}
				send(command)
				if tc.disabled {
					read(500)
					send("NOOP")
					read(200)
					select {
					case <-authenticator.calls:
						t.Fatal("disabled LOGIN reached credential verification")
					default:
					}
				} else {
					read(334)
					if !initial {
						send(username)
						read(334)
					}
					password := base64.StdEncoding.EncodeToString([]byte(tc.password))
					send(password)
					if tc.password == "correct-password" {
						read(235)
					} else {
						read(535)
					}
					select {
					case got := <-authenticator.calls:
						if got.username != username || got.password != password {
							t.Errorf("credential bytes changed: got %q, %q; want %q, %q", got.username, got.password, username, password)
						}
					default:
						t.Fatal("LOGIN did not reach credential verification")
					}
				}
				send("QUIT")
				read(221)
			})
		}
	}
}
