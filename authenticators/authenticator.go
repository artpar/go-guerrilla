package authenticators

import "github.com/flashmob/go-guerrilla/backends"

type Authenticator interface {
	VerifyLOGIN(login, password string) bool
	VerifyPLAIN(login, password string) bool
	VerifyGSSAPI(login, password string) bool
	VerifyDIGESTMD5(login, password string) bool
	VerifyMD5(login, password string) bool
	VerifyCRAMMD5(login, password string) bool
	DecodeLogin(login string) (string, error)

	GetAdvertiseAuthentication(authType []string) string
}

type AuthenticatorCreator func(config backends.BackendConfig) Authenticator
