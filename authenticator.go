package guerrilla

import (
	"errors"
	"strings"

	"github.com/phires/go-guerrilla/auth"
)

// Authenticator manages the authentication process.
type Authenticator struct {
	providers map[string]auth.Provider
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(config *AuthConfig) *Authenticator {
	providers := make(map[string]auth.Provider)
	if config.Enabled {
		if len(config.Plain) > 0 {
			providers["PLAIN"] = auth.NewPlainAuthProvider(config.Plain)
		}
		if len(config.DigestMD5) > 0 {
			providers["DIGEST-MD5"] = auth.NewDigestMD5Provider(config.DigestMD5)
		}
	}
	return &Authenticator{providers: providers}
}

// GetMechanisms returns a list of supported authentication mechanisms.
func (a *Authenticator) GetMechanisms() []string {
	var mechs []string
	for name := range a.providers {
		mechs = append(mechs, name)
	}
	return mechs
}

// Authenticate performs authentication using the specified mechanism.
func (a *Authenticator) Authenticate(client *client, mechanism string, data string) (bool, error) {
	provider, ok := a.providers[strings.ToUpper(mechanism)]
	if !ok {
		return false, errors.New("unsupported authentication mechanism")
	}
	return provider.Authenticate(data)
}
