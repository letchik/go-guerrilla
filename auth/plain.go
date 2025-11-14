package auth

import (
	"encoding/base64"
	"errors"
	"strings"
)

// PlainAuthProvider implements the PLAIN authentication mechanism.
type PlainAuthProvider struct {
	users map[string]string
}

// NewPlainAuthProvider creates a new PlainAuthProvider.
func NewPlainAuthProvider(users map[string]string) *PlainAuthProvider {
	return &PlainAuthProvider{users: users}
}

// Name returns the name of the authentication mechanism.
func (p *PlainAuthProvider) Name() string {
	return "PLAIN"
}

// Authenticate performs PLAIN authentication.
func (p *PlainAuthProvider) Authenticate(clientData string) (bool, error) {
	decoded, err := base64.StdEncoding.DecodeString(clientData)
	if err != nil {
		return false, errors.New("invalid base64 data")
	}
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) != 3 {
		return false, errors.New("invalid PLAIN auth data")
	}
	username := parts[1]
	password := parts[2]
	if storedPassword, ok := p.users[username]; ok && storedPassword == password {
		return true, nil
	}
	return false, nil
}
