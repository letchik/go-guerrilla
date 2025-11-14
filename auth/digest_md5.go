package auth

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// DigestMD5Provider implements the DIGEST-MD5 authentication mechanism.
type DigestMD5Provider struct {
	users map[string]string
}

// NewDigestMD5Provider creates a new DigestMD5Provider.
func NewDigestMD5Provider(users map[string]string) *DigestMD5Provider {
	return &DigestMD5Provider{users: users}
}

// Name returns the name of the authentication mechanism.
func (d *DigestMD5Provider) Name() string {
	return "DIGEST-MD5"
}

// Authenticate performs DIGEST-MD5 authentication.
func (d *DigestMD5Provider) Authenticate(clientData string) (bool, error) {
	// This is a simplified implementation of DIGEST-MD5.
	// A real implementation would involve a challenge-response mechanism.
	decoded, err := base64.StdEncoding.DecodeString(clientData)
	if err != nil {
		return false, errors.New("invalid base64 data")
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 2 {
		return false, errors.New("invalid DIGEST-MD5 auth data")
	}
	username := parts[0]
	response := parts[1]
	if storedPassword, ok := d.users[username]; ok {
		// In a real scenario, you would use the realm, nonce, etc.
		// to calculate the expected response.
		// Here, we'll just do a simple hash comparison for demonstration.
		hasher := md5.New()
		hasher.Write([]byte(username + ":" + storedPassword))
		expectedResponse := fmt.Sprintf("%x", hasher.Sum(nil))
		if response == expectedResponse {
			return true, nil
		}
	}
	return false, nil
}
