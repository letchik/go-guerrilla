package auth

// Provider is an interface for different authentication mechanisms.
type Provider interface {
	// Name returns the name of the authentication mechanism (e.g., "PLAIN", "DIGEST-MD5").
	Name() string
	// Authenticate performs the authentication process.
	Authenticate(clientData string) (bool, error)
}
