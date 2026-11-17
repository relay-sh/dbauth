package dbauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// RefreshBefore is how long before a cached token expires that TokenSource mints the next one.
const RefreshBefore = 2 * time.Minute

// TokenSource caches a token for one database and mints a new one shortly before it expires; it is safe for concurrent use.
type TokenSource struct {
	host, region string
	creds        aws.CredentialsProvider
	now          func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewTokenSource returns a TokenSource for the database at host, signing through the STS endpoint of region ("" for the global endpoint).
func NewTokenSource(host, region string, creds aws.CredentialsProvider) *TokenSource {
	return &TokenSource{host: host, region: region, creds: creds, now: time.Now}
}

// Token returns the cached token, or mints a new one when it is missing or about to expire.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.token != "" && now.Before(s.expires.Add(-RefreshBefore)) {
		return s.token, nil
	}
	if s.creds == nil {
		return "", errors.New("dbauth: no AWS credentials provider")
	}
	c, err := s.creds.Retrieve(ctx)
	if err != nil {
		return "", err
	}
	token, err := newToken(ctx, c, s.host, s.region, now)
	if err != nil {
		return "", err
	}
	s.token, s.expires = token, now.Add(TokenTTL)
	if c.CanExpire && c.Expires.Before(s.expires) {
		s.expires = c.Expires
	}
	return s.token, nil
}
