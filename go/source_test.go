package dbauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type countingProvider struct {
	calls int
	creds aws.Credentials
	err   error
}

func (p *countingProvider) Retrieve(context.Context) (aws.Credentials, error) {
	p.calls++
	return p.creds, p.err
}

func clockedSource(p aws.CredentialsProvider, host string) (*TokenSource, *time.Time) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s := NewTokenSource(host, "us-east-1", p)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestTokenSourceCachesUntilShortlyBeforeExpiry(t *testing.T) {
	p := &countingProvider{creds: aws.Credentials{AccessKeyID: "AKIDSOURCE", SecretAccessKey: "secret"}}
	s, now := clockedSource(p, "orders.db.userelay.sh")
	first, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(TokenTTL - RefreshBefore - time.Second)
	if again, _ := s.Token(context.Background()); again != first || p.calls != 1 {
		t.Fatalf("a fresh token was not reused: calls %d", p.calls)
	}
	*now = now.Add(time.Second)
	if next, _ := s.Token(context.Background()); next == first || p.calls != 2 {
		t.Fatalf("a token about to expire was reused: calls %d", p.calls)
	}
}

func TestTokenSourceFollowsExpiringCredentials(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	p := &countingProvider{creds: aws.Credentials{AccessKeyID: "AKIDSOURCE", SecretAccessKey: "secret", CanExpire: true, Expires: now.Add(5 * time.Minute)}}
	s, clock := clockedSource(p, "orders.db.userelay.sh")
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(3*time.Minute + time.Second)
	if _, err := s.Token(context.Background()); err != nil || p.calls != 2 {
		t.Fatalf("a token signed by credentials about to expire was reused: calls %d", p.calls)
	}
}

func TestTokenSourceErrors(t *testing.T) {
	if _, err := NewTokenSource("orders.db.userelay.sh", "", nil).Token(context.Background()); err == nil || !strings.Contains(err.Error(), "no AWS credentials provider") {
		t.Errorf("nil provider: %v", err)
	}
	failing := &countingProvider{err: errors.New("expired SSO session")}
	s, _ := clockedSource(failing, "orders.db.userelay.sh")
	if _, err := s.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "expired SSO session") {
		t.Errorf("provider error: %v", err)
	}
	s, _ = clockedSource(&countingProvider{creds: aws.Credentials{AccessKeyID: "a", SecretAccessKey: "b"}}, "orders.db.userelay.sh:6379")
	if _, err := s.Token(context.Background()); err == nil {
		t.Error("a host with a port was accepted")
	}
}
