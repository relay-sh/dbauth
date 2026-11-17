package dbauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type vector struct {
	Name            string `json:"name"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Host            string `json:"host"`
	Region          string `json:"region"`
	Time            string `json:"time"`
	Token           string `json:"token"`
}

func TestTokensMatchTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../testvectors/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, v.Time)
			if err != nil {
				t.Fatal(err)
			}
			creds := aws.Credentials{AccessKeyID: v.AccessKeyID, SecretAccessKey: v.SecretAccessKey, SessionToken: v.SessionToken}
			got, err := newToken(context.Background(), creds, v.Host, v.Region, at)
			if err != nil || got != v.Token {
				t.Fatalf("token = %q, %v\nwant    %q", got, err, v.Token)
			}
		})
	}
}

func TestNewToken(t *testing.T) {
	creds := credentials.NewStaticCredentialsProvider("AKIDSTATIC", "secret", "")
	token, err := NewToken(context.Background(), "Orders.AB1CD.db.userelay.sh", "us-east-1", creds)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&") || !strings.HasSuffix(token, "&X-Relay-Server-Id=orders.ab1cd.db.userelay.sh") {
		t.Errorf("token = %q", token)
	}
	if !strings.Contains(token, "X-Amz-SignedHeaders=host%3Bx-relay-server-id") {
		t.Errorf("the server id is not signed: %q", token)
	}
}

func TestNewTokenRefusals(t *testing.T) {
	creds := credentials.NewStaticCredentialsProvider("AKIDSTATIC", "secret", "")
	failing := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return aws.Credentials{}, errors.New("no credentials") })
	for name, tc := range map[string]struct {
		host, region string
		creds        aws.CredentialsProvider
		want         string
	}{
		"no provider":     {"orders.db.userelay.sh", "", nil, "no AWS credentials provider"},
		"provider fails":  {"orders.db.userelay.sh", "", failing, "no credentials"},
		"port":            {"orders.db.userelay.sh:5432", "", creds, "without a port"},
		"empty host":      {"", "", creds, "not a database hostname"},
		"single label":    {"localhost", "", creds, "not a database hostname"},
		"invalid region":  {"orders.db.userelay.sh", "us-east", creds, "invalid region"},
		"a URL, not host": {"postgres://orders.db.userelay.sh", "", creds, "not a database hostname"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewToken(context.Background(), tc.host, tc.region, tc.creds); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNewTokenSigningFailure(t *testing.T) {
	defer func(p func(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time, ...func(*v4.SignerOptions)) (string, http.Header, error)) {
		presign = p
	}(presign)
	presign = func(context.Context, aws.Credentials, *http.Request, string, string, string, time.Time, ...func(*v4.SignerOptions)) (string, http.Header, error) {
		return "", nil, errors.New("sign failed")
	}
	if _, err := newToken(context.Background(), aws.Credentials{}, "orders.db.userelay.sh", "", time.Now()); err == nil {
		t.Error("a signing failure is returned")
	}
}
