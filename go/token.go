// Package dbauth mints the IAM tokens that log in to Relay databases.
package dbauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// TokenTTL is how long a token stays valid, unless the credentials that signed it expire first.
const TokenTTL = 15 * time.Minute

const (
	serverIDHeader = "X-Relay-Server-Id"
	stsVersion     = "2011-06-15"
	globalHost     = "sts.amazonaws.com"
	globalRegion   = "us-east-1"
)

var (
	awsRegion        = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	dbHost           = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	emptyPayloadHash = hex.EncodeToString(func() []byte { h := sha256.Sum256(nil); return h[:] }())
	presign          = v4.NewSigner().PresignHTTP
)

// NewToken returns a token for the database at host (the hostname from its connection string, without a port), signed through the STS endpoint of region ("" for the global endpoint).
func NewToken(ctx context.Context, host, region string, creds aws.CredentialsProvider) (string, error) {
	if creds == nil {
		return "", errors.New("dbauth: no AWS credentials provider")
	}
	c, err := creds.Retrieve(ctx)
	if err != nil {
		return "", err
	}
	return newToken(ctx, c, host, region, time.Now())
}

func newToken(ctx context.Context, creds aws.Credentials, host, region string, now time.Time) (string, error) {
	host = strings.ToLower(host)
	if !dbHost.MatchString(host) {
		return "", errors.New("dbauth: " + strconv.Quote(host) + " is not a database hostname; pass the host from the connection string without a port")
	}
	stsHost, signingRegion := globalHost, globalRegion
	if region != "" {
		if !awsRegion.MatchString(region) {
			return "", errors.New("dbauth: invalid region " + strconv.Quote(region))
		}
		stsHost, signingRegion = regionalHost(region), region
	}
	q := url.Values{
		"Action":        {"GetCallerIdentity"},
		"Version":       {stsVersion},
		"X-Amz-Expires": {strconv.Itoa(int(TokenTTL / time.Second))},
	}
	req := (&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: stsHost, Path: "/", RawQuery: q.Encode()},
		Header: http.Header{serverIDHeader: {host}},
		Host:   stsHost,
	}).WithContext(ctx)
	signed, _, err := presign(ctx, creds, req, emptyPayloadHash, "sts", signingRegion, now.UTC())
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(signed, "https://") + "&" + serverIDHeader + "=" + url.QueryEscape(host), nil
}

func regionalHost(region string) string {
	if strings.HasPrefix(region, "cn-") {
		return "sts." + region + ".amazonaws.com.cn"
	}
	return "sts." + region + ".amazonaws.com"
}
