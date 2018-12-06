package letsencrypt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"golang.org/x/crypto/acme"
)

var ErrNoChallenges = errors.New("no suitable challenge found")

// http-01 challenge is supported.
func HttpChallenge(auth *acme.Authorization) (*acme.Challenge, error) {
	var chal *acme.Challenge
	for _, c := range auth.Challenges {
		if c.Type == "http-01" {
			chal = c
		}
	}
	if chal == nil {
		return nil, ErrNoChallenges
	}
	return chal, nil
}

// dns-01 challenge is supported.
func DnsChallenge(auth *acme.Authorization) (*acme.Challenge, error) {
	var chal *acme.Challenge
	for _, c := range auth.Challenges {
		if c.Type == "dns-01" {
			chal = c
		}
	}
	if chal == nil {
		return nil, ErrNoChallenges
	}
	return chal, nil
}


// Http-01 PerHttpChallenge creates a temporary server that ACME can access to verify
// ownership of a domain name.
func (c *Client) PerHttpChallenge(ctx context.Context, chal *acme.Challenge) error {
	c.log.Debugf("attempting HTTP challenge on :http")
	response, err := c.client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}
	var (
		b   = []byte(response)
		mux = http.NewServeMux()
	)
	mux.HandleFunc(
		c.client.HTTP01ChallengePath(chal.Token),
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.WriteHeader(http.StatusOK)
			w.Write(b)
		},
	)
	l, err := net.Listen("tcp", ":http")
	if err != nil {
		return err
	}
	defer l.Close()
	go func() {
		http.Serve(l, mux)
	}()
	_, err = c.client.Accept(ctx, chal)
	if err != nil {
		return err
	}
	_, err = c.client.WaitAuthorization(ctx, chal.URI)
	return err
}

// Dns-01 PerDnsChallenge creates a temporary server that ACME can access to verify
// ownership of a domain name.
func (c *Client) PerDnsChallenge(ctx context.Context, chal *acme.Challenge, domain string) error {
	c.log.Debugf("attempting DNS challenge on %s", domain)
	tok, err := c.client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}
	fmt.Printf("Please add DNS TXT parsing:  _acme-challenge.%s ", domain)
	fmt.Println(tok)
	var start string
	fmt.Println("是否解析好了(y/n):")
	fmt.Scan(&start)
	if start == "y" {
		_, err = c.client.Accept(ctx, chal)
		if err != nil {
			return err
		}
		_, err = c.client.WaitAuthorization(ctx, chal.URI)
		return err
	} else {
		return errors.New("Input error")
	}
}

// authorize attempts to authorize the provided domain name in preparation for
// obtaining a TLS certificate.
func (c *Client) authorize(ctx context.Context, domain string, chtype string) error {
	c.log.Debugf("authorizing %s", domain)
	auth, err := c.client.Authorize(ctx, domain)
	if err != nil {
		return err
	}
	if auth.Status == acme.StatusValid {
		return nil
	}
	if chtype == ":http"{
		chal, err := HttpChallenge(auth)
		if err != nil {
			return err
		}
		return c.PerHttpChallenge(ctx, chal)
	} else if chtype == ":dns" {
		chal, err := DnsChallenge(auth)
		if err != nil {
			return err
		}
		return c.PerDnsChallenge(ctx, chal, domain)
	} else {
		return errors.New("No support for other challenges")
	}
}