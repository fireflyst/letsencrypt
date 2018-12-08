package acme

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/acme"
	"io"
	"net/http"
	"os"
	"time"
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
func (c *Client) PerHttpChallenge(ctx context.Context, chal *acme.Challenge, domain, path string) error {
	c.log.Debugf("attempting HTTP challenge on :http")
	url := c.client.HTTP01ChallengePath(chal.Token)
	response, err := c.client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}
	file, err := os.Create(path + "/" + chal.Token)
	if err != nil {
		return err
	}
	_, err = file.WriteString(response)
	file.Close()
	if err != nil {
		return err
	}
	fmt.Print("http://", domain + url, " ", "value: " + response , "\n")
	var resp = &http.Response{StatusCode:600}
	var value string

	for response != value {
		for resp.StatusCode != 200{
			resp, err = http.Get("http://" +  domain + url)
			if resp.StatusCode != 200 {
				time.Sleep(time.Second *10 )
			}
		}
		defer resp.Body.Close()
		if err != nil {
			return err
		}
		if value != "" {
			time.Sleep(time.Second *10 )
		}
		buf := make([]byte, 1*128)
		for {
			n, err := resp.Body.Read(buf)
			if n == 0 {
				if err != io.EOF {
					return err
				}
				break
			}
			value += string(buf[:n])
		}
		if err != nil {
			return err
		}
		break
	}
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
	fmt.Printf("Please add DNS TXT parsing:  _acme-challenge.%s ", domain)
	fmt.Println(tok)
	if err != nil {
		return err
	}
	var res string
	for res != tok {
		time.Sleep(time.Second*10)
		res = TxtChange(domain)
	}
	_, err = c.client.Accept(ctx, chal)
	if err != nil {
		return err
	}
	_, err = c.client.WaitAuthorization(ctx, chal.URI)
	return err
}

// authorize attempts to authorize the provided domain name in preparation for
// obtaining a TLS certificate.
func (c *Client) authorize(ctx context.Context, domain, chtype, path string) error {
	c.log.Debugf("authorizing %s", domain)
	auth, err := c.client.Authorize(ctx, domain)
	if err != nil {
		return err
	}
	if auth.Status == acme.StatusValid {
		return nil
	}
	if chtype == "http"{
		chal, err := HttpChallenge(auth)
		if err != nil {
			return err
		}
		return c.PerHttpChallenge(ctx, chal, domain, path)
	} else if chtype == "dns" {
		chal, err := DnsChallenge(auth)
		if err != nil {
			return err
		}
		return c.PerDnsChallenge(ctx, chal, domain)
	} else {
		return errors.New("No support for other challenges")
	}
}