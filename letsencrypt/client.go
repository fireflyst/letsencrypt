package letsencrypt


import (
	"context"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
)

// Client facilitates the process of obtaining TLS certificates.
type Client struct {
	client *acme.Client
	log    *logrus.Entry
}

// New creates a new ACME client. If the key does not exist, a new one is
// generated and registered.
func New(ctx context.Context, key string) (*Client, error) {
	client := &acme.Client{}
	k, err := loadKey(key)
	if err != nil {
		if os.IsNotExist(err) {
			k, err = generateKey(key)
			if err != nil {
				return nil, err
			}
			client.Key = k
			if email == "" {
				if _, err := client.Register(ctx, nil, acme.AcceptTOS); err != nil {
					return nil, err
				}
			} else {
				account := acme.Account{
					Contact: []string{"mailto:" + email},
				}
				if _, err := client.Register(ctx, &account, acme.AcceptTOS); err != nil {
					return nil, err
				}
			}
		} else {
			return nil, err
		}
	} else {
		client.Key = k
	}
	return &Client{
		client: client,
		log:    logrus.WithField("context", "acme"),
	}, nil
}

// Create attempts to create a TLS certificate and private key for the
// specified domain names. The provided address is used for challenges.
func (c *Client) Create(ctx context.Context, key, cert, chtype string,domains ...string) error {
	for _, d := range domains {
		if err := c.authorize(ctx, d, chtype); err != nil {
			return err
		}
	}
	k, err := generateKey(key)
	if err != nil {
		return err
	}
	b, err := createCSR(k, domains...)
	if err != nil {
		return err
	}
	return c.createCert(ctx, b, cert)
}
