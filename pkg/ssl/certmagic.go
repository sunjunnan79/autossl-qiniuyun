package ssl

import (
	"context"
	"fmt"

	"github.com/caddyserver/certmagic"
)

func NewCertMagicClient(email string, storage certmagic.Storage, provider Provider) (*CertMagicClient, error) {
	if email == "" {
		email = "admin@yourdomain.com"
	}
	if storage == nil {
		return nil, fmt.Errorf("certmagic storage is required")
	}

	dnsProvider, err := NewDNSProvider(provider)
	if err != nil {
		return nil, err
	}

	certmagic.DefaultACME.Email = email
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: dnsProvider,
		},
	}
	certmagic.Default.Storage = storage

	cm := certmagic.NewDefault()
	cm.Storage = storage

	return &CertMagicClient{cm: cm}, nil
}

type CertMagicClient struct {
	cm *certmagic.Config
}

func (c *CertMagicClient) ObtainCert(ctx context.Context, domain string) (string, string, error) {
	err := c.cm.ObtainCertSync(ctx, domain)
	if err != nil {
		return "", "", err
	}

	cert, err := c.cm.CacheManagedCertificate(ctx, domain)
	if err != nil {
		return "", "", err
	}

	certPEM, keyPEM, err := c.convertCertToPEM(cert.Certificate)
	if err != nil {
		return "", "", err
	}

	return certPEM, keyPEM, nil
}
