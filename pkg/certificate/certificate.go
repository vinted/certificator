package certificate

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/vault"
)

// ObtainCertificate gets certificate and stores it in Vault KV store
func ObtainCertificate(client *lego.Client, vault *vault.VaultClient, domains []string,
	dnsAddr, challengeProvider string, propagationReq bool) error {
	provider, err := dns.NewDNSChallengeProviderByName(challengeProvider)
	if err != nil {
		return err
	}

	if propagationReq {
		err = client.Challenge.SetDNS01Provider(provider,
			dns01.AddRecursiveNameservers([]string{dnsAddr}))
	} else {
		err = client.Challenge.SetDNS01Provider(provider,
			dns01.AddRecursiveNameservers([]string{dnsAddr}),
			dns01.DisableCompletePropagationRequirement())
	}
	if err != nil {
		return err
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	certificate, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	return storeCertificateInVault(domains[0], certificate, vault)
}

// GetCertificate reads certificate from Vault KV store and parses it
func GetCertificate(domain string, vault *vault.VaultClient) (*x509.Certificate, error) {
	secrets, err := vault.KVRead(vaultCertLocation(domain))
	if err != nil {
		return nil, err
	}
	if cert, ok := secrets["certificate"].(string); ok {
		parsedCert, err := certcrypto.ParsePEMBundle([]byte(cert))
		if err != nil {
			return nil, err
		}
		return parsedCert[0], nil
	}

	return nil, nil
}

// NeedsRenewing checks if certificate expiration date is earlier than configured in config.Cfg.RenewBeforeDays
func NeedsRenewing(certificate *x509.Certificate, domain string, days int, logger *logrus.Logger) (bool, error) {
	if certificate == nil {
		return true, nil
	}

	if certificate.IsCA {
		return true, fmt.Errorf("certificate bundle for %s starts with a CA certificate", domain)
	}

	notAfter := int(time.Until(certificate.NotAfter).Hours() / 24.0)
	logger.Printf("certificate is valid for %v more days", notAfter)
	if notAfter > days {
		logger.Printf("certificate for %s does not need renewing", domain)

		return false, nil
	}

	return true, nil
}

func vaultCertLocation(domain string) string {
	return "certificates/" + domain
}

func storeCertificateInVault(domain string, certs *certificate.Resource, vault *vault.VaultClient) error {
	payload := map[string]string{"certificate": string(certs.Certificate),
		"private_key":        string(certs.PrivateKey),
		"issuer_certificate": string(certs.IssuerCertificate)}

	return vault.KVWrite(vaultCertLocation(domain), payload)
}
