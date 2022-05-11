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

// NeedsReissuing checks if certificate domains and required domains match
// and if certificate expiration date is earlier than configured in config.Cfg.RenewBeforeDays
func NeedsReissuing(certificate *x509.Certificate, domains []string, days int, logger *logrus.Logger) (bool, error) {
	if certificate == nil {
		return true, nil
	}

	if certificate.IsCA {
		return true, fmt.Errorf("certificate bundle for %s starts with a CA certificate", domains[0])
	}

	// Check if all domains are in certificate DNS names
	if !arraysEqual(domains, certificate.DNSNames) {
		logger.Printf("certificate %s domains changed, it needs reissuing", domains[0])
		logger.Printf("certificate domains: %v", certificate.DNSNames)
		logger.Printf("required domains: %v", domains)
		return true, nil
	}

	notAfter := int(time.Until(certificate.NotAfter).Hours() / 24.0)
	logger.Printf("certificate is valid for %v more days", notAfter)
	if notAfter > days {
		logger.Printf("certificate for %s does not need renewing", domains[0])

		return false, nil
	}

	return true, nil
}

func arraysEqual(array1 []string, array2 []string) bool {
	if len(array1) != len(array2) {
		return false
	}

	for _, v := range array1 {
		if !arrayContains(array2, v) {
			return false
		}
	}

	return true
}

func arrayContains(array []string, element string) bool {
	for _, a := range array {
		if a == element {
			return true
		}
	}
	return false
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
