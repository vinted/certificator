package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/thanos-io/thanos/pkg/testutil"
)

func TestNeedsRenewing(t *testing.T) {
	template := &x509.Certificate{
		IsCA:         false,
		SerialNumber: big.NewInt(1234),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0 /* years */, 3 /* months */, 0 /* days */),
	}
	logger := logrus.New()

	certificate := generateCert(t, template)

	for _, tcase := range []struct {
		tcaseName      string
		certificate    *x509.Certificate
		renewDays      int
		expectedResult bool
	}{
		{
			tcaseName:      "certificate expires after three months (90 days), renewDays = 30",
			certificate:    certificate,
			renewDays:      30,
			expectedResult: false,
		},
		{
			tcaseName:      "certificate expires after three months (90 days), renewDays = 100",
			certificate:    certificate,
			renewDays:      100,
			expectedResult: true,
		},
		{
			tcaseName:      "nil certificate, renew days 30",
			certificate:    nil,
			renewDays:      30,
			expectedResult: true,
		},
	} {
		t.Run(tcase.tcaseName, func(t *testing.T) {
			result, err := NeedsRenewing(tcase.certificate, "test.com", tcase.renewDays, logger)
			testutil.Ok(t, err)
			testutil.Equals(t, tcase.expectedResult, result)
		})
	}
}

func generateCert(t *testing.T, template *x509.Certificate) *x509.Certificate {
	privatekey, err := rsa.GenerateKey(rand.Reader, 512)
	testutil.Ok(t, err)

	publickey := &privatekey.PublicKey

	// create a self-signed certificate. template = parent
	var parent = template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, privatekey)
	testutil.Ok(t, err)

	parsedCert, _ := x509.ParseCertificate(cert)

	return parsedCert
}
