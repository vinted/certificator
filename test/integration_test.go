package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/thanos-io/thanos/pkg/testutil"
	"github.com/vinted/certificator/pkg/acme"
	"github.com/vinted/certificator/pkg/certificate"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/vault"
)

var (
	// vaultDevToken token should be equal to `VAULT_DEV_ROOT_TOKEN_ID` set in vault container
	// It should be defined in docker-compoose.yml
	vaultDevToken  string = "supersecret"
	vaultKVPath    string = "/secret/data/integration_test/"
	vaultEABKVPath string = "/secret/data/integration_test_eab/"
	acc            *acme.User
	keyEncoded     string
	acmeEmail      string = "test@test.com"
	acmeURL        string = "https://pebble:14000/dir"
	acmeEABURL     string = "https://pebble-eab:14000/dir"
	acmeEABKID     string = "kid-1"
	acmeEABHMACKEY string = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
)

func TestMain(m *testing.M) {
	//Set necessary ENV variables
	os.Setenv("VAULT_ADDR", "http://vault:8200")
	os.Setenv("VAULT_DEV_ROOT_TOKEN_ID", vaultDevToken)
	// This makes pebble certificate trusted
	os.Setenv("LEGO_CA_CERTIFICATES", "../fixtures/pebble.minica.pem")
	// This shows where is the exec challenge provider script
	os.Setenv("EXEC_PATH", "../fixtures/update-dns.sh")

	os.Exit(m.Run())
}

func TestAcmeClientAndAccountSetup(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	// testVaultClient will be used to delete entries from Vault
	testVaultClient, err := api.NewClient(api.DefaultConfig())
	testutil.Ok(t, err)

	// Make sure that this variable provides access to vault KV storage
	testVaultClient.SetToken(vaultDevToken)

	vaultClient, err := vault.NewVaultClient("", "", "dev", vaultKVPath, logger)
	testutil.Ok(t, err)

	// Make sure we are starting in a clean Vault
	deleteAccountFromVault(t, testVaultClient)
	deleteKeyFromVault(t, testVaultClient)

	acmeConfig := config.Acme{
		AccountEmail:      acmeEmail,
		ServerURL:         acmeURL,
		ReregisterAccount: true,
	}

	// This populates data in Vault, account and key are both present
	_, err = acme.NewClient(acmeConfig, vaultClient, logger)
	testutil.Ok(t, err)

	// Save account and key data from first registration
	account, err := vaultClient.KVRead("account")
	testutil.Ok(t, err)
	accountInfo, ok := account["account"].(string)
	testutil.Equals(t, true, ok)
	testutil.Ok(t, json.Unmarshal([]byte(accountInfo), &acc))

	key, err := vaultClient.KVRead("key")
	testutil.Ok(t, err)
	keyEncoded, ok = key["pem"].(string)
	testutil.Equals(t, true, ok)

	for _, tcase := range []struct {
		tcaseName            string
		accountInVault       bool
		keyInVault           bool
		reregisteringEnabled bool
		expectedErr          bool
	}{
		{
			tcaseName:            "Account and key are in Vault, reregistering enabled",
			accountInVault:       true,
			keyInVault:           true,
			reregisteringEnabled: true,
			expectedErr:          false,
		},
		{
			tcaseName:            "Account NOT in Vault, key in Vault, reregistering enabled",
			accountInVault:       false,
			keyInVault:           true,
			reregisteringEnabled: true,
			expectedErr:          false,
		},
		{
			tcaseName:            "Account and key are NOT in Vault, reregistering enabled",
			accountInVault:       false,
			keyInVault:           false,
			reregisteringEnabled: true,
			expectedErr:          false,
		},
		{
			tcaseName:            "Account in Vault, key NOT in Vault, reregistering enabled",
			accountInVault:       true,
			keyInVault:           false,
			reregisteringEnabled: true,
			expectedErr:          false,
		},
		{
			tcaseName:            "Account in Vault, key NOT in Vault, reregistering disabled, expecting an error",
			accountInVault:       true,
			keyInVault:           false,
			reregisteringEnabled: false,
			expectedErr:          true,
		},
	} {
		t.Run(tcase.tcaseName, func(t *testing.T) {
			if !tcase.accountInVault {
				deleteAccountFromVault(t, testVaultClient)
			} else {
				jsonAccount, err := json.Marshal(acc)
				testutil.Ok(t, err)

				err = vaultClient.KVWrite("account", map[string]string{"account": string(jsonAccount)})
				testutil.Ok(t, err)
			}

			if !tcase.keyInVault {
				deleteKeyFromVault(t, testVaultClient)
			} else {
				err = vaultClient.KVWrite("key", map[string]string{"pem": keyEncoded})
				testutil.Ok(t, err)
			}

			acmeConfig := config.Acme{
				AccountEmail:      acmeEmail,
				ServerURL:         acmeURL,
				ReregisterAccount: tcase.reregisteringEnabled,
			}
			_, err := acme.NewClient(acmeConfig, vaultClient, logger)
			if tcase.expectedErr {
				testutil.NotOk(t, err)
			} else {
				testutil.Ok(t, err)
			}
		})
	}
}

func TestCertificateObtaining(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	vaultClient, err := vault.NewVaultClient("", "", "dev", vaultKVPath, logger)
	testutil.Ok(t, err)

	acmeConfig := config.Acme{
		AccountEmail:      acmeEmail,
		ServerURL:         acmeURL,
		ReregisterAccount: true,
	}
	acmeClient, err := acme.NewClient(acmeConfig, vaultClient, logger)
	testutil.Ok(t, err)

	for _, domain := range []string{"example.com", "test.com", "mydomain.com"} {
		err := certificate.ObtainCertificate(acmeClient, vaultClient, []string{domain},
			"challtestsrv:8053", "exec", false)
		testutil.Ok(t, err)

		cert, err := certificate.GetCertificate(domain, vaultClient)
		testutil.Ok(t, err)

		// Check if certificate is issued recently
		testutil.Assert(t, time.Since(cert.NotBefore).Minutes() < 5)
	}
}

func TestCertificateObtainingWithEAB(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	vaultClient, err := vault.NewVaultClient("", "", "dev", vaultEABKVPath, logger)
	testutil.Ok(t, err)

	acmeConfig := config.Acme{
		ServerURL:         acmeEABURL,
		ReregisterAccount: true,
		EABKid:            acmeEABKID,
		EABHmacKey:        acmeEABHMACKEY,
	}

	acmeClient, err := acme.NewClient(acmeConfig, vaultClient, logger)
	testutil.Ok(t, err)

	for _, domain := range []string{"example-eab.com", "test-eab.com", "mydomain-eab.com"} {
		err := certificate.ObtainCertificate(acmeClient, vaultClient, []string{domain},
			"challtestsrv:8053", "exec", false)
		testutil.Ok(t, err)

		cert, err := certificate.GetCertificate(domain, vaultClient)
		testutil.Ok(t, err)

		// Check if certificate is issued recently
		testutil.Assert(t, time.Since(cert.NotBefore).Minutes() < 5)
	}
}

func deleteAccountFromVault(t *testing.T, cl *api.Client) {
	t.Log("Deleting account from Vault")
	_, err := cl.Logical().Delete(vaultKVPath + "account")
	testutil.Ok(t, err)
}

func deleteKeyFromVault(t *testing.T, cl *api.Client) {
	t.Log("Deleting key from Vault")
	_, err := cl.Logical().Delete(vaultKVPath + "key")
	testutil.Ok(t, err)
}
