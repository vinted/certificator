package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/vault"
)

// User represents a users local saved credentials.
// Implements registration.User interface
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

// GetEmail returns the email address for the account.
func (u *User) GetEmail() string {
	return u.Email
}

// GetRegistration returns the server registration.
func (u User) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey returns the private account key.
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// NewClient initializes acme client and returns
func NewClient(
	cfg config.Acme,
	vault *vault.VaultClient,
	logger *logrus.Logger) (*lego.Client, error) {

	acc, err := setupAccount(cfg.AccountEmail, cfg.ReregisterAccount, vault, logger)
	if err != nil {
		return nil, err
	}

	client, err := setupClient(acc, cfg.ServerURL, logger)
	if err != nil {
		return nil, err
	}

	return registerAccount(acc, client, vault, cfg, logger)
}

func setupClient(
	acc *User,
	serverURL string,
	logger *logrus.Logger) (*lego.Client, error) {

	logger.Debug("setting up client")

	clientConfig := lego.NewConfig(acc)
	clientConfig.CADirURL = serverURL

	client, err := lego.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func setupAccount(
	email string,
	reregister bool,
	vault *vault.VaultClient,
	logger *logrus.Logger) (*User, error) {

	var acc *User

	secrets, err := vault.KVRead("account")
	if err != nil {
		return nil, err
	}

	if secrets == nil {
		acc, err = newAccount(email, reregister, vault, logger)
		if err != nil {
			return nil, err
		}

		return acc, nil
	}

	if accountInfo, ok := secrets["account"].(string); ok {
		err := json.Unmarshal([]byte(accountInfo), &acc)
		if err != nil {
			return nil, err
		}

		acc.key, err = getAccountKey(reregister, vault, logger)
		if err != nil {
			return nil, err
		}
		return acc, nil
	}

	return nil, errors.New("failed reading account from vault")
}

func newAccount(email string, reregister bool, vault *vault.VaultClient, logger *logrus.Logger) (*User, error) {
	key, err := getAccountKey(reregister, vault, logger)
	if err != nil {
		return nil, err
	}

	return &User{
		Email: email,
		key:   key,
	}, nil
}

func getAccountKey(reregister bool, vault *vault.VaultClient, logger *logrus.Logger) (crypto.PrivateKey, error) {
	var (
		keyDecoded crypto.PrivateKey
		err        error
	)

	secrets, err := vault.KVRead("key")
	if err != nil {
		return nil, err
	}

	if secrets != nil {
		if key, ok := secrets["pem"].(string); ok {
			return certcrypto.ParsePEMPrivateKey([]byte(key))
		} else {
			return nil, errors.New("key read from vault cannot be used")
		}
	} else if reregister {
		keyDecoded, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		keyEncoded := certcrypto.PEMEncode(keyDecoded)
		return keyDecoded, saveKey(keyEncoded, vault, logger)
	} else {
		return nil, errors.New("key not found and re-registering is disabled")
	}
}

func registerAccount(acc *User, client *lego.Client, vault *vault.VaultClient,
	cfg config.Acme, logger *logrus.Logger) (*lego.Client, error) {
	logger.Debug("checking client registration")
	_, err := client.Registration.QueryRegistration()
	if err != nil {
		logger.Warn("registration not found")

		client, err = recoverAccount(acc, client, vault, cfg, logger)
		if err != nil {
			return nil, err
		}
	} else {
		logger.Debug("account is registered correctly")
	}

	return client, nil
}

func recoverAccount(acc *User, client *lego.Client, vault *vault.VaultClient,
	cfg config.Acme, logger *logrus.Logger) (*lego.Client, error) {
	// Try to resolve registration by private key
	reg, err := client.Registration.ResolveAccountByKey()

	if err != nil {
		logger.Warn("could not resolve account by key")

		if cfg.ReregisterAccount {
			// Reset local registration data and reregister
			logger.Info("reregistering account")
			acc.Registration = nil
			client, err = setupClient(acc, cfg.ServerURL, logger)
			if err != nil {
				return nil, err
			}

			if cfg.EABKid != "" && cfg.EABHmacKey != "" {
				reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{TermsOfServiceAgreed: true, Kid: cfg.EABKid, HmacEncoded: cfg.EABHmacKey})
				if err != nil {
					return nil, err
				}
			} else {
				reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
				if err != nil {
					return nil, err
				}
			}

			acc.Registration = reg
		} else {
			return nil, errors.New("account registration not found and re-registering is disabled")
		}
	} else {
		logger.Info("account resolved by key")
		acc.Registration = reg
	}

	// Save new account registration
	return client, saveAccount(acc, vault, logger)
}

func saveAccount(account *User, vault *vault.VaultClient, logger *logrus.Logger) error {
	logger.Info("saving ACME account")
	jsonAccount, err := json.Marshal(account)
	if err != nil {
		return err
	}

	return vault.KVWrite("account", map[string]string{"account": string(jsonAccount)})
}

func saveKey(key []byte, vault *vault.VaultClient, logger *logrus.Logger) error {
	logger.Info("saving ACME account key")

	return vault.KVWrite("key", map[string]string{"pem": string(key)})
}
