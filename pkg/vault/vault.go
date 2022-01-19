package vault

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
)

type VaultClient struct {
	client   *api.Client
	kvPrefix string
	logger   *logrus.Logger
}

// NewClient initializes vault client with default configuration.
// It authenticates using approle method (or uses provided token in dev) and returns.
func NewVaultClient(roleID, secretID, env, kvPrefix string, logger *logrus.Logger) (*VaultClient, error) {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}

	if env == "dev" {
		client.SetToken(os.Getenv("VAULT_DEV_ROOT_TOKEN_ID"))
	} else {
		payload := map[string]interface{}{"role_id": roleID,
			"secret_id": secretID}
		resp, err := client.Logical().Write("auth/approle/login", payload)
		if err != nil {
			return nil, err
		}

		client.SetToken(resp.Auth.ClientToken)
	}

	return &VaultClient{client: client, kvPrefix: kvPrefix, logger: logger}, nil
}

// KVWrite writes value to vault key value v2 storage
func (cl *VaultClient) KVWrite(path string, value map[string]string) error {
	fullPath := vaultFullPath(path, cl.kvPrefix)
	cl.logger.Infof("Writing to vault path %s", fullPath)
	payload := map[string]interface{}{"data": value}
	resp, err := cl.client.Logical().Write(fullPath, payload)
	if err != nil {
		err = fmt.Errorf("failed storing KV value to Vault, got: %v, error: %s", resp, err)
		return err
	}

	return nil
}

// KVRead reads data from vault key value storage
func (cl *VaultClient) KVRead(path string) (map[string]interface{}, error) {
	fullPath := vaultFullPath(path, cl.kvPrefix)
	cl.logger.Infof("reading Vault path: %s", fullPath)
	resp, err := cl.client.Logical().Read(fullPath)
	if err != nil {
		err = fmt.Errorf("failed reading KV from Vault at path: %s, got: %v, error: %s",
			fullPath, resp, err)
		return nil, err
	}

	if resp == nil {
		return nil, nil
	}

	if value, ok := resp.Data["data"].(map[string]interface{}); ok {
		return value, nil
	}

	return nil, nil
}

func vaultFullPath(path string, prefix string) string {
	return prefix + path
}
