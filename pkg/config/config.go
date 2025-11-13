package config

import (
	"io/ioutil"
	"os"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// Acme contains acme related configuration parameters
type Acme struct {
	AccountEmail              string `envconfig:"ACME_ACCOUNT_EMAIL" required:"true"`
	DNSChallengeProvider      string `envconfig:"ACME_DNS_CHALLENGE_PROVIDER" required:"true"`
	DNSPropagationRequirement bool   `envconfig:"ACME_DNS_PROPAGATION_REQUIREMENT" default:"true"`
	ReregisterAccount         bool   `envconfig:"ACME_REREGISTER_ACCOUNT" default:"false"`
	ServerURL                 string `envconfig:"ACME_SERVER_URL" default:"https://acme-staging-v02.api.letsencrypt.org/directory"`
}

// Vault contains vault related configuration parameters
type Vault struct {
	ApproleRoleID   string `envconfig:"VAULT_APPROLE_ROLE_ID"`
	ApproleSecretID string `envconfig:"VAULT_APPROLE_SECRET_ID"`
	Token           string `envconfig:"VAULT_TOKEN"`
	KVStoragePath   string `envconfig:"VAULT_KV_STORAGE_PATH" default:"secret/data/certificator/"`
}

type Log struct {
	Format string `envconfig:"LOG_FORMAT" default:"JSON"`
	Level  string `envconfig:"LOG_LEVEL" default:"INFO"`
}

// Config contains all configuration parameters
type Config struct {
	Acme            Acme
	Vault           Vault
	Log             Log
	DNSAddress      string   `envconfig:"DNS_ADDRESS" default:"127.0.0.1:53"`
	Environment     string   `envconfig:"ENVIRONMENT" default:"prod"`
	DomainsFile     string   `envconfig:"CERTIFICATOR_DOMAINS_FILE" default:"/code/domains.yml"`
	RenewBeforeDays int      `envconfig:"CERTIFICATOR_RENEW_BEFORE_DAYS" default:"30"`
	Domains         []string `yaml:"domains"`
}

// LoadConfig loads configuration options to  variable
func LoadConfig() (Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return Config{}, errors.Wrapf(err, "failed getting config from env")
	}

	f, err := os.Open(cfg.DomainsFile)
	if err != nil {
		return Config{}, errors.Wrapf(err, "opening %s", cfg.DomainsFile)
	}

	content, err := ioutil.ReadAll(f)
	if err != nil {
		return Config{}, errors.Wrapf(err, "reading content of %s", cfg.DomainsFile)
	}

	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return Config{}, errors.Wrapf(err, "parsing %s", cfg.DomainsFile)
	}

	return cfg, err
}
