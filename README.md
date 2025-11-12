# certificator

The tool that requests certificates from ACME supporting CA, solves DNS challenges, and stores certificates in Vault.

## Usage

1. Add domains that need certificates to domains.yml file
1. Set necessary environment variables (see [configuration](#Configuration))
1. Run certificator
1. Find certificates in Vault

## Configuration

Certificator reads most configuration parameters from environment variables.
They are defined in [pkg/config/config.go](pkg/config/config.go) Config struct

Configuration variables:
- `ACME_ACCOUNT_EMAIL` - email used in certificate retrieval process. **Required**
- `ACME_DNS_CHALLENGE_PROVIDER` - DNS challenge provider. Available providers can be found [here](https://go-acme.github.io/lego/dns/#dns-providers). **Required**
- `ACME_DNS_PROPAGATION_REQUIREMENT` - if set to true, requires complete DNS record propagation before stating that challenge is solved. Default: true
- `ACME_REREGISTER_ACCOUNT` - if set to true, allows registering an account with CA. This should be set to true for the first use. When credentials are stored in Vault, you can set this to false to avoid accidental registrations. Default: false
- `ACME_SERVER_URL` - ACME directory location. Default: https://acme-staging-v02.api.letsencrypt.org/directory
- `VAULT_APPROLE_ROLE_ID` - role ID for Vault approle authentication method. **Required in prod env**
- `VAULT_APPROLE_SECRET_ID` - secret ID for Vault approle authentication method. **Required in prod env**
- `VAULT_KV_STORAGE_PATH` - path in Vault KV storage where certificator stores certificates and account data. Default: secret/data/certificator/
- `VAULT_ADDR` sets vault address, example: "http://localhost:8200". **Required**
- `LOG_FORMAT` - logging format, supported formats - JSON and LOGFMT. Default: JSON
- `LOG_LEVEL` - logging level, supported levels - DEBUG, INFO, WARN, ERROR, FATAL. Default: INFO.
- `DNS_ADDRESS` - DNS server address that is used to check challenge DNS record propagation. Default: 127.0.0.1:53
- `ENVIRONMENT` - sets an environment where the certificator is running. If the environment is dev it uses token set in `VAULT_DEV_ROOT_TOKEN_ID` env variable to authenticate in Vault. If the environment is prod it uses an approle authentication method. Default: prod
- `CERTIFICATOR_DOMAINS_FILE` - path to a file where domains are defined. Overridden by `CERTIFICATOR_DOMAINS_LIST`. Default: /code/domains.yml
- `CERTIFICATOR_DOMAINS_LIST` - allows specifying domains directly via an environment variable. If set(non-empty), this takes precedence over loading domains from the DomainsFile (`CERTIFICATOR_DOMAINS_FILE`).
- `CERTIFICATOR_RENEW_BEFORE_DAYS` - set how many validity days should certificate have remaining before renewal. Default: 30

#### CNAME

- `LEGO_EXPERIMENTAL_CNAME_SUPPORT` boolean value which enables CNAME support. When `true`, it tries to resolve `_acme-challenge.<YOUR_DOMAIN>` and if it finds a CNAME record for that request it solves the challenge for the CNAME record value. Example:

```
If it finds this record:
CNAME _acme_challenge.test.com -> test.com.challenges.test.com
it creates TXT record in challenges.test.com zone:
TXT test.com.challenges.test.com -> <CHALLENGE_VALUE>
CA will verify domain ownership following the same scheme
```

This allows giving this tool a token with access rights limited to a single DNS zone.

#### Domains

The application supports two ways to configure the list of domains that it should retrieve certificates for:

### 1. Environment Variable: `CERTIFICATOR_DOMAINS_LIST`

You can specify the list of domains directly via the `CERTIFICATOR_DOMAINS_LIST` environment variable. This is useful for containerised deployments or environments where editing files is inconvenient. The value should be a comma-separated list of domains.

**Example:**

```sh
export CERTIFICATOR_DOMAINS_LIST=example.com,example.org,sub.example.net
```

Note: **If this variable is set (non-empty), it takes precedence over file-based configuration.**

### 2. Domains File: `CERTIFICATOR_DOMAINS_FILE`

If `CERTIFICATOR_DOMAINS_LIST` is not set, the application will load domains from a YAML file specified by the `CERTIFICATOR_DOMAINS_FILE` environment variable. An example file is in [domains.yml](domains.yml), which is deployed to `/code/domains.yml` in the container and is the default value for this variable.

**Example:**

```sh
export CERTIFICATOR_DOMAINS_FILE=/path/to/my_domains.yml
```

Every item in the array under the `domains` key results in a certificate. The first domain in an array item is used for the CommonName field of the certificate, all other domains are added using the Subject Alternate Names extension. Domains in a single array item are separated by commas. The first domain is also used as a key in the Vault KV store.

## Tests

This project contains unit and integration tests. To run them follow the instructions

#### Integration tests

Files related to integration tests lie in directory `test`.
It relies on several components: pebble, vault, challtestsrv.

Steps to run it:

1. Build container that runs tests:
`docker-compose build tester`
1. Run tests:
    - only integration tests:
    `docker-compose run --rm tester go test ./test/...`
    - all tests:
    `docker-compose run --rm tester go test ./...`
1. Check results
1. Bring down testing infrastructure
`docker-compose down`

#### Unit tests

Unit tests can be run without any dependencies, simply execute:
`go test ./pkg/...`
