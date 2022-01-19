module github.com/vinted/certificator

go 1.16

require (
	github.com/go-acme/lego v2.7.2+incompatible
	github.com/go-acme/lego/v4 v4.5.3
	github.com/go-test/deep v1.0.8 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/hcl v1.0.1-vault-3 // indirect
	github.com/hashicorp/vault/api v1.3.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/thanos-io/thanos v0.24.0
	gopkg.in/yaml.v2 v2.4.0
)

replace k8s.io/client-go => k8s.io/client-go v0.20.4
