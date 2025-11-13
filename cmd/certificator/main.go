package main

import (
	"strings"

	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/acme"
	"github.com/vinted/certificator/pkg/certificate"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/vault"
)

func main() {
	logger := logrus.New()
	legoLog.Logger = logger

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal(err)
	}

	switch cfg.Log.Format {
	case "JSON":
		logger.SetFormatter(&logrus.JSONFormatter{})
	case "LOGFMT":
		logger.SetFormatter(&logrus.TextFormatter{})
	}

	switch cfg.Log.Level {
	case "DEBUG":
		logger.SetLevel(logrus.DebugLevel)
	case "INFO":
		logger.SetLevel(logrus.InfoLevel)
	case "WARN":
		logger.SetLevel(logrus.WarnLevel)
	case "ERROR":
		logger.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		logger.SetLevel(logrus.FatalLevel)
	}

	vaultClient, err := vault.NewVaultClient(cfg.Vault, cfg.Environment, logger)
	if err != nil {
		logger.Fatal(err)
	}

	acmeClient, err := acme.NewClient(cfg.Acme.AccountEmail, cfg.Acme.ServerURL,
		cfg.Acme.ReregisterAccount, vaultClient, logger)
	if err != nil {
		logger.Fatal(err)
	}

	var failedDomains []string

	for _, dom := range cfg.Domains {
		allDomains := strings.Split(dom, ",")
		mainDomain := allDomains[0]
		cert, err := certificate.GetCertificate(mainDomain, vaultClient)
		if err != nil {
			failedDomains = append(failedDomains, mainDomain)
			logger.Error(err)
			continue
		}
		logger.Infof("checking certificate for %s", mainDomain)

		needsReissuing, err := certificate.NeedsReissuing(cert, allDomains, cfg.RenewBeforeDays, logger)
		if err != nil {
			failedDomains = append(failedDomains, mainDomain)
			logger.Error(err)
			continue
		}

		if needsReissuing {
			logger.Infof("obtaining certificate for %s", mainDomain)
			err := certificate.ObtainCertificate(acmeClient, vaultClient, allDomains,
				cfg.DNSAddress, cfg.Acme.DNSChallengeProvider, cfg.Acme.DNSPropagationRequirement)
			if err != nil {
				failedDomains = append(failedDomains, mainDomain)
				logger.Error(err)
				continue
			}
		} else {
			logger.Infof("certificate for %s is up to date, skipping renewal", mainDomain)
		}
	}

	if len(failedDomains) > 0 {
		logger.Fatalf("Failed to renew certificates for: %v", failedDomains)
	}
}
