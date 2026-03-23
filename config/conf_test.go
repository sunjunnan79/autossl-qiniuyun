package config

import (
	"testing"
	"time"
)

func TestParseNacosDSN(t *testing.T) {
	server, port, ns, user, pass, group, dataID, err := parseNacosDSN("127.0.0.1:8848?namespace=dev&username=nacos&password=secret&group=QA&dataId=svc")
	if err != nil {
		t.Fatalf("parseNacosDSN returned error: %v", err)
	}

	if server != "127.0.0.1" || port != 8848 || ns != "dev" || user != "nacos" || pass != "secret" || group != "QA" || dataID != "svc" {
		t.Fatalf("unexpected parse result: %q %d %q %q %q %q %q", server, port, ns, user, pass, group, dataID)
	}
}

func TestValidateConfigSetsDefaultDuration(t *testing.T) {
	conf := &Conf{
		Qiniu: QiniuConf{
			AccessKey: "ak",
			SecretKey: "sk",
		},
		SSL: SSLConf{
			Email: "ops@example.com",
			Crypto: CryptoConf{
				MasterKey: "master-key",
			},
			Store: StoreConf{
				Driver: "sqlite",
				DSN:    "./data/sqlite/ssl.db",
			},
		},
	}

	if err := validateConfig(conf); err != nil {
		t.Fatalf("validateConfig returned error: %v", err)
	}

	if conf.SSL.Duration != 5*time.Minute {
		t.Fatalf("expected default duration to be 5m, got %s", conf.SSL.Duration)
	}
	if conf.SSL.Store.CertMagicTablePrefix == "" {
		t.Fatalf("expected certmagic namespace default to be set")
	}
	if conf.SSL.Store.LockLease != 15*time.Minute {
		t.Fatalf("expected default lock lease to be 15m, got %s", conf.SSL.Store.LockLease)
	}
}
