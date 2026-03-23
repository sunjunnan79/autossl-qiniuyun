package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nacos-group/nacos-sdk-go/clients"
	"github.com/nacos-group/nacos-sdk-go/common/constant"
	"github.com/nacos-group/nacos-sdk-go/vo"
	"github.com/spf13/viper"
)

type EmailConf struct {
	UserName string `yaml:"username"`
	Password string `yaml:"password"`
	Sender   string `yaml:"sender"`
	Receiver string `yaml:"receiver"`
	SmtpPort string `yaml:"smtpPort"`
	SmtpHost string `yaml:"smtpHost"`
}

type QiniuConf struct {
	AccessKey string `yaml:"accessKey"`
	SecretKey string `yaml:"secretKey"`
}

type StoreConf struct {
	Driver               string        `yaml:"driver"`
	DSN                  string        `yaml:"dsn"`
	CertMagicTablePrefix string        `yaml:"certmagicTablePrefix"`
	LockLease            time.Duration `yaml:"lockLease"`
}

type CryptoConf struct {
	MasterKey string `yaml:"masterKey"`
}

type MigrationConf struct {
	LegacySQLitePath string `yaml:"legacySQLitePath"`
}

type SSLConf struct {
	Email     string        `yaml:"email"`
	Duration  time.Duration `yaml:"duration"`
	SSLPath   string        `yaml:"sslPath"`
	DB        string        `yaml:"db"`
	Store     StoreConf     `yaml:"store"`
	Crypto    CryptoConf    `yaml:"crypto"`
	Migration MigrationConf `yaml:"migration"`
	Aliyun    struct {
		AccessKeyID     string `yaml:"accessKeyID"`
		AccessKeySecret string `yaml:"accessKeySecret"`
	} `yaml:"aliyun"`
}

type Conf struct {
	SSL   SSLConf   `yaml:"ssl"`
	Qiniu QiniuConf `yaml:"qiniu"`
	Email EmailConf `yaml:"email"`
}

const (
	defaultLocalConfigPath      = "./config/config.yaml"
	defaultSyncInterval         = 5 * time.Minute
	defaultDistributedLockLease = 15 * time.Minute
	defaultCertMagicNamespace   = "autossl-qiniu"
)

func GetConfig() (*Conf, error) {
	content, err := getConfigContent()
	if err != nil {
		return nil, err
	}

	v := viper.New()
	v.SetConfigType("yaml")

	if err := v.ReadConfig(bytes.NewBufferString(content)); err != nil {
		return nil, fmt.Errorf("parse config failed: %w", err)
	}

	var conf Conf
	if err := v.Unmarshal(&conf); err != nil {
		return nil, fmt.Errorf("decode config failed: %w", err)
	}

	if err := validateConfig(&conf); err != nil {
		return nil, err
	}

	return &conf, nil
}

func getConfigContent() (string, error) {
	if dsn := os.Getenv("NACOSDSN"); dsn != "" {
		content, err := getConfigFromNacos(dsn)
		if err == nil {
			return content, nil
		}
	}

	fileContent, err := os.ReadFile(defaultLocalConfigPath)
	if err != nil {
		return "", fmt.Errorf("read local config %s failed: %w", defaultLocalConfigPath, err)
	}
	return string(fileContent), nil
}

func getConfigFromNacos(dsn string) (string, error) {
	server, port, namespace, user, pass, group, dataID, err := parseNacosDSN(dsn)
	if err != nil {
		return "", err
	}

	serverConfigs := []constant.ServerConfig{{
		IpAddr: server,
		Port:   port,
		Scheme: "http",
	}}

	clientConfig := constant.ClientConfig{
		NamespaceId:         namespace,
		Username:            user,
		Password:            pass,
		TimeoutMs:           5000,
		NotLoadCacheAtStart: true,
		CacheDir:            "./data/configCache",
	}

	configClient, err := clients.CreateConfigClient(map[string]interface{}{
		"serverConfigs": serverConfigs,
		"clientConfig":  clientConfig,
	})
	if err != nil {
		return "", fmt.Errorf("init nacos config client failed: %w", err)
	}

	content, err := configClient.GetConfig(vo.ConfigParam{
		DataId: dataID,
		Group:  group,
	})
	if err != nil {
		return "", fmt.Errorf("get nacos config failed: %w", err)
	}
	return content, nil
}

func parseNacosDSN(dsn string) (server string, port uint64, ns, user, pass, group, dataID string, err error) {
	if dsn == "" {
		return "", 0, "", "", "", "", "", fmt.Errorf("environment variable NACOSDSN is empty")
	}

	parts := strings.SplitN(dsn, "?", 2)
	host := parts[0]
	params := url.Values{}
	if len(parts) == 2 {
		params, _ = url.ParseQuery(parts[1])
	}

	hostParts := strings.Split(host, ":")
	server = hostParts[0]
	if server == "" {
		return "", 0, "", "", "", "", "", fmt.Errorf("invalid nacos host in DSN")
	}
	if len(hostParts) > 1 {
		p, convErr := strconv.Atoi(hostParts[1])
		if convErr != nil {
			return "", 0, "", "", "", "", "", fmt.Errorf("invalid nacos port: %w", convErr)
		}
		port = uint64(p)
	} else {
		port = 8848
	}

	ns = params.Get("namespace")
	if ns == "" {
		ns = "public"
	}

	user = params.Get("username")
	pass = params.Get("password")
	group = params.Get("group")
	if group == "" {
		group = "DEFAULT_GROUP"
	}

	dataID = params.Get("dataId")
	if dataID == "" {
		return "", 0, "", "", "", "", "", fmt.Errorf("dataId is required in NACOSDSN")
	}

	return
}

func validateConfig(conf *Conf) error {
	switch {
	case conf.Qiniu.AccessKey == "":
		return fmt.Errorf("qiniu accessKey is required")
	case conf.Qiniu.SecretKey == "":
		return fmt.Errorf("qiniu secretKey is required")
	case conf.SSL.Email == "":
		return fmt.Errorf("ssl email is required")
	case conf.SSL.Crypto.MasterKey == "":
		return fmt.Errorf("ssl crypto masterKey is required")
	}

	if conf.SSL.Duration <= 0 {
		conf.SSL.Duration = defaultSyncInterval
	}

	if conf.SSL.Store.Driver == "" && conf.SSL.DB != "" {
		conf.SSL.Store.Driver = "sqlite"
	}
	if conf.SSL.Store.DSN == "" && conf.SSL.DB != "" {
		conf.SSL.Store.DSN = conf.SSL.DB
	}

	if conf.SSL.Store.Driver == "" {
		return fmt.Errorf("ssl store driver is required")
	}
	if conf.SSL.Store.DSN == "" {
		return fmt.Errorf("ssl store dsn is required")
	}
	if conf.SSL.Store.CertMagicTablePrefix == "" {
		conf.SSL.Store.CertMagicTablePrefix = defaultCertMagicNamespace
	}
	if conf.SSL.Store.LockLease <= 0 {
		conf.SSL.Store.LockLease = defaultDistributedLockLease
	}

	return nil
}
