package config

import (
	"bytes"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"sync"
	"time"
)

// 定义全局配置变量
var (
	EmailConfig EmailConf
	QiniuConfig QiniuConf
	SSLConfig   SSLConf
	mu          sync.Mutex // 保护写操作的互斥锁
	Changed     bool
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

type SSLConf struct {
	Email    string        `yaml:"email"`
	Duration time.Duration `yaml:"duration"`
	SSLPath  string        `yaml:"sslPath"`
	Aliyun   struct {
		AccessKeyID     string `yaml:"accessKeyID"`
		AccessKeySecret string `yaml:"accessKeySecret"`
	} `yaml:"aliyun"`
	DB string `yaml:"db"`
}

type CronConf struct {
	EmailConf
	QiniuConf
	SSLConf
}

// InitViper 初始化 Viper 并监听配置文件变化
func InitViper(path string) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml") // 确保 Viper 识别 YAML 格式

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal("读取配置文件失败:", err.Error())
	}

	// 加载初始配置
	ReloadConfig()

	// 监听配置文件变化
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("配置文件发生变化，重新加载...")
		ReloadConfig()
	})
}

// ReloadConfig 重新加载配置到结构体
func ReloadConfig() {
	mu.Lock()
	defer mu.Unlock()

	if err := viper.UnmarshalKey("email", &EmailConfig); err != nil {
		log.Println("解析 Email 配置失败:", err)
		return
	}

	if err := viper.UnmarshalKey("qiniu", &QiniuConfig); err != nil {
		log.Println("解析 Qiniu 配置失败:", err)
		return
	}

	if err := viper.UnmarshalKey("ssl", &SSLConfig); err != nil {
		log.Println("解析 SSL 配置失败:", err)
		return
	}

	SetChangeStatus(true)

}

// WriteConfigToFile 将配置写入 YAML 文件
func WriteConfigToFile(yamlData string) error {
	mu.Lock()
	defer mu.Unlock()

	var cronConf CronConf
	decoder := yaml.NewDecoder(bytes.NewReader([]byte(yamlData)))
	err := decoder.Decode(&cronConf)
	if err != nil {
		log.Println("解析 YAML 失败:", err)
		return err
	}

	// 将 CronConf 结构体转换为 YAML
	data, err := yaml.Marshal(cronConf)
	if err != nil {
		log.Println("序列化 YAML 失败:", err)
		return err
	}

	// 获取配置文件路径
	configPath := viper.ConfigFileUsed()

	// 写入 YAML 文件
	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		log.Println("写入配置文件失败:", err)
		return err
	}

	// 让 Viper 重新加载配置
	err = viper.ReadInConfig()
	if err != nil {
		log.Println("重新加载 Viper 配置失败:", err)
		return err
	}

	return nil
}

// GetAllConfigsAsYAML 获取所有配置并转换为 YAML 字符串
func GetAllConfigsAsYAML() (string, error) {
	config := GetCronConfig()
	// 序列化成 YAML 格式
	data, err := yaml.Marshal(config)
	if err != nil {
		log.Println("序列化 YAML 失败:", err)
		return "", err
	}

	return string(data), nil
}

// GetCronConfig 获取 Cron 配置
func GetCronConfig() *CronConf {
	mu.Lock()
	defer mu.Unlock()
	return &CronConf{
		EmailConf: EmailConfig,
		QiniuConf: QiniuConfig,
		SSLConf:   SSLConfig,
	}
}

func SetChangeStatus(changed bool) {
	Changed = changed
}

func CheckIfStatus() bool {
	return Changed
}
