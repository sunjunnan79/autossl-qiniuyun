package dao

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"os"
	"path/filepath"
)

// SSLDao 负责 SSL 表的数据库操作
type SSLDao struct {
	db *gorm.DB
}

// NewSSLDao 创建一个新的 SSLDao 实例
func NewSSLDao(path string) (*SSLDao, error) {
	// 自动创建父级目录
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create db directory failed: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}

	// 自动迁移表结构
	if err := db.AutoMigrate(&SSL{}, &Domain{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &SSLDao{db: db}, nil
}

// CreateSSL 创建 SSL 证书记录
func (dao *SSLDao) CreateSSL(ssl *SSL) error {
	return dao.db.Create(&ssl).Error
}

// GetSSLByID 通过 certId 获取 SSL 证书
func (dao *SSLDao) GetSSLByID(certId string) (*SSL, error) {
	var ssl SSL
	err := dao.db.Preload("Domains").Where("cert_id= ?", certId).First(&ssl).Error
	if err != nil {
		return nil, err
	}
	return &ssl, nil
}

// GetSSLByID 通过 certId 获取 SSL 证书
func (dao *SSLDao) GetSSLByName(name string) (*SSL, error) {
	var ssl SSL
	err := dao.db.Preload("Domains").Where("domain_name= ?", name).Find(&ssl).Error
	if err != nil {
		return nil, err
	}
	return &ssl, nil
}

func (dao *SSLDao) GetSSLS() (*[]SSL, error) {
	var ssl []SSL
	err := dao.db.Preload("Domains").Find(&ssl).Error
	if err != nil {
		return nil, err
	}
	return &ssl, nil
}

// GetSSLByCertID 通过 CertID 获取 SSL 证书
func (dao *SSLDao) GetSSLByCertID(certID string) (*SSL, error) {
	var ssl SSL
	err := dao.db.Preload("Domains").Where("cert_id = ?", certID).First(&ssl).Error
	if err != nil {
		return nil, err
	}
	return &ssl, nil
}

func (dao *SSLDao) GetDomains(domainName string) (int64, []string, error) {
	var ssl SSL
	var domainNames []string

	// 查询 SSL 记录
	if err := dao.db.Preload("Domains").Where("domain_name = ?", domainName).First(&ssl).Error; err != nil {
		return 0, nil, err
	}

	// 提取所有域名
	for _, domain := range ssl.Domains {
		domainNames = append(domainNames, domain.Name)
	}

	return ssl.NotAfter.Unix(), domainNames, nil
}

// UpdateSSL 更新 SSL 证书的域名
func (dao *SSLDao) UpdateSSL(certID string, newDomains []string) error {
	var ssl SSL
	var err error
	tx := dao.db.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	err = tx.Where("cert_id = ?", certID).First(&ssl).Error
	if err != nil {

		return err
	}

	// 删除旧的域名记录
	err = tx.Where("ssl_id = ?", ssl.ID).Delete(&Domain{}).Error
	if err != nil {
		return err
	}

	// 添加新的域名记录
	for _, domain := range newDomains {
		err = tx.Create(&Domain{Name: domain, SSLID: ssl.ID}).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// DeleteSSL 硬删除 SSL 证书及关联域名
func (dao *SSLDao) DeleteSSL(certID string) error {
	var ssl SSL
	if err := dao.db.Unscoped().Where("cert_id = ?", certID).First(&ssl).Error; err != nil {
		return err
	}

	// 直接硬删除关联的域名
	if err := dao.db.Unscoped().Where("ssl_id = ?", ssl.ID).Delete(&Domain{}).Error; err != nil {
		return err
	}

	// 直接硬删除 SSL 记录
	return dao.db.Unscoped().Delete(&ssl).Error
}
