package dao

import (
	"time"

	"gorm.io/gorm"
)

const (
	CertificateStatusPending    = "pending_publish"
	CertificateStatusActive     = "active"
	CertificateStatusSuperseded = "superseded"
	CertificateStatusFailed     = "failed"
)

const (
	PublishStatusSuccess = "success"
	PublishStatusFailed  = "failed"
	PublishStatusSkipped = "skipped"
)

type Certificate struct {
	gorm.Model
	ParentDomain    string `gorm:"size:255;not null;index:idx_cert_parent_status,priority:1;index:idx_cert_parent_version,priority:1"`
	Version         int    `gorm:"not null;index:idx_cert_parent_version,priority:2"`
	Status          string `gorm:"size:32;not null;index:idx_cert_parent_status,priority:2"`
	Fingerprint     string `gorm:"size:128;not null"`
	CertPEMEnc      string `gorm:"type:text;not null"`
	KeyPEMEnc       string `gorm:"type:text;not null"`
	NotAfter        time.Time
	PublishedCertID string `gorm:"size:255"`
	LastPublishedAt *time.Time
	LastError       string `gorm:"type:text"`
	Domains         []CertificateDomain
	PublishRecords  []CertificatePublishRecord
}

type CertificateDomain struct {
	gorm.Model
	CertificateID uint   `gorm:"not null;index"`
	Domain        string `gorm:"size:255;not null;index"`
}

type CertificatePublishRecord struct {
	gorm.Model
	CertificateID     uint `gorm:"not null;index"`
	Status            string
	PublishedCertID   string `gorm:"size:255"`
	ErrorMessage      string `gorm:"type:text"`
	PublishedAt       *time.Time
	AttemptedDomains  string `gorm:"type:text"`
	SuccessfulDomains string `gorm:"type:text"`
	SkippedDomains    string `gorm:"type:text"`
	FailedDomains     string `gorm:"type:text"`
}

type DistributedLock struct {
	gorm.Model
	Name          string    `gorm:"size:255;uniqueIndex;not null"`
	OwnerToken    string    `gorm:"size:255;not null"`
	OwnerInstance string    `gorm:"size:255;not null"`
	ExpiresAt     time.Time `gorm:"index"`
}

type CertMagicStoreEntry struct {
	gorm.Model
	StorageKey string    `gorm:"size:512;uniqueIndex;not null"`
	ValueEnc   string    `gorm:"type:longtext;not null"`
	Size       int64     `gorm:"not null"`
	ModifiedAt time.Time `gorm:"index"`
}

type LegacySSL struct {
	gorm.Model
	DomainName string
	CertID     string
	CertPEM    string
	KeyPEM     string
	NotAfter   time.Time
	Domains    []LegacyDomain `gorm:"foreignKey:SSLID"`
}

type LegacyDomain struct {
	gorm.Model
	Name  string
	SSLID uint
}

type CertificateData struct {
	ID              uint
	ParentDomain    string
	Version         int
	Status          string
	Fingerprint     string
	CertPEM         string
	KeyPEM          string
	NotAfter        time.Time
	PublishedCertID string
	LastPublishedAt *time.Time
	LastError       string
	Domains         []string
}

type SkippedDomain struct {
	Domain string `json:"domain"`
	Reason string `json:"reason"`
	Error  string `json:"error"`
}

type FailedDomain struct {
	Domain string `json:"domain"`
	Error  string `json:"error"`
}
