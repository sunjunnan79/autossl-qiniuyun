package dao

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	appcrypto "github.com/muxi-Infra/autossl-qiniuyun/pkg/crypto"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type SSLDao struct {
	db        *gorm.DB
	encryptor *appcrypto.Encryptor
}

func NewSSLDao(driver string, dsn string, encryptor *appcrypto.Encryptor) (*SSLDao, error) {
	if encryptor == nil {
		return nil, fmt.Errorf("encryptor is required")
	}

	db, err := openDB(driver, dsn)
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(
		&Certificate{},
		&CertificateDomain{},
		&CertificatePublishRecord{},
		&DistributedLock{},
		&CertMagicStoreEntry{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &SSLDao{
		db:        db,
		encryptor: encryptor,
	}, nil
}

func openDB(driver string, dsn string) (*gorm.DB, error) {
	switch strings.ToLower(driver) {
	case "sqlite", "":
		if dsn == "" {
			return nil, fmt.Errorf("sqlite dsn is required")
		}
		if dsn != ":memory:" {
			if err := os.MkdirAll(filepath.Dir(dsn), 0755); err != nil {
				return nil, fmt.Errorf("create db directory failed: %w", err)
			}
		}
		return gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	case "mysql":
		return gorm.Open(mysql.Open(dsn), &gorm.Config{})
	case "postgres", "postgresql":
		return gorm.Open(postgres.Open(dsn), &gorm.Config{})
	default:
		return nil, fmt.Errorf("unsupported store driver: %s", driver)
	}
}

func (dao *SSLDao) Close() error {
	sqlDB, err := dao.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (dao *SSLDao) GetActiveCertificate(ctx context.Context, parentDomain string) (*CertificateData, error) {
	var cert Certificate
	err := dao.db.WithContext(ctx).
		Preload("Domains").
		Where("parent_domain = ? AND status = ?", parentDomain, CertificateStatusActive).
		Order("version DESC").
		First(&cert).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return dao.toCertificateData(&cert)
}

func (dao *SSLDao) GetLatestPendingCertificate(ctx context.Context, parentDomain string) (*CertificateData, error) {
	var cert Certificate
	err := dao.db.WithContext(ctx).
		Preload("Domains").
		Where("parent_domain = ? AND status = ?", parentDomain, CertificateStatusPending).
		Order("version DESC").
		First(&cert).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return dao.toCertificateData(&cert)
}

func (dao *SSLDao) CreatePendingCertificate(ctx context.Context, parentDomain, fingerprint, certPEM, keyPEM string, notAfter time.Time) (*CertificateData, error) {
	certPEMEnc, err := dao.encryptor.EncryptString(certPEM)
	if err != nil {
		return nil, err
	}
	keyPEMEnc, err := dao.encryptor.EncryptString(keyPEM)
	if err != nil {
		return nil, err
	}

	var created Certificate
	err = dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var last Certificate
		nextVersion := 1
		if err := tx.Where("parent_domain = ?", parentDomain).Order("version DESC").First(&last).Error; err == nil {
			nextVersion = last.Version + 1
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		created = Certificate{
			ParentDomain: parentDomain,
			Version:      nextVersion,
			Status:       CertificateStatusPending,
			Fingerprint:  fingerprint,
			CertPEMEnc:   certPEMEnc,
			KeyPEMEnc:    keyPEMEnc,
			NotAfter:     notAfter.UTC(),
		}

		return tx.Create(&created).Error
	})
	if err != nil {
		return nil, err
	}

	return dao.toCertificateData(&created)
}

func (dao *SSLDao) MarkCertificateUploaded(ctx context.Context, certificateID uint, publishedCertID string) error {
	return dao.db.WithContext(ctx).
		Model(&Certificate{}).
		Where("id = ?", certificateID).
		Updates(map[string]any{
			"published_cert_id": publishedCertID,
			"last_error":        "",
		}).Error
}

func (dao *SSLDao) MarkCertificatePublishFailed(ctx context.Context, certificateID uint, publishedCertID, errorMessage string, attemptedDomains, successfulDomains []string, skippedDomains []SkippedDomain, failedDomains []FailedDomain) error {
	return dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Certificate{}).
			Where("id = ?", certificateID).
			Updates(map[string]any{
				"status":            CertificateStatusPending,
				"published_cert_id": publishedCertID,
				"last_error":        errorMessage,
			}).Error; err != nil {
			return err
		}

		record := CertificatePublishRecord{
			CertificateID:     certificateID,
			Status:            PublishStatusFailed,
			PublishedCertID:   publishedCertID,
			ErrorMessage:      errorMessage,
			AttemptedDomains:  marshalDomains(attemptedDomains),
			SuccessfulDomains: marshalDomains(successfulDomains),
			SkippedDomains:    marshalSkippedDomains(skippedDomains),
			FailedDomains:     marshalFailedDomains(failedDomains),
		}
		return tx.Create(&record).Error
	})
}

func (dao *SSLDao) ActivateCertificate(ctx context.Context, certificateID uint, domains []string, publishedCertID string, publishedAt time.Time, skippedDomains []SkippedDomain, failedDomains []FailedDomain) error {
	return dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var target Certificate
		if err := tx.Where("id = ?", certificateID).First(&target).Error; err != nil {
			return err
		}

		if err := tx.Model(&Certificate{}).
			Where("parent_domain = ? AND id <> ? AND status = ?", target.ParentDomain, target.ID, CertificateStatusActive).
			Update("status", CertificateStatusSuperseded).Error; err != nil {
			return err
		}

		if err := tx.Where("certificate_id = ?", target.ID).Delete(&CertificateDomain{}).Error; err != nil {
			return err
		}

		for _, domain := range domains {
			if err := tx.Create(&CertificateDomain{
				CertificateID: target.ID,
				Domain:        domain,
			}).Error; err != nil {
				return err
			}
		}

		if err := tx.Model(&Certificate{}).
			Where("id = ?", target.ID).
			Updates(map[string]any{
				"status":            CertificateStatusActive,
				"published_cert_id": publishedCertID,
				"last_published_at": publishedAt.UTC(),
				"last_error":        "",
			}).Error; err != nil {
			return err
		}

		record := CertificatePublishRecord{
			CertificateID:     target.ID,
			Status:            PublishStatusSuccess,
			PublishedCertID:   publishedCertID,
			PublishedAt:       ptrTime(publishedAt.UTC()),
			AttemptedDomains:  marshalDomains(domains),
			SuccessfulDomains: marshalDomains(domains),
			SkippedDomains:    marshalSkippedDomains(skippedDomains),
			FailedDomains:     marshalFailedDomains(failedDomains),
		}
		return tx.Create(&record).Error
	})
}

func (dao *SSLDao) RefreshActiveCertificateState(ctx context.Context, certificateID uint, domains []string, publishedCertID string, publishedAt time.Time, skippedDomains []SkippedDomain, failedDomains []FailedDomain) error {
	return dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("certificate_id = ?", certificateID).Delete(&CertificateDomain{}).Error; err != nil {
			return err
		}
		for _, domain := range domains {
			if err := tx.Create(&CertificateDomain{
				CertificateID: certificateID,
				Domain:        domain,
			}).Error; err != nil {
				return err
			}
		}

		if err := tx.Model(&Certificate{}).
			Where("id = ?", certificateID).
			Updates(map[string]any{
				"published_cert_id": publishedCertID,
				"last_published_at": publishedAt.UTC(),
				"last_error":        "",
			}).Error; err != nil {
			return err
		}

		record := CertificatePublishRecord{
			CertificateID:     certificateID,
			Status:            PublishStatusSuccess,
			PublishedCertID:   publishedCertID,
			PublishedAt:       ptrTime(publishedAt.UTC()),
			AttemptedDomains:  marshalDomains(domains),
			SuccessfulDomains: marshalDomains(domains),
			SkippedDomains:    marshalSkippedDomains(skippedDomains),
			FailedDomains:     marshalFailedDomains(failedDomains),
		}
		return tx.Create(&record).Error
	})
}

func (dao *SSLDao) RecordCertificatePublishSkipped(ctx context.Context, certificateID uint, publishedCertID string, attemptedDomains []string, skippedDomains []SkippedDomain, failedDomains []FailedDomain) error {
	record := CertificatePublishRecord{
		CertificateID:     certificateID,
		Status:            PublishStatusSkipped,
		PublishedCertID:   publishedCertID,
		AttemptedDomains:  marshalDomains(attemptedDomains),
		SuccessfulDomains: marshalDomains(nil),
		SkippedDomains:    marshalSkippedDomains(skippedDomains),
		FailedDomains:     marshalFailedDomains(failedDomains),
	}
	return dao.db.WithContext(ctx).Create(&record).Error
}

func (dao *SSLDao) TryAcquireLock(ctx context.Context, name, ownerToken, ownerInstance string, lease time.Duration) (bool, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(lease)

	return dao.acquireLockInternal(ctx, name, ownerToken, ownerInstance, expiresAt)
}

func (dao *SSLDao) ReleaseLock(ctx context.Context, name, ownerToken string) error {
	return dao.db.WithContext(ctx).Unscoped().
		Where("name = ? AND owner_token = ?", name, ownerToken).
		Delete(&DistributedLock{}).Error
}

func (dao *SSLDao) StoreCertMagicValue(ctx context.Context, key string, value []byte) error {
	encrypted, err := dao.encryptor.EncryptString(string(value))
	if err != nil {
		return err
	}

	entry := CertMagicStoreEntry{
		StorageKey: key,
		ValueEnc:   encrypted,
		Size:       int64(len(value)),
		ModifiedAt: time.Now().UTC(),
	}

	return dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing CertMagicStoreEntry
		err := tx.Where("storage_key = ?", key).First(&existing).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return tx.Create(&entry).Error
		case err != nil:
			return err
		default:
			return tx.Model(&existing).Updates(map[string]any{
				"value_enc":   entry.ValueEnc,
				"size":        entry.Size,
				"modified_at": entry.ModifiedAt,
			}).Error
		}
	})
}

func (dao *SSLDao) LoadCertMagicValue(ctx context.Context, key string) ([]byte, time.Time, error) {
	var entry CertMagicStoreEntry
	if err := dao.db.WithContext(ctx).Where("storage_key = ?", key).First(&entry).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, time.Time{}, fs.ErrNotExist
		}
		return nil, time.Time{}, err
	}

	plain, err := dao.encryptor.DecryptString(entry.ValueEnc)
	if err != nil {
		return nil, time.Time{}, err
	}
	return []byte(plain), entry.ModifiedAt, nil
}

func (dao *SSLDao) DeleteCertMagicValue(ctx context.Context, key string) error {
	exists := dao.CertMagicExists(ctx, key)
	if !exists {
		return fs.ErrNotExist
	}

	return dao.db.WithContext(ctx).
		Unscoped().
		Where("storage_key = ? OR storage_key LIKE ?", key, key+"/%").
		Delete(&CertMagicStoreEntry{}).Error
}

func (dao *SSLDao) CertMagicExists(ctx context.Context, key string) bool {
	var count int64
	if err := dao.db.WithContext(ctx).
		Model(&CertMagicStoreEntry{}).
		Where("storage_key = ? OR storage_key LIKE ?", key, key+"/%").
		Count(&count).Error; err != nil {
		return false
	}
	return count > 0
}

func (dao *SSLDao) ListCertMagicKeys(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var rows []CertMagicStoreEntry
	query := dao.db.WithContext(ctx).Model(&CertMagicStoreEntry{})
	if prefix != "" {
		query = query.Where("storage_key LIKE ?", prefix+"/%")
	}
	if err := query.Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fs.ErrNotExist
	}

	set := make(map[string]struct{})
	for _, row := range rows {
		key := row.StorageKey
		relative := strings.TrimPrefix(key, prefix)
		relative = strings.TrimPrefix(relative, "/")
		if relative == "" {
			continue
		}
		if !recursive {
			first := strings.Split(relative, "/")[0]
			if prefix != "" {
				key = path.Join(prefix, first)
			} else {
				key = first
			}
		}
		set[key] = struct{}{}
	}

	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func (dao *SSLDao) StatCertMagicKey(ctx context.Context, key string) (bool, int64, time.Time, error) {
	var entry CertMagicStoreEntry
	err := dao.db.WithContext(ctx).Where("storage_key = ?", key).First(&entry).Error
	switch {
	case err == nil:
		return true, entry.Size, entry.ModifiedAt, nil
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return false, 0, time.Time{}, err
	}

	if dao.CertMagicExists(ctx, key) {
		return false, 0, time.Time{}, nil
	}
	return false, 0, time.Time{}, fs.ErrNotExist
}

func (dao *SSLDao) ImportLegacySQLite(ctx context.Context, legacyPath string) error {
	if legacyPath == "" {
		return nil
	}

	legacyDB, err := gorm.Open(sqlite.Open(legacyPath), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("open legacy sqlite failed: %w", err)
	}

	var legacyCerts []LegacySSL
	if err := legacyDB.WithContext(ctx).Preload("Domains").Find(&legacyCerts).Error; err != nil {
		return fmt.Errorf("read legacy certificates failed: %w", err)
	}

	for _, legacy := range legacyCerts {
		existing, err := dao.GetActiveCertificate(ctx, legacy.DomainName)
		if err != nil {
			return err
		}
		if existing != nil {
			continue
		}

		fingerprint := legacy.CertID
		if fingerprint == "" {
			fingerprint = legacy.DomainName
		}
		created, err := dao.CreatePendingCertificate(ctx, legacy.DomainName, fingerprint, legacy.CertPEM, legacy.KeyPEM, legacy.NotAfter)
		if err != nil {
			return err
		}

		domains := make([]string, 0, len(legacy.Domains))
		for _, item := range legacy.Domains {
			domains = append(domains, item.Name)
		}

		if err := dao.ActivateCertificate(ctx, created.ID, domains, legacy.CertID, time.Now().UTC(), nil, nil); err != nil {
			return err
		}
	}

	return nil
}

func (dao *SSLDao) acquireLockInternal(ctx context.Context, name, ownerToken, ownerInstance string, expiresAt time.Time) (bool, error) {
	now := time.Now().UTC()
	var current DistributedLock
	err := dao.db.WithContext(ctx).Where("name = ?", name).First(&current).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		lock := DistributedLock{
			Name:          name,
			OwnerToken:    ownerToken,
			OwnerInstance: ownerInstance,
			ExpiresAt:     expiresAt,
		}
		if err := dao.db.WithContext(ctx).Create(&lock).Error; err != nil {
			return false, nil
		}
		return true, nil
	case err != nil:
		return false, err
	}

	if current.ExpiresAt.After(now) && current.OwnerToken != ownerToken {
		return false, nil
	}

	result := dao.db.WithContext(ctx).Model(&DistributedLock{}).
		Where("name = ? AND owner_token = ? AND expires_at = ?", current.Name, current.OwnerToken, current.ExpiresAt).
		Updates(map[string]any{
			"owner_token":    ownerToken,
			"owner_instance": ownerInstance,
			"expires_at":     expiresAt,
		})
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected == 1, nil
}

func (dao *SSLDao) toCertificateData(cert *Certificate) (*CertificateData, error) {
	certPEM, err := dao.encryptor.DecryptString(cert.CertPEMEnc)
	if err != nil {
		return nil, err
	}
	keyPEM, err := dao.encryptor.DecryptString(cert.KeyPEMEnc)
	if err != nil {
		return nil, err
	}

	domains := make([]string, 0, len(cert.Domains))
	for _, domain := range cert.Domains {
		domains = append(domains, domain.Domain)
	}
	sort.Strings(domains)

	return &CertificateData{
		ID:              cert.ID,
		ParentDomain:    cert.ParentDomain,
		Version:         cert.Version,
		Status:          cert.Status,
		Fingerprint:     cert.Fingerprint,
		CertPEM:         certPEM,
		KeyPEM:          keyPEM,
		NotAfter:        cert.NotAfter,
		PublishedCertID: cert.PublishedCertID,
		LastPublishedAt: cert.LastPublishedAt,
		LastError:       cert.LastError,
		Domains:         domains,
	}, nil
}

func marshalDomains(domains []string) string {
	if len(domains) == 0 {
		return "[]"
	}
	data, err := json.Marshal(domains)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func marshalSkippedDomains(skippedDomains []SkippedDomain) string {
	if len(skippedDomains) == 0 {
		return "[]"
	}
	data, err := json.Marshal(skippedDomains)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func marshalFailedDomains(failedDomains []FailedDomain) string {
	if len(failedDomains) == 0 {
		return "[]"
	}
	data, err := json.Marshal(failedDomains)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
