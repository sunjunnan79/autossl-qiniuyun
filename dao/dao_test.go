package dao

import (
	"context"
	"errors"
	"io/fs"
	"sort"
	"testing"
	"time"

	appcrypto "github.com/muxi-Infra/autossl-qiniuyun/pkg/crypto"
)

func newTestDao(t *testing.T) *SSLDao {
	t.Helper()

	encryptor, err := appcrypto.NewEncryptor("test-master-key")
	if err != nil {
		t.Fatalf("NewEncryptor returned error: %v", err)
	}

	dao, err := NewSSLDao("sqlite", ":memory:", encryptor)
	if err != nil {
		t.Fatalf("NewSSLDao returned error: %v", err)
	}
	return dao
}

func TestCertificateActivationReplacesCurrentRecord(t *testing.T) {
	dao := newTestDao(t)
	defer dao.Close()

	ctx := context.Background()

	first, err := dao.CreatePendingCertificate(ctx, "example.com", "fp-1", "cert-1", "key-1", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreatePendingCertificate returned error: %v", err)
	}
	if err := dao.ActivateCertificate(ctx, first.ID, []string{"a.example.com"}, "qiniu-1", time.Now(), nil, nil); err != nil {
		t.Fatalf("ActivateCertificate returned error: %v", err)
	}

	second, err := dao.CreatePendingCertificate(ctx, "example.com", "fp-2", "cert-2", "key-2", time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatalf("CreatePendingCertificate returned error: %v", err)
	}
	if err := dao.ActivateCertificate(ctx, second.ID, []string{"b.example.com"}, "qiniu-2", time.Now(), nil, nil); err != nil {
		t.Fatalf("ActivateCertificate returned error: %v", err)
	}

	current, err := dao.GetActiveCertificate(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetActiveCertificate returned error: %v", err)
	}
	if current == nil || current.Version != 2 || current.CertPEM != "cert-2" {
		t.Fatalf("unexpected active certificate: %+v", current)
	}
}

func TestDistributedLockAllowsSingleOwner(t *testing.T) {
	dao := newTestDao(t)
	defer dao.Close()

	ctx := context.Background()
	ok, err := dao.TryAcquireLock(ctx, "lock-1", "owner-a", "instance-a", 5*time.Minute)
	if err != nil || !ok {
		t.Fatalf("first TryAcquireLock = %v, %v", ok, err)
	}

	ok, err = dao.TryAcquireLock(ctx, "lock-1", "owner-b", "instance-b", 5*time.Minute)
	if err != nil {
		t.Fatalf("second TryAcquireLock returned error: %v", err)
	}
	if ok {
		t.Fatalf("expected second lock acquisition to fail while lease is active")
	}

	if err := dao.ReleaseLock(ctx, "lock-1", "owner-a"); err != nil {
		t.Fatalf("ReleaseLock returned error: %v", err)
	}

	ok, err = dao.TryAcquireLock(ctx, "lock-1", "owner-b", "instance-b", 5*time.Minute)
	if err != nil || !ok {
		t.Fatalf("third TryAcquireLock = %v, %v", ok, err)
	}
}

func TestCertMagicStoreCRUD(t *testing.T) {
	dao := newTestDao(t)
	defer dao.Close()

	ctx := context.Background()
	if err := dao.StoreCertMagicValue(ctx, "a/b/c", []byte("hello")); err != nil {
		t.Fatalf("StoreCertMagicValue returned error: %v", err)
	}

	value, _, err := dao.LoadCertMagicValue(ctx, "a/b/c")
	if err != nil {
		t.Fatalf("LoadCertMagicValue returned error: %v", err)
	}
	if string(value) != "hello" {
		t.Fatalf("expected hello, got %q", value)
	}

	keys, err := dao.ListCertMagicKeys(ctx, "a", false)
	if err != nil {
		t.Fatalf("ListCertMagicKeys returned error: %v", err)
	}
	sort.Strings(keys)
	if len(keys) != 1 || keys[0] != "a/b" {
		t.Fatalf("unexpected keys: %+v", keys)
	}

	isTerminal, size, _, err := dao.StatCertMagicKey(ctx, "a/b/c")
	if err != nil {
		t.Fatalf("StatCertMagicKey returned error: %v", err)
	}
	if !isTerminal || size != 5 {
		t.Fatalf("unexpected stat: terminal=%v size=%d", isTerminal, size)
	}

	if err := dao.DeleteCertMagicValue(ctx, "a"); err != nil {
		t.Fatalf("DeleteCertMagicValue returned error: %v", err)
	}
	if _, _, err := dao.LoadCertMagicValue(ctx, "a/b/c"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestRecordSkippedPublish(t *testing.T) {
	dao := newTestDao(t)
	defer dao.Close()

	ctx := context.Background()
	cert, err := dao.CreatePendingCertificate(ctx, "example.com", "fp-1", "cert", "key", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreatePendingCertificate returned error: %v", err)
	}

	err = dao.RecordCertificatePublishSkipped(ctx, cert.ID, "qiniu-1", []string{"a.example.com"}, []SkippedDomain{{
		Domain: "a.example.com",
		Reason: "missing_cname",
		Error:  "qiniu request failed",
	}}, nil)
	if err != nil {
		t.Fatalf("RecordCertificatePublishSkipped returned error: %v", err)
	}

	var records []CertificatePublishRecord
	if err := dao.db.Where("certificate_id = ?", cert.ID).Find(&records).Error; err != nil {
		t.Fatalf("query publish records returned error: %v", err)
	}
	if len(records) != 1 || records[0].Status != PublishStatusSkipped {
		t.Fatalf("unexpected publish records: %+v", records)
	}
}
