package ssl

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/muxi-Infra/autossl-qiniuyun/dao"
	appcrypto "github.com/muxi-Infra/autossl-qiniuyun/pkg/crypto"
)

func newDatabaseStorage(t *testing.T) *DatabaseStorage {
	t.Helper()

	encryptor, err := appcrypto.NewEncryptor("storage-test-key")
	if err != nil {
		t.Fatalf("NewEncryptor returned error: %v", err)
	}
	sslDAO, err := dao.NewSSLDao("sqlite", ":memory:", encryptor)
	if err != nil {
		t.Fatalf("NewSSLDao returned error: %v", err)
	}

	t.Cleanup(func() {
		_ = sslDAO.Close()
	})

	return NewDatabaseStorage(sslDAO, "tests", "instance-a", time.Minute)
}

func TestDatabaseStorageRoundTrip(t *testing.T) {
	storage := newDatabaseStorage(t)
	ctx := context.Background()

	if err := storage.Store(ctx, "a/b", []byte("hello")); err != nil {
		t.Fatalf("Store returned error: %v", err)
	}

	value, err := storage.Load(ctx, "a/b")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if string(value) != "hello" {
		t.Fatalf("expected hello, got %q", value)
	}

	info, err := storage.Stat(ctx, "a/b")
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if !info.IsTerminal || info.Size != 5 {
		t.Fatalf("unexpected key info: %+v", info)
	}
}

func TestDatabaseStorageDeletePrefix(t *testing.T) {
	storage := newDatabaseStorage(t)
	ctx := context.Background()

	if err := storage.Store(ctx, "a/b", []byte("one")); err != nil {
		t.Fatalf("Store returned error: %v", err)
	}
	if err := storage.Store(ctx, "a/c", []byte("two")); err != nil {
		t.Fatalf("Store returned error: %v", err)
	}

	if err := storage.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}

	if _, err := storage.Load(ctx, "a/b"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
}
