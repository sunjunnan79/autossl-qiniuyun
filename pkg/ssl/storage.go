package ssl

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/muxi-Infra/autossl-qiniuyun/dao"
)

type DatabaseStorage struct {
	dao        *dao.SSLDao
	namespace  string
	instanceID string
	lockLease  time.Duration
	lockTokens map[string]string
	mu         sync.Mutex
}

func NewDatabaseStorage(sslDAO *dao.SSLDao, namespace, instanceID string, lockLease time.Duration) *DatabaseStorage {
	if namespace == "" {
		namespace = "autossl-qiniu"
	}
	if lockLease <= 0 {
		lockLease = 15 * time.Minute
	}

	return &DatabaseStorage{
		dao:        sslDAO,
		namespace:  strings.Trim(namespace, "/"),
		instanceID: instanceID,
		lockLease:  lockLease,
		lockTokens: make(map[string]string),
	}
}

func (s *DatabaseStorage) Store(ctx context.Context, key string, value []byte) error {
	return s.dao.StoreCertMagicValue(ctx, s.storageKey(key), value)
}

func (s *DatabaseStorage) Load(ctx context.Context, key string) ([]byte, error) {
	value, _, err := s.dao.LoadCertMagicValue(ctx, s.storageKey(key))
	return value, err
}

func (s *DatabaseStorage) Delete(ctx context.Context, key string) error {
	return s.dao.DeleteCertMagicValue(ctx, s.storageKey(key))
}

func (s *DatabaseStorage) Exists(ctx context.Context, key string) bool {
	return s.dao.CertMagicExists(ctx, s.storageKey(key))
}

func (s *DatabaseStorage) List(ctx context.Context, key string, recursive bool) ([]string, error) {
	keys, err := s.dao.ListCertMagicKeys(ctx, s.storageKey(key), recursive)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(keys))
	for _, item := range keys {
		result = append(result, s.publicKey(item))
	}
	return result, nil
}

func (s *DatabaseStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	isTerminal, size, modifiedAt, err := s.dao.StatCertMagicKey(ctx, s.storageKey(key))
	if err != nil {
		if err == fs.ErrNotExist {
			return certmagic.KeyInfo{}, err
		}
		return certmagic.KeyInfo{}, err
	}
	return certmagic.KeyInfo{
		Key:        key,
		Modified:   modifiedAt,
		Size:       size,
		IsTerminal: isTerminal,
	}, nil
}

func (s *DatabaseStorage) Lock(ctx context.Context, name string) error {
	lockName := "certmagic:" + s.storageKey(name)
	token := fmt.Sprintf("%s:%d", s.instanceID, time.Now().UnixNano())

	for {
		ok, err := s.dao.TryAcquireLock(ctx, lockName, token, s.instanceID, s.lockLease)
		if err != nil {
			return err
		}
		if ok {
			s.mu.Lock()
			s.lockTokens[lockName] = token
			s.mu.Unlock()
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *DatabaseStorage) Unlock(ctx context.Context, name string) error {
	lockName := "certmagic:" + s.storageKey(name)
	s.mu.Lock()
	token := s.lockTokens[lockName]
	delete(s.lockTokens, lockName)
	s.mu.Unlock()
	if token == "" {
		return nil
	}
	return s.dao.ReleaseLock(ctx, lockName, token)
}

func (s *DatabaseStorage) storageKey(key string) string {
	if key == "" {
		return s.namespace
	}
	return path.Join(s.namespace, key)
}

func (s *DatabaseStorage) publicKey(key string) string {
	prefix := s.namespace + "/"
	return strings.TrimPrefix(key, prefix)
}
