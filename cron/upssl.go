package cron

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/muxi-Infra/autossl-qiniuyun/config"
	"github.com/muxi-Infra/autossl-qiniuyun/dao"
	appcrypto "github.com/muxi-Infra/autossl-qiniuyun/pkg/crypto"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/email"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/qiniu"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/ssl"
)

const (
	ExpirationThreshold = 20
	SecondsPerDay       = 24 * 60 * 60
	DefaultInterval     = 5 * time.Minute
	DefaultRunTimeout   = 5 * time.Minute
)

type QiniuSSL struct {
	qiniuClient *qiniu.QiniuClient
	sslDAO      *dao.SSLDao
	cmClient    *ssl.CertMagicClient
	emailClient *email.EmailClient
	receiver    string
	duration    time.Duration
	lockLease   time.Duration
	instanceID  string
}

func NewQiniuSSL() (*QiniuSSL, error) {
	conf, err := config.GetConfig()
	if err != nil {
		return nil, err
	}

	encryptor, err := appcrypto.NewEncryptor(conf.SSL.Crypto.MasterKey)
	if err != nil {
		return nil, err
	}

	sslDAO, err := dao.NewSSLDao(conf.SSL.Store.Driver, conf.SSL.Store.DSN, encryptor)
	if err != nil {
		return nil, err
	}

	if err := sslDAO.ImportLegacySQLite(context.Background(), conf.SSL.Migration.LegacySQLitePath); err != nil {
		return nil, err
	}

	instanceID, err := buildInstanceID()
	if err != nil {
		return nil, err
	}

	storage := ssl.NewDatabaseStorage(
		sslDAO,
		conf.SSL.Store.CertMagicTablePrefix,
		instanceID,
		conf.SSL.Store.LockLease,
	)

	provider := ssl.NewProvider(
		ssl.Aliyun,
		conf.SSL.Aliyun.AccessKeyID,
		conf.SSL.Aliyun.AccessKeySecret,
		"",
	)

	cmClient, err := ssl.NewCertMagicClient(conf.SSL.Email, storage, provider)
	if err != nil {
		return nil, err
	}

	return &QiniuSSL{
		qiniuClient: qiniu.NewQiniuClient(conf.Qiniu.AccessKey, conf.Qiniu.SecretKey),
		sslDAO:      sslDAO,
		cmClient:    cmClient,
		emailClient: email.NewEmailClient(
			conf.Email.UserName,
			conf.Email.Password,
			conf.Email.Sender,
			conf.Email.SmtpHost,
			conf.Email.SmtpPort,
		),
		receiver:   conf.Email.Receiver,
		duration:   conf.SSL.Duration,
		lockLease:  conf.SSL.Store.LockLease,
		instanceID: instanceID,
	}, nil
}

func (q *QiniuSSL) Start(ctx context.Context) error {
	interval := q.duration
	if interval <= 0 {
		interval = DefaultInterval
	}
	defer func() {
		_ = q.sslDAO.Close()
	}()

	if err := q.runOnce(ctx); err != nil {
		log.Println(err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := q.runOnce(ctx); err != nil {
				log.Println(err)
			}
		}
	}
}

func (q *QiniuSSL) runOnce(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in SSL sync: %v\n%s", r, string(debug.Stack()))
			log.Println(err)
			q.notifyError("autossl-qiniu alert", fmt.Sprintf("ssl sync panic: %v", r))
		}
	}()

	runCtx, cancel := context.WithTimeout(ctx, DefaultRunTimeout)
	defer cancel()

	domainGroups, err := q.getDomainGroups()
	if err != nil {
		q.notifyError("autossl-qiniu alert", fmt.Sprintf("group domains failed: %s", err.Error()))
		return err
	}

	for parentDomain, domains := range domainGroups {
		lockToken := fmt.Sprintf("%s:%s:%d", q.instanceID, parentDomain, time.Now().UnixNano())
		ok, err := q.sslDAO.TryAcquireLock(runCtx, "sync:"+parentDomain, lockToken, q.instanceID, q.lockLease)
		if err != nil {
			log.Println(err)
			continue
		}
		if !ok {
			continue
		}

		func() {
			defer func() {
				if err := q.sslDAO.ReleaseLock(context.Background(), "sync:"+parentDomain, lockToken); err != nil {
					log.Println(err)
				}
			}()

			if err := q.syncParentDomain(runCtx, parentDomain, domains); err != nil {
				log.Println(err)
				q.notifyError("autossl-qiniu alert", fmt.Sprintf("sync certificate for %s failed: %s", parentDomain, err.Error()))
			}
		}()
	}

	return nil
}

func (q *QiniuSSL) syncParentDomain(ctx context.Context, parentDomain string, domains []string) error {
	if len(domains) == 0 {
		return nil
	}

	sort.Strings(domains)
	activeCert, err := q.sslDAO.GetActiveCertificate(ctx, parentDomain)
	if err != nil {
		return fmt.Errorf("get active certificate failed: %w", err)
	}

	pendingCert, err := q.sslDAO.GetLatestPendingCertificate(ctx, parentDomain)
	if err != nil {
		return fmt.Errorf("get pending certificate failed: %w", err)
	}

	if pendingCert != nil && checkIfPass(time.Now().Unix(), pendingCert.NotAfter.Unix()) {
		return q.ensurePublished(ctx, pendingCert, domains, true)
	}

	if activeCert == nil {
		return q.obtainAndPublish(ctx, parentDomain, domains)
	}

	if !checkIfPass(time.Now().Unix(), activeCert.NotAfter.Unix()) {
		return q.obtainAndPublish(ctx, parentDomain, domains)
	}

	if !q.qiniuCertUsable(ctx, activeCert.PublishedCertID) {
		return q.ensurePublished(ctx, activeCert, domains, false)
	}

	pendingDomains := filterUnpublishedDomains(domains, activeCert.Domains)
	if len(pendingDomains) > 0 {
		return q.ensurePublished(ctx, activeCert, pendingDomains, false)
	}

	return nil
}

func (q *QiniuSSL) obtainAndPublish(ctx context.Context, parentDomain string, domains []string) error {
	certPEM, keyPEM, notAfter, fingerprint, err := q.obtainSSLCredit(ctx, parentDomain)
	if err != nil {
		return err
	}

	candidate, err := q.sslDAO.CreatePendingCertificate(ctx, parentDomain, fingerprint, certPEM, keyPEM, notAfter)
	if err != nil {
		return fmt.Errorf("create pending certificate failed: %w", err)
	}

	return q.ensurePublished(ctx, candidate, domains, true)
}

func (q *QiniuSSL) ensurePublished(ctx context.Context, cert *dao.CertificateData, domains []string, activate bool) error {
	publishedCertID := cert.PublishedCertID
	if !q.qiniuCertUsable(ctx, publishedCertID) {
		resp, err := q.qiniuClient.UPSSLCert(cert.KeyPEM, cert.CertPEM, cert.ParentDomain)
		if err != nil {
			_ = q.sslDAO.MarkCertificatePublishFailed(ctx, cert.ID, publishedCertID, err.Error(), domains, nil, nil, nil)
			return fmt.Errorf("upload certificate to qiniu failed: %w", err)
		}
		publishedCertID = resp.CertID
		if err := q.sslDAO.MarkCertificateUploaded(ctx, cert.ID, publishedCertID); err != nil {
			return fmt.Errorf("persist qiniu cert id failed: %w", err)
		}
	}

	var (
		successDomains []string
		skippedDomains []dao.SkippedDomain
		failedDomains  []dao.FailedDomain
	)

	for _, domain := range domains {
		if err := q.qiniuClient.ForceHTTPS(domain, publishedCertID); err != nil {
			var reqErr *qiniu.RequestError
			if errors.As(err, &reqErr) && reqErr.IsMissingCNAME() {
				skippedDomains = append(skippedDomains, dao.SkippedDomain{
					Domain: domain,
					Reason: "missing_cname",
					Error:  err.Error(),
				})
				continue
			}
			failedDomains = append(failedDomains, dao.FailedDomain{
				Domain: domain,
				Error:  err.Error(),
			})
			continue
		}
		successDomains = append(successDomains, domain)
	}

	if len(successDomains) == 0 {
		if len(failedDomains) > 0 {
			_ = q.sslDAO.MarkCertificatePublishFailed(ctx, cert.ID, publishedCertID, "no domains published successfully", domains, nil, skippedDomains, failedDomains)
			return fmt.Errorf("failed to publish domains for %s: failed=%+v skipped=%+v", cert.ParentDomain, failedDomains, skippedDomains)
		}
		if len(skippedDomains) > 0 {
			if err := q.sslDAO.RecordCertificatePublishSkipped(ctx, cert.ID, publishedCertID, domains, skippedDomains, nil); err != nil {
				return fmt.Errorf("record skipped publish failed: %w", err)
			}
		}
		log.Printf("skip publishing certificate for %s because all domains are missing cname: %+v", cert.ParentDomain, skippedDomains)
		return nil
	}

	if activate {
		if err := q.sslDAO.ActivateCertificate(ctx, cert.ID, successDomains, publishedCertID, time.Now().UTC(), skippedDomains, failedDomains); err != nil {
			return fmt.Errorf("activate certificate failed: %w", err)
		}
	} else {
		allSuccessfulDomains := uniqueSortedDomains(append(append([]string{}, cert.Domains...), successDomains...))
		if err := q.sslDAO.RefreshActiveCertificateState(ctx, cert.ID, allSuccessfulDomains, publishedCertID, time.Now().UTC(), skippedDomains, failedDomains); err != nil {
			return fmt.Errorf("refresh active certificate state failed: %w", err)
		}
	}

	if len(skippedDomains) > 0 {
		log.Printf("published certificate for %s with skipped domains: %+v", cert.ParentDomain, skippedDomains)
	}
	if len(failedDomains) > 0 {
		return fmt.Errorf("published certificate for %s with failed domains: %+v", cert.ParentDomain, failedDomains)
	}

	if len(skippedDomains) > 0 {
		return nil
	}

	return nil
}

func filterUnpublishedDomains(allDomains, publishedDomains []string) []string {
	if len(allDomains) == 0 {
		return nil
	}

	publishedSet := make(map[string]struct{}, len(publishedDomains))
	for _, domain := range publishedDomains {
		publishedSet[domain] = struct{}{}
	}

	var pending []string
	for _, domain := range allDomains {
		if _, exists := publishedSet[domain]; exists {
			continue
		}
		pending = append(pending, domain)
	}
	return uniqueSortedDomains(pending)
}

func (q *QiniuSSL) obtainSSLCredit(ctx context.Context, fatherDomain string) (certPEM, keyPEM string, notAfter time.Time, fingerprint string, err error) {
	certPEM, keyPEM, err = q.cmClient.ObtainCert(ctx, "*."+fatherDomain)
	if err != nil {
		return "", "", time.Time{}, "", fmt.Errorf("obtain certificate for %s failed: %w", "*."+fatherDomain, err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", "", time.Time{}, "", fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", time.Time{}, "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	sum := sha256.Sum256(block.Bytes)
	return certPEM, keyPEM, cert.NotAfter.UTC(), hex.EncodeToString(sum[:]), nil
}

func (q *QiniuSSL) qiniuCertUsable(ctx context.Context, certID string) bool {
	if certID == "" {
		return false
	}

	resp, err := q.qiniuClient.GETSSLCertById(certID)
	if err != nil {
		return false
	}
	if resp.Code != 0 && resp.Cert.Certid == "" {
		return false
	}
	return checkIfPass(time.Now().Unix(), int64(resp.Cert.NotAfter))
}

func (q *QiniuSSL) notifyError(subject, text string) {
	if q.emailClient == nil || q.receiver == "" {
		return
	}

	if err := q.emailClient.SendEmail([]string{q.receiver}, subject, text, "", nil); err != nil {
		log.Println(err)
	}
}

func checkIfPass(now, t int64) bool {
	return t-now > ExpirationThreshold*SecondsPerDay
}

func (q *QiniuSSL) getDomainGroups() (map[string][]string, error) {
	domainGroups := make(map[string][]string)
	domainList, err := q.qiniuClient.GetDomainList()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain list: %w", err)
	}

	for _, domain := range domainList.Domains {
		parentDomain, err := getParentDomain(domain.Name)
		if err != nil {
			log.Printf("parse domain %s failed: %v", domain.Name, err)
			continue
		}
		domainGroups[parentDomain] = append(domainGroups[parentDomain], domain.Name)
	}

	for parentDomain, domains := range domainGroups {
		domainGroups[parentDomain] = uniqueSortedDomains(domains)
	}

	return domainGroups, nil
}

func needsRepublish(active *dao.CertificateData, domains []string) bool {
	if active == nil {
		return true
	}
	if len(active.Domains) != len(domains) {
		return true
	}
	for index := range domains {
		if active.Domains[index] != domains[index] {
			return true
		}
	}
	return false
}

func uniqueSortedDomains(domains []string) []string {
	set := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		set[domain] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for domain := range set {
		result = append(result, domain)
	}
	sort.Strings(result)
	return result
}

func getParentDomain(domain string) (string, error) {
	if strings.HasPrefix(domain, ".") {
		return strings.TrimPrefix(domain, "."), nil
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("no parent domain for %s", domain)
	}

	return strings.Join(parts[1:], "."), nil
}

func buildInstanceID() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%d", hostname, os.Getpid()), nil
}
