package qiniu

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/qiniu/go-sdk/v7/auth"
)

func NewQiniuClient(accessKey string, secretKey string) *QiniuClient {
	return &QiniuClient{
		qiniuClient: auth.New(accessKey, secretKey),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

const QiniuBaseUrl = "https://api.qiniu.com"

type QiniuClient struct {
	qiniuClient *auth.Credentials
	client      *http.Client
}

func (c *QiniuClient) GetDomainList() (GetDomainResp, error) {
	var resp GetDomainResp
	data, err := c.newReq(http.MethodGet, "/domain", GetDomainReq{Limit: 1000})
	if err != nil {
		return GetDomainResp{}, err
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return GetDomainResp{}, err
	}
	return resp, nil
}

func (c *QiniuClient) UPSSLCert(pri, ca, name string) (UPSSLCertResp, error) {
	var resp UPSSLCertResp
	data, err := c.newReq(http.MethodPost, "/sslcert", UPSSLCertReq{Name: name, CommonName: name, Pri: pri, Ca: ca})
	if err != nil {
		return UPSSLCertResp{}, err
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return UPSSLCertResp{}, err
	}
	return resp, nil
}

func (c *QiniuClient) GETSSLCertList() (GetSSLCertListResp, error) {
	var resp GetSSLCertListResp
	data, err := c.newReq(http.MethodGet, "/sslcert", GetSSLCertListReq{Limit: 500})
	if err != nil {
		return GetSSLCertListResp{}, err
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return GetSSLCertListResp{}, err
	}
	return resp, nil
}

func (c *QiniuClient) GETSSLCertById(certID string) (GetSSLCertByIDResp, error) {
	var resp GetSSLCertByIDResp
	data, err := c.newReq(http.MethodGet, "/sslcert/"+certID, nil)
	if err != nil {
		return GetSSLCertByIDResp{}, err
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return GetSSLCertByIDResp{}, err
	}
	return resp, nil
}

func (c *QiniuClient) RemoveSSLCert(certID string) error {
	_, err := c.newReq(http.MethodPost, "/sslcert/"+certID, nil)
	return err
}

func (c *QiniuClient) ForceHTTPS(name, certID string) error {
	_, err := c.newReq(http.MethodPut, "/domain/"+name+"/sslize", ForceHTTPSReq{
		CertId:      certID,
		ForceHttps:  false,
		Http2Enable: false,
	})
	return err
}
