package qiniu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/qiniu/go-sdk/v7/auth"
)

type RequestError struct {
	StatusCode int
	Body       string
	Code       int
	Message    string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("qiniu request failed with status %d: %s", e.StatusCode, e.Body)
}

func (e *RequestError) IsMissingCNAME() bool {
	return e.Code == 400392 || strings.Contains(e.Message, "cname为空") || strings.Contains(e.Body, "cname为空")
}

type GetDomainReq struct {
	Limit int `json:"limit"`
}

type GetDomainResp struct {
	Domains []Domain `json:"domains"`
}

type Domain struct {
	Name     string `json:"name"`
	CreateAt string `json:"createAt"`
}

type UPSSLCertReq struct {
	Name       string `json:"name"`
	CommonName string `json:"common_name"`
	Pri        string `json:"pri"`
	Ca         string `json:"ca"`
}

type GetSSLCertListReq struct {
	Limit int `json:"limit"`
}

type GetSSLCertByIDResp struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
	Cert  struct {
		Certid           string   `json:"certid"`
		Name             string   `json:"name"`
		Uid              int      `json:"uid"`
		CommonName       string   `json:"common_name"`
		Dnsnames         []string `json:"dnsnames"`
		CreateTime       int      `json:"create_time"`
		NotBefore        int      `json:"not_before"`
		NotAfter         int      `json:"not_after"`
		Orderid          string   `json:"orderid"`
		ProductShortName string   `json:"product_short_name"`
		ProductType      string   `json:"product_type"`
		CertType         string   `json:"cert_type"`
		Encrypt          string   `json:"encrypt"`
		EncryptParameter string   `json:"encryptParameter"`
		Enable           bool     `json:"enable"`
		ChildOrderId     string   `json:"child_order_id"`
		State            string   `json:"state"`
		AutoRenew        bool     `json:"auto_renew"`
		Renewable        bool     `json:"renewable"`
		Ca               string   `json:"ca"`
		Pri              string   `json:"pri"`
	} `json:"cert"`
}

type GetSSLCertListResp struct {
	Certs []Cert `json:"certs"`
}

type GetSSLCertById struct {
	Certs []Cert `json:"certs"`
}

type Cert struct {
	CertId   string `json:"certid"`
	Name     string `json:"name"`
	NotAfter int64  `json:"not_after"`
}

type ForceHTTPSReq struct {
	CertId      string `json:"certid"`
	ForceHttps  bool   `json:"forceHttps"`
	Http2Enable bool   `json:"http2Enable"`
}

type UPSSLCertResp struct {
	CertID string `json:"certid"`
}

func (c *QiniuClient) newReq(method, path string, data any) ([]byte, error) {
	var body io.Reader
	urlParams := url.Values{}

	if data != nil {
		values, err := c.structToMap(data)
		if err != nil {
			return nil, err
		}

		if method == http.MethodGet {
			for k, v := range values {
				urlParams.Set(k, v)
			}
			path = fmt.Sprintf("%s?%s", path, urlParams.Encode())
		} else {
			jsonData, err := json.Marshal(data)
			if err != nil {
				return nil, err
			}
			body = bytes.NewBuffer(jsonData)
		}
	}

	req, err := http.NewRequest(method, QiniuBaseUrl+path, body)
	if err != nil {
		return nil, err
	}

	if method == http.MethodGet {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}

	if err := c.qiniuClient.AddToken(auth.TokenQBox, req); err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		reqErr := &RequestError{
			StatusCode: resp.StatusCode,
			Body:       string(result),
		}
		var payload struct {
			Code  int    `json:"code"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(result, &payload); err == nil {
			reqErr.Code = payload.Code
			reqErr.Message = payload.Error
		}
		return nil, reqErr
	}

	return result, nil
}

func (c *QiniuClient) structToMap(data any) (map[string]string, error) {
	result := make(map[string]string)

	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Struct {
		return nil, errors.New("data must be a struct")
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)
		if value.IsZero() {
			continue
		}

		key := field.Tag.Get("json")
		if key == "" {
			key = field.Name
		}

		result[key] = fmt.Sprintf("%v", value.Interface())
	}

	return result, nil
}
