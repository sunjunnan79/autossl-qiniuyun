package cron

import "context"

type Corn interface {
	Start(ctx context.Context) error
}

func NewCorn(q *QiniuSSL) (Corn, error) {
	return q, nil
}
