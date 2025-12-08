package cron

type Corn interface {
	Start()
}

func NewCorn(q *QiniuSSL) (Corn, error) {
	return q, nil
}
