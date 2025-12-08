//go:generate wire
//go:build wireinject

package main

import (
	"github.com/google/wire"
	"github.com/muxi-Infra/autossl-qiniuyun/cron"
)

// wireSet 定义所有依赖
var wireSet = wire.NewSet(
	cron.NewQiniuSSL,
	cron.NewCorn,
	NewApp,
)

func InitApp() (*App, error) {
	wire.Build(
		wireSet,
	)
	return &App{}, nil

}
