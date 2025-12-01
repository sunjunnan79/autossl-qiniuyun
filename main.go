package main

import (
	"github.com/muxi-Infra/autossl-qiniuyun/config"
	"github.com/muxi-Infra/autossl-qiniuyun/cron"
)

func main() {
	config.InitViper("./config")
	app := InitApp()
	app.Serve()
	return
}

type App struct {
	corn cron.Corn
}

func NewApp(cron cron.Corn) *App {
	return &App{
		corn: cron,
	}
}

func (app *App) Serve() {
	app.corn.Start()
}
