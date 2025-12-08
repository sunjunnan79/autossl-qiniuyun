package main

import (
	"github.com/muxi-Infra/autossl-qiniuyun/cron"
	"log"
)

func main() {
	app, err := InitApp()
	if err != nil {
		log.Println(err)
		return
	}
	app.Serve()
	return
}

type App struct {
	corn cron.Corn
}

func NewApp(cron cron.Corn) (*App, error) {
	return &App{
		corn: cron,
	}, nil
}

func (app *App) Serve() {
	app.corn.Start()
}
