package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/muxi-Infra/autossl-qiniuyun/cron"
)

func main() {
	app, err := InitApp()
	if err != nil {
		log.Println(err)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Serve(ctx); err != nil {
		log.Println(err)
	}
}

type App struct {
	corn cron.Corn
}

func NewApp(cron cron.Corn) (*App, error) {
	return &App{
		corn: cron,
	}, nil
}

func (app *App) Serve(ctx context.Context) error {
	return app.corn.Start(ctx)
}
