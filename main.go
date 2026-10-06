package main

import (
	"embed"
	"log"
	"os"
	"strings"

	"github.com/IshikawaUta/gohex/internal/service"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

// wailsEmitter adapts the Wails event manager to the service.Emitter
// interface (Wails Emit takes variadic data, the interface a single payload).
// The app pointer is filled in after application.New because the service must
// exist before the app registers it.
type wailsEmitter struct {
	app *application.App
}

func (e *wailsEmitter) Emit(name string, payload any) {
	if e.app == nil {
		return
	}
	e.app.Event.Emit(name, payload)
}

func main() {
	emitter := &wailsEmitter{}
	svc, err := service.New("", emitter)
	if err != nil {
		log.Fatalf("gohex: init service: %v", err)
	}

	// Startup hints: open files given on the command line (or GOHEX_OPEN,
	// comma-separated) and optionally pre-accept the disclaimer for tests.
	var files []string
	if v := os.Getenv("GOHEX_OPEN"); v != "" {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				files = append(files, f)
			}
		}
	}
	files = append(files, os.Args[1:]...)
	skip := os.Getenv("GOHEX_SKIP_DISCLAIMER") == "1"
	svc.SetStartupHints(skip, files)

	app := application.New(application.Options{
		Name:        "GoHex",
		Description: "Hex editor and digital forensic suite",
		Services: []application.Service{
			application.NewService(svc),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})
	emitter.app = app

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     "GoHex",
		Width:     1280,
		Height:    720,
		MinWidth:  800,
		MinHeight: 480,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(24, 26, 32),
		URL:              "/",
	})

	err = app.Run()
	svc.Close()
	if err != nil {
		log.Printf("gohex: exit: %v", err)
		os.Exit(1)
	}
}
