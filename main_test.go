package main

import (
	"testing"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

func newTestApp(t *testing.T) *application.App {
	t.Helper()
	return application.New(application.Options{
		Name: "GoHex-test",
	})
}

func TestWailsEmitterNilAppIsNoop(t *testing.T) {
	e := &wailsEmitter{}
	e.Emit("test.event", "payload") // must not panic with nil app
}

func TestWailsEmitterEmitsWhenAppSet(t *testing.T) {
	e := &wailsEmitter{}
	e.app = newTestApp(t)
	received := make(chan any, 1)
	unsub := e.app.Event.On("test.event", func(ev *application.CustomEvent) {
		received <- ev.Data
	})
	defer unsub()
	e.Emit("test.event", 42)
	select {
	case v := <-received:
		if v != 42 {
			t.Fatalf("payload = %v, want 42", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event was not delivered")
	}
}
