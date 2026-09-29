// Package events carries decision-log entries from every service to web.
// Events must never contain token values or private key material.
package events

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"agentbroker/internal/config"
)

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type Event struct {
	Tenant    string          `json:"tenant"`
	RunID     string          `json:"run_id"`
	TS        time.Time       `json:"ts"`
	Component string          `json:"component"`
	Type      string          `json:"type"`
	Result    string          `json:"result"` // ok | deny | info | error
	Summary   string          `json:"summary"`
	Checks    []Check         `json:"checks,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// Emitter posts events asynchronously; a slow or absent web never blocks callers.
type Emitter struct {
	component string
	ch        chan Event
}

func NewEmitter(component string) *Emitter {
	e := &Emitter{component: component, ch: make(chan Event, 256)}
	go e.loop()
	return e
}

func (e *Emitter) Emit(ev Event) {
	if ev.Tenant == "" {
		return
	}
	ev.Component = e.component
	if ev.TS.IsZero() {
		ev.TS = time.Now()
	}
	select {
	case e.ch <- ev:
	default:
		log.Printf("events: dropped %s", ev.Type)
	}
}

func (e *Emitter) loop() {
	client := &http.Client{Timeout: 2 * time.Second}
	for ev := range e.ch {
		b, _ := json.Marshal(ev)
		resp, err := client.Post(config.EventsURL+"/events", "application/json", bytes.NewReader(b))
		if err != nil {
			continue
		}
		resp.Body.Close()
	}
}
