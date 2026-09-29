package harness

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"agentbroker/internal/config"
)

const (
	maxTurns   = 6
	maxTickets = 3
)

//go:embed toyrepo
var toyrepo embed.FS

const systemPrompt = `You are a code reviewer. Review the repository you are given for security issues.
File one ticket per distinct issue with the create_ticket tool (at most 3 tickets).
When you are done, reply with a short summary of your findings.`

var createTicketTool = anthropic.ToolParam{
	Name:        "create_ticket",
	Description: anthropic.String("File a ticket in the team's issue tracker for one finding."),
	Strict:      anthropic.Bool(true),
	InputSchema: anthropic.ToolInputSchemaParam{
		Properties: map[string]any{
			"title": map[string]any{"type": "string", "description": "Short summary of the issue"},
			"body":  map[string]any{"type": "string", "description": "Location, impact and suggested fix"},
		},
		Required:    []string{"title", "body"},
		ExtraFields: map[string]any{"additionalProperties": false},
	},
}

func repoPrompt() string {
	var names []string
	_ = fs.WalkDir(toyrepo, "toyrepo", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, path)
		}
		return nil
	})
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("Review this repository.\n")
	for _, n := range names {
		data, _ := toyrepo.ReadFile(n)
		fmt.Fprintf(&b, "\n<file path=%q>\n%s</file>\n", strings.TrimPrefix(n, "toyrepo/"), data)
	}
	return b.String()
}

// agent is a manual tool-use loop. The model only ever sees the system
// prompt, the repo, the tool schema and the strings createTicket returns.
func (r *Run) agent(ctx context.Context) {
	client := anthropic.NewClient()
	model := config.Env("CLAUDE_MODEL", "claude-opus-5-5")
	params := anthropic.MessageNewParams{
		Model:        anthropic.Model(model),
		MaxTokens:    8000,
		System:       []anthropic.TextBlockParam{{Text: systemPrompt}},
		Tools:        []anthropic.ToolUnionParam{{OfTool: &createTicketTool}},
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffortLow},
		Messages:     []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(repoPrompt()))},
	}
	reqOpts := []option.RequestOption{
		option.WithHeaderAdd("anthropic-beta", "server-side-fallback-2026-07-01"),
		option.WithJSONSet("fallbacks", "default"),
	}

	r.emit("run.status", "info", "agent started ("+model+")", statusData("running"))
	r.emitContext(params)

	for turn := 0; turn < maxTurns; turn++ {
		resp, err := client.Messages.New(ctx, params, reqOpts...)
		if err != nil {
			status := "failed"
			if ctx.Err() != nil {
				status = "cancelled"
			}
			r.emit("run.status", "error", "model call failed: "+err.Error(), statusData(status))
			return
		}
		// Append-only history: the response goes in unmodified.
		params.Messages = append(params.Messages, resp.ToParam())
		r.emitContext(params)

		switch resp.StopReason {
		case anthropic.StopReasonRefusal:
			r.emit("run.status", "error", "model refused", statusData("failed"))
			return
		case anthropic.StopReasonMaxTokens:
			r.emit("run.status", "error", "model hit max_tokens", statusData("failed"))
			return
		case anthropic.StopReasonToolUse:
		default:
			r.emit("model.final", "info", finalText(resp), nil)
			r.emit("run.status", "ok", "agent finished", statusData("completed"))
			return
		}

		var results []anthropic.ContentBlockParamUnion
		for _, block := range resp.Content {
			tu, ok := block.AsAny().(anthropic.ToolUseBlock)
			if !ok {
				continue
			}
			results = append(results, anthropic.NewToolResultBlock(tu.ID, r.runTool(ctx, tu), false))
		}
		params.Messages = append(params.Messages, anthropic.NewUserMessage(results...))
		r.emitContext(params)
	}
	r.emit("run.status", "error", "turn limit reached", statusData("completed"))
}

func (r *Run) runTool(ctx context.Context, tu anthropic.ToolUseBlock) string {
	if tu.Name != "create_ticket" {
		return "Unknown tool."
	}
	var in struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	if err := json.Unmarshal(tu.Input, &in); err != nil || in.Title == "" {
		return "Invalid input: title and body are required."
	}
	r.emit("model.intent", "info", "model intent: create_ticket “"+in.Title+"”", nil)
	return r.createTicket(ctx, in.Title, in.Body)
}

// emitContext publishes exactly what is sent to Claude, for the dashboard's
// "model context" panel.
func (r *Run) emitContext(p anthropic.MessageNewParams) {
	b, err := json.Marshal(p)
	if err == nil {
		r.emit("model.context", "info", "", b)
	}
}

func finalText(m *anthropic.Message) string {
	var parts []string
	for _, block := range m.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func statusData(s string) []byte {
	b, _ := json.Marshal(map[string]string{"status": s})
	return b
}
