// Command demo runs one component of the agent credential broker demo.
// `demo supervise` generates key material and starts all the others as
// local processes; `demo pki` only generates key material (for Compose).
package main

import (
	"fmt"
	"os"

	"agentbroker/internal/broker"
	"agentbroker/internal/grants"
	"agentbroker/internal/harness"
	"agentbroker/internal/jira"
	"agentbroker/internal/supervise"
	"agentbroker/internal/web"
)

func main() {
	cmds := map[string]func(){
		"supervise": supervise.Main,
		"pki":       supervise.Init,
		"web":       web.Main,
		"grants":    grants.Main,
		"broker":    broker.Main,
		"harness":   harness.Main,
		"jira":      jira.Main,
	}
	if len(os.Args) < 2 || cmds[os.Args[1]] == nil {
		fmt.Fprintln(os.Stderr, "usage: demo supervise|pki|web|grants|broker|harness|jira")
		os.Exit(2)
	}
	cmds[os.Args[1]]()
}
