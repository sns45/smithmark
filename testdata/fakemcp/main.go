// Command fakemcp is a minimal MCP server test fixture for Task 2.3
// (pkg/discover.ExtractTools): it speaks just enough of the stdio transport
// described in docs/decisions.md's U2 to exercise the extractor end to end.
// It understands exactly three methods: initialize, notifications/initialized,
// and tools/list, and always reports the same two tools with fixed input
// schemas, so the digests ExtractTools computes over their canonical form are
// stable across every run and every OS. It is invoked with an explicit
// directory path (go run ./testdata/fakemcp), which works even though the
// directory lives under testdata and is therefore skipped by ./... patterns.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// helloWorldSchema and addNumbersSchema are fixed strings by design: the
// whole point of this fixture is that its schemas never change, so a test
// can pin the sha256 digest ExtractTools computes over their canonical form.
// addNumbersSchema is shared verbatim with pkg/core/manifest's own
// SchemaDigest pinned vector test, proving the same algorithm both ways.
const (
	helloWorldSchema = `{"type":"object","properties":{"name":{"type":"string"},"loud":{"type":"boolean"}},"required":["name"]}`
	addNumbersSchema = `{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}`
)

// incomingMessage is the subset of a JSON-RPC 2.0 request or notification
// this fixture needs to read off stdin: the method name, and the id when
// present (a notification has none).
type incomingMessage struct {
	ID     *int   `json:"id"`
	Method string `json:"method"`
}

func writeLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

func main() {
	hang := flag.Bool("hang", false,
		"read tools/list but never answer it, to exercise a client's context timeout")
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var msg incomingMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			fmt.Fprintf(os.Stderr, "fakemcp: parsing request: %v\n", err)
			continue
		}

		switch msg.Method {
		case "initialize":
			resp := map[string]any{
				"jsonrpc": "2.0",
				"id":      msg.ID,
				"result": map[string]any{
					"protocolVersion": "2025-06-18",
					"capabilities":    map[string]any{},
					"serverInfo":      map[string]any{"name": "fakemcp", "version": "0.1.0"},
				},
			}
			if err := writeLine(os.Stdout, resp); err != nil {
				return
			}
		case "notifications/initialized":
			// Notification: no response.
		case "tools/list":
			if *hang {
				// Deliberately never respond. The parent kills this process
				// once its context deadline passes; sleep rather than exit
				// so the test genuinely exercises that timeout path. A bare
				// "select {}" here would instead trip Go's runtime deadlock
				// detector (this is the only goroutine) and exit almost
				// immediately with "all goroutines are asleep - deadlock!",
				// which would make the timeout test pass for the wrong
				// reason; a long sleep is a real, non-deadlocking block.
				time.Sleep(time.Hour)
			}
			resp := map[string]any{
				"jsonrpc": "2.0",
				"id":      msg.ID,
				"result": map[string]any{
					"tools": []any{
						map[string]any{
							"name":        "hello_world",
							"description": "Say hello to someone by name.",
							"inputSchema": json.RawMessage(helloWorldSchema),
						},
						map[string]any{
							"name":        "add_numbers",
							"description": "Add two numbers together.",
							"inputSchema": json.RawMessage(addNumbersSchema),
						},
					},
				},
			}
			if err := writeLine(os.Stdout, resp); err != nil {
				return
			}
		default:
			fmt.Fprintf(os.Stderr, "fakemcp: unknown method %q\n", msg.Method)
		}
	}
}
