package discover

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// mcpProtocolVersion is the MCP protocol version this client negotiates
// (verified against the modelcontextprotocol.io 2025-06-18 specification's
// lifecycle and transports pages via context7 before implementation; see the
// Task 2.3 report for what was checked).
const mcpProtocolVersion = "2025-06-18"

// clientName and clientVersion identify smithmark itself in the initialize
// handshake's clientInfo block.
const (
	clientName    = "smithmark"
	clientVersion = "0.1.0"
)

// stderrCaptureLimit bounds how many bytes of a subprocess's stderr this
// package retains for error messages, so a runaway or adversarial process
// cannot inflate an error message without bound.
const stderrCaptureLimit = 4096

// initializeRequestID and toolsListRequestID are the fixed JSON-RPC request
// ids ExtractTools uses for the two requests it sends; a single extraction
// never needs more than two in flight, so there is no need to generate them.
const (
	initializeRequestID = 1
	toolsListRequestID  = 2
)

// rpcRequest is a JSON-RPC 2.0 request: it always carries a non nil id,
// unlike rpcNotification.
type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// rpcNotification is a JSON-RPC 2.0 notification: it must never carry an id
// field at all, which is why it is a distinct type from rpcRequest rather
// than the same struct with a zero id.
type rpcNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
}

// rpcIncoming is the subset of an incoming JSON-RPC 2.0 message this client
// reads: a response's result or error, keyed by id. A server initiated
// notification decodes with a nil ID and is ignored by readRPCResult.
type rpcIncoming struct {
	ID     *int            `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// rpcError is a JSON-RPC 2.0 error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// initializeParams is the initialize request's params object (MCP lifecycle,
// spec 2025-06-18): protocol version, capabilities (empty; this client
// declares none), and client identity.
type initializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      clientInfo     `json:"clientInfo"`
}

type clientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// wireTool is the shape of one entry in a tools/list result's tools array,
// and also the shape --tools-from strictly decodes (U2): name, optional
// description, and a JSON Schema object for inputSchema.
type wireTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// toolsListResult is a tools/list response's result object.
type toolsListResult struct {
	Tools []wireTool `json:"tools"`
}

// ExtractTools launches command as a subprocess and speaks the MCP stdio
// transport (newline delimited JSON-RPC 2.0, verified against the
// modelcontextprotocol.io 2025-06-18 specification) to discover its tool
// listing: it sends an initialize request (protocolVersion 2025-06-18,
// empty capabilities, clientInfo naming smithmark), reads the response,
// sends the notifications/initialized notification, sends a tools/list
// request, reads that response, and then always terminates the whole process
// tree, not just the immediate process: command commonly names a wrapper
// (npx, uvx, go run) that forks the real server as its own child, and
// killing only the wrapper would leave that real server running, orphaned.
// While waiting for a given request's response it ignores any notification
// the server raises on its own, or any response to a different id, reading
// line by line since stdio messages are newline delimited and must not
// contain embedded newlines. Each returned tool's InputSchemaDigest is computed by
// the pure manifest.SchemaDigest helper, so canonicalization is never
// duplicated between this package and pkg/core/manifest. The returned
// transports slice is always exactly ["stdio"], since that is the only
// transport this function speaks.
//
// On a context cancellation or deadline, or any protocol error (a
// malformed message, a JSON-RPC error response, an id mismatch that never
// resolves, or the process exiting early), the process tree is killed and
// ExtractTools returns a *codes.Error carrying codes.ToolExtractionFailed,
// with as much of the process's stderr as stderrCaptureLimit retained,
// folded into the detail message.
//
// Callers must pass a context with a deadline. With context.Background(),
// a server that streams endless notifications without ever answering a
// request would keep ExtractTools reading until the scanner's buffer limit
// errors on an oversized line, or indefinitely if every line stays small;
// the deadline is what bounds a merely unhelpful server, not just a hung
// one.
//
// Security posture (decision U2): ExtractTools executes the command it is
// given. smithmark attest may call this, because a maker attesting their own
// artifact is running their own code by design. smithmark verify and
// smithmark lint must never call this function: verifying or linting an
// artifact must never require executing it.
func ExtractTools(ctx context.Context, command []string) ([]manifest.ToolDecl, []string, error) {
	if len(command) == 0 {
		return nil, nil, codes.E(codes.ToolExtractionFailed, "extract tools: command must not be empty")
	}

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	prepareProcessGroup(cmd)
	// Override CommandContext's default cancellation (plain Process.Kill,
	// which only reaches the immediate process) so a context deadline also
	// tears down a grandchild the command forked, exactly like the explicit
	// termination below does.
	cmd.Cancel = func() error { return killProcessTree(cmd) }
	// WaitDelay bounds the final cmd.Wait below: a descendant that escaped
	// the process group (a double fork, or a setsid call of its own) can
	// survive killProcessTree while holding the inherited stderr write end,
	// and Wait would otherwise block forever on that never closing pipe.
	// After this delay Wait force closes the pipes and returns.
	cmd.WaitDelay = 3 * time.Second

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, codes.E(codes.ToolExtractionFailed, "extract tools: creating stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		// StdinPipe already handed back the write end. If we bail here, before
		// Start, nothing else will ever close it (cmd.Wait, which normally
		// closes StdinPipe's ends, never runs on an unstarted command), so
		// close it explicitly to avoid leaking the underlying os.Pipe fd.
		_ = stdin.Close()
		return nil, nil, codes.E(codes.ToolExtractionFailed, "extract tools: creating stdout pipe: %v", err)
	}
	stderr := &boundedWriter{limit: stderrCaptureLimit}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, nil, codes.E(codes.ToolExtractionFailed, "extract tools: starting %q: %v", command[0], err)
	}

	tools, speakErr := speakMCP(stdin, stdout)

	// Always terminate the whole process tree once the exchange is over, win
	// or lose (U2 posture: attest owns the subprocess for exactly this long
	// and no longer). Kill before Wait so a subprocess blocked writing more
	// than the pipe buffer holds cannot make Wait itself hang.
	_ = stdin.Close()
	_ = killProcessTree(cmd)
	_ = cmd.Wait() // reaps the direct child and its I/O copying goroutines, including stderr's.

	if speakErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, codes.E(codes.ToolExtractionFailed,
				"extract tools: %v: %v (stderr: %s)", ctxErr, speakErr, stderr.String())
		}
		return nil, nil, codes.E(codes.ToolExtractionFailed,
			"extract tools: %v (stderr: %s)", speakErr, stderr.String())
	}

	return tools, []string{"stdio"}, nil
}

// speakMCP runs the initialize / notifications-initialized / tools-list
// exchange described on ExtractTools over stdin and stdout, and maps the
// result into manifest.ToolDecl values.
func speakMCP(stdin io.Writer, stdout io.Reader) ([]manifest.ToolDecl, error) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	if err := writeRPCMessage(stdin, rpcRequest{
		JSONRPC: "2.0",
		ID:      initializeRequestID,
		Method:  "initialize",
		Params: initializeParams{
			ProtocolVersion: mcpProtocolVersion,
			Capabilities:    map[string]any{},
			ClientInfo:      clientInfo{Name: clientName, Version: clientVersion},
		},
	}); err != nil {
		return nil, fmt.Errorf("sending initialize: %w", err)
	}
	if _, err := readRPCResult(scanner, initializeRequestID); err != nil {
		return nil, fmt.Errorf("reading initialize response: %w", err)
	}

	if err := writeRPCMessage(stdin, rpcNotification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}); err != nil {
		return nil, fmt.Errorf("sending notifications/initialized: %w", err)
	}

	if err := writeRPCMessage(stdin, rpcRequest{
		JSONRPC: "2.0",
		ID:      toolsListRequestID,
		Method:  "tools/list",
	}); err != nil {
		return nil, fmt.Errorf("sending tools/list: %w", err)
	}
	result, err := readRPCResult(scanner, toolsListRequestID)
	if err != nil {
		return nil, fmt.Errorf("reading tools/list response: %w", err)
	}

	var listResult toolsListResult
	if err := json.Unmarshal(result, &listResult); err != nil {
		return nil, fmt.Errorf("decoding tools/list result: %w", err)
	}

	return mapWireTools(listResult.Tools)
}

// mapWireTools converts wire tool entries into manifest.ToolDecl values,
// digesting each inputSchema with manifest.SchemaDigest. It is shared
// verbatim between ExtractTools and ToolsFromFile, since --tools-from must
// map identically to a live extraction (U2).
//
// An empty listing maps to a non nil empty slice and is accepted here by
// design: downstream manifest validation owns whether a tool less MCP
// surface is acceptable, not this adapter. A tool with an absent inputSchema
// fails the whole extraction deliberately, via SchemaDigest rejecting the
// empty schema: MCP requires inputSchema on every tool, so a server that
// omits it is committing a protocol violation this package surfaces loudly
// rather than papering over with a placeholder digest.
func mapWireTools(wire []wireTool) ([]manifest.ToolDecl, error) {
	tools := make([]manifest.ToolDecl, 0, len(wire))
	for _, t := range wire {
		digest, err := manifest.SchemaDigest(t.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("digesting inputSchema for tool %q: %w", t.Name, err)
		}
		tools = append(tools, manifest.ToolDecl{
			Name:              t.Name,
			Description:       t.Description,
			InputSchemaDigest: digest,
		})
	}
	return tools, nil
}

// writeRPCMessage marshals v as one line of JSON followed by a newline, per
// the stdio transport's newline delimited framing.
func writeRPCMessage(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

// readRPCResult reads newline delimited JSON-RPC messages from scanner until
// it finds a response whose id equals wantID, ignoring any notification the
// server raises on its own (no id) or response to a different id along the
// way. It
// returns an error if the matching response carries a JSON-RPC error object,
// if a line fails to parse, or if the stream ends before a match is found
// (which is what happens once the subprocess is killed after a context
// timeout: the pipe closes and Scan stops).
func readRPCResult(scanner *bufio.Scanner, wantID int) (json.RawMessage, error) {
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg rpcIncoming
		if err := json.Unmarshal(line, &msg); err != nil {
			return nil, fmt.Errorf("parsing JSON-RPC message: %w", err)
		}
		if msg.ID == nil || *msg.ID != wantID {
			continue
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("server returned JSON-RPC error %d: %s", msg.Error.Code, msg.Error.Message)
		}
		return msg.Result, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return nil, io.ErrUnexpectedEOF
}

// boundedWriter caps how many bytes it retains, silently discarding the
// rest, so capturing a subprocess's stderr for an error message cannot let
// that subprocess inflate memory without bound. It still reports every byte
// as written, matching io.Discard's convention of accepting and dropping
// data past its limit rather than erroring the writer (a stderr writer must
// never itself fail the subprocess's write calls).
type boundedWriter struct {
	buf   bytes.Buffer
	limit int
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *boundedWriter) String() string {
	return b.buf.String()
}

// toolsFromFileDoc is the strict shape of a --tools-from file (U2 escape
// hatch for CI that cannot launch the server): a tools array whose entries
// are shaped exactly like a live tools/list result's Tool objects.
type toolsFromFileDoc struct {
	Tools []wireTool `json:"tools"`
}

// ToolsFromFile reads and strictly parses a --tools-from file: unknown
// fields are rejected at every nesting level. Each tool's inputSchema is
// mapped through manifest.SchemaDigest identically to ExtractTools (via the
// shared mapWireTools helper), so a maker's static tool listing and a live
// extraction produce the same manifest.ToolDecl shape. A missing file
// surfaces as a wrapped os.ErrNotExist.
func ToolsFromFile(path string) ([]manifest.ToolDecl, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tools from file %s: %w", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc toolsFromFileDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("tools from file %s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("tools from file %s: trailing data after JSON document", path)
	}

	tools, err := mapWireTools(doc.Tools)
	if err != nil {
		return nil, fmt.Errorf("tools from file %s: %w", path, err)
	}
	return tools, nil
}
