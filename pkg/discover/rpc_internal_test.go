package discover

import (
	"bufio"
	"strings"
	"testing"
)

// TestReadRPCResultErrorObject drives readRPCResult over a JSON-RPC response
// that carries an error object for the awaited id: the branch must surface the
// server's error rather than returning a result.
func TestReadRPCResultErrorObject(t *testing.T) {
	line := `{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"method not found"}}` + "\n"
	scanner := bufio.NewScanner(strings.NewReader(line))
	_, err := readRPCResult(scanner, toolsListRequestID)
	if err == nil {
		t.Fatal("readRPCResult returned no error for a JSON-RPC error response")
	}
	if !strings.Contains(err.Error(), "method not found") {
		t.Errorf("err = %v, want the server's error message folded in", err)
	}
}

// TestReadRPCResultMalformedLine drives readRPCResult over a line that is not
// JSON at all: the parse branch must fail rather than silently skip it.
func TestReadRPCResultMalformedLine(t *testing.T) {
	line := "this is not json\n"
	scanner := bufio.NewScanner(strings.NewReader(line))
	_, err := readRPCResult(scanner, initializeRequestID)
	if err == nil {
		t.Fatal("readRPCResult returned no error for a malformed line")
	}
	if !strings.Contains(err.Error(), "parsing JSON-RPC message") {
		t.Errorf("err = %v, want a JSON parse failure", err)
	}
}
