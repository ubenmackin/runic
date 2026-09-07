package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"runic/internal/agent/identity"
	"runic/internal/common/log"
	"runic/internal/common/version"
)

func TestArchDownloadFilenameMatrix(t *testing.T) {
	tests := []struct {
		arch     string
		wantFile string
		wantErr  bool
	}{
		{arch: "amd64", wantFile: "runic-agent-amd64"},
		{arch: "arm64", wantFile: "runic-agent-arm64"},
		{arch: "arm", wantFile: "runic-agent-arm"},
		{arch: "386", wantErr: true},
		{arch: "mips", wantErr: true},
		{arch: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			got, err := archDownloadFilename(tt.arch)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("archDownloadFilename(%q) expected error, got %q", tt.arch, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("archDownloadFilename(%q) error = %v", tt.arch, err)
			}
			if got != tt.wantFile {
				t.Errorf("archDownloadFilename(%q) = %q, want %q", tt.arch, got, tt.wantFile)
			}
		})
	}
}

func TestIsRetryableUpdateStatus(t *testing.T) {
	retryable := []int{http.StatusTooManyRequests, 500, 502, 503, 504, 599}
	for _, code := range retryable {
		if !isRetryableUpdateStatus(code) {
			t.Errorf("isRetryableUpdateStatus(%d) = false, want true", code)
		}
	}
	nonRetryable := []int{200, 400, 401, 403, 404, 409, 422}
	for _, code := range nonRetryable {
		if isRetryableUpdateStatus(code) {
			t.Errorf("isRetryableUpdateStatus(%d) = true, want false", code)
		}
	}
}

func TestParseUpdateRetryAfter(t *testing.T) {
	if got := parseUpdateRetryAfter(""); got != 0 {
		t.Errorf("empty header = %v, want 0", got)
	}
	if got := parseUpdateRetryAfter("2"); got != 2*time.Second {
		t.Errorf("delta-seconds = %v, want 2s", got)
	}
	if got := parseUpdateRetryAfter("0"); got != 0 {
		t.Errorf("zero = %v, want 0", got)
	}
	if got := parseUpdateRetryAfter("not-a-date"); got != 0 {
		t.Errorf("invalid = %v, want 0", got)
	}
	future := time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseUpdateRetryAfter(future); got <= 0 || got > 6*time.Second {
		t.Errorf("http-date future = %v, want ~5s", got)
	}
}

func TestDownloadBinary429RetryThenSuccess(t *testing.T) {
	origDelays := updateRetryDelays
	t.Cleanup(func() { updateRetryDelays = origDelays })
	updateRetryDelays = []time.Duration{10 * time.Millisecond}

	var calls atomic.Int32
	fakeBinary := []byte("fake-binary-429")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "runic-agent/") {
			t.Errorf("User-Agent = %q, want runic-agent/ prefix", r.Header.Get("User-Agent"))
		}
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fakeBinary)
	}))
	defer server.Close()

	body, err := downloadBinary(context.Background(), server.Client(), server.URL, "amd64")
	if err != nil {
		t.Fatalf("downloadBinary() error = %v", err)
	}
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(data) != string(fakeBinary) {
		t.Errorf("body = %q, want %q", string(data), string(fakeBinary))
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("requests = %d, want 2 (initial + 1 retry)", got)
	}
}

func TestDownloadBinary5xxRetryThenSuccess(t *testing.T) {
	origDelays := updateRetryDelays
	t.Cleanup(func() { updateRetryDelays = origDelays })
	updateRetryDelays = []time.Duration{10 * time.Millisecond}

	var calls atomic.Int32
	fakeBinary := []byte("fake-binary-5xx")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fakeBinary)
	}))
	defer server.Close()

	body, err := downloadBinary(context.Background(), server.Client(), server.URL, "amd64")
	if err != nil {
		t.Fatalf("downloadBinary() error = %v", err)
	}
	defer func() { _ = body.Close() }()
	data, _ := io.ReadAll(body)
	if string(data) != string(fakeBinary) {
		t.Errorf("body = %q, want %q", string(data), string(fakeBinary))
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("requests = %d, want 2", got)
	}
}

func TestDownloadBinaryRetryAfterHonoredOverBackoff(t *testing.T) {
	origDelays := updateRetryDelays
	t.Cleanup(func() { updateRetryDelays = origDelays })
	updateRetryDelays = []time.Duration{10 * time.Second}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	start := time.Now()
	body, err := downloadBinary(context.Background(), server.Client(), server.URL, "amd64")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("downloadBinary() error = %v", err)
	}
	_ = body.Close()
	if elapsed > 5*time.Second {
		t.Errorf("retry took %v, want fast retry honoring Retry-After: 0 over 10s backoff", elapsed)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("requests = %d, want 2", got)
	}
}

func TestDownloadBinaryNoRetryOn404(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := downloadBinary(context.Background(), server.Client(), server.URL, "amd64")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("requests = %d, want 1 (no retry on 404)", got)
	}
}

func TestDownloadBinaryUnsupportedArch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be hit for unsupported arch")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := downloadBinary(context.Background(), server.Client(), server.URL, "mips")
	if err == nil {
		t.Fatal("expected error for unsupported arch, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported architecture") {
		t.Errorf("error = %v, want unsupported architecture", err)
	}
}

func TestDownloadBinaryUserAgentVersion(t *testing.T) {
	var gotUA atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA.Store(r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	body, err := downloadBinary(context.Background(), server.Client(), server.URL, "amd64")
	if err != nil {
		t.Fatalf("downloadBinary() error = %v", err)
	}
	_ = body.Close()
	want := "runic-agent/" + version.AgentVersion
	if got, _ := gotUA.Load().(string); got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
}

func TestHandleUpdateAgentCancelledParentStillDownloads(t *testing.T) {
	fakeBinary := []byte("#!/bin/sh\n# fake agent binary\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "downloads") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(fakeBinary)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "runic-agent")
	if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatalf("failed to create target binary: %v", err)
	}
	origPath := UpdateBinaryPath
	t.Cleanup(func() { UpdateBinaryPath = origPath })
	UpdateBinaryPath = binaryPath

	origDelays := updateRetryDelays
	t.Cleanup(func() { updateRetryDelays = origDelays })
	updateRetryDelays = []time.Duration{10 * time.Millisecond}

	exitCh := make(chan int, 1)
	agent := &Agent{
		httpClient: server.Client(),
		exitFunc: func(code int) {
			select {
			case exitCh <- code:
			default:
			}
		},
	}

	sseCtx, cancel := context.WithCancel(context.Background())
	cancel()

	agent.handleUpdateAgent(sseCtx, server.URL)

	select {
	case code := <-exitCh:
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected exitFunc to be called even though parent SSE context was canceled")
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read updated binary: %v", err)
	}
	if string(data) != string(fakeBinary) {
		t.Errorf("binary = %q, want %q", string(data), string(fakeBinary))
	}
}

func TestHandleUpdateAgentHostMismatchReports(t *testing.T) {
	logBuf := newSyncWriter()
	log.Init("error", logBuf)
	defer log.Init("info", os.Stdout)

	exitCh := make(chan int, 1)
	agent := &Agent{
		config:     &identity.Config{ControlPlaneURL: "https://control.example.com:60443"},
		httpClient: http.DefaultClient,
		exitFunc: func(code int) {
			select {
			case exitCh <- code:
			default:
			}
		},
	}

	agent.handleUpdateAgent(context.Background(), "https://other.example.com:60443")

	select {
	case <-exitCh:
		t.Error("expected exitFunc NOT to be called on host mismatch")
	default:
	}
	if got := agent.getLastUpdateError(); got == "" {
		t.Error("expected last update error to be recorded, got empty")
	} else if !strings.Contains(got, "does not match") {
		t.Errorf("last update error = %q, want host mismatch detail", got)
	}
	if out := logBuf.String(); !strings.Contains(out, "Invalid control plane URL") {
		t.Errorf("log = %q, want invalid URL reason", out)
	}
}

func TestHandleUpdateAgentPortMismatchReports(t *testing.T) {
	logBuf := newSyncWriter()
	log.Init("error", logBuf)
	defer log.Init("info", os.Stdout)

	exitCh := make(chan int, 1)
	agent := &Agent{
		config:     &identity.Config{ControlPlaneURL: "https://control.example.com:60443"},
		httpClient: http.DefaultClient,
		exitFunc: func(code int) {
			select {
			case exitCh <- code:
			default:
			}
		},
	}

	agent.handleUpdateAgent(context.Background(), "https://control.example.com:64443")

	select {
	case <-exitCh:
		t.Error("expected exitFunc NOT to be called on port mismatch")
	default:
	}
	if got := agent.getLastUpdateError(); got == "" {
		t.Error("expected last update error to be recorded, got empty")
	} else if !strings.Contains(got, "port") {
		t.Errorf("last update error = %q, want port mismatch detail", got)
	}
	if out := logBuf.String(); !strings.Contains(out, "Invalid control plane URL") {
		t.Errorf("log = %q, want invalid URL reason", out)
	}
}

func TestLastUpdateErrorTruncation(t *testing.T) {
	agent := &Agent{}
	long := strings.Repeat("x", maxLastUpdateErrLen+100)
	agent.setLastUpdateError(long)
	if got := agent.getLastUpdateError(); len(got) != maxLastUpdateErrLen {
		t.Errorf("stored len = %d, want %d", len(got), maxLastUpdateErrLen)
	}
	agent.setLastUpdateError("")
	if got := agent.getLastUpdateError(); got != "" {
		t.Errorf("after clear = %q, want empty", got)
	}
}

func TestHandleUpdateAgentConcurrentSkipsDuplicate(t *testing.T) {
	fakeBinary := []byte("#!/bin/sh\n# fake agent binary\n")
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "downloads") {
			downloads.Add(1)
			// Hold the download open briefly so concurrent triggers
			// overlap while the first update is in flight.
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(fakeBinary)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "runic-agent")
	if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatalf("failed to create target binary: %v", err)
	}
	origPath := UpdateBinaryPath
	t.Cleanup(func() { UpdateBinaryPath = origPath })
	UpdateBinaryPath = binaryPath

	var exits atomic.Int32
	agent := &Agent{
		httpClient: server.Client(),
		exitFunc: func(code int) {
			exits.Add(1)
		},
	}

	const triggers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < triggers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			agent.handleUpdateAgent(context.Background(), server.URL)
		}()
	}
	close(start)
	wg.Wait()

	if got := exits.Load(); got != 1 {
		t.Errorf("exitFunc calls = %d, want 1 (concurrent update_agent events must not double-exit)", got)
	}
	if got := downloads.Load(); got != 1 {
		t.Errorf("binary downloads = %d, want 1 (concurrent update_agent events must run a single performUpdate)", got)
	}
	if got := agent.getLastUpdateError(); got != "" {
		t.Errorf("last update error = %q, want empty after successful single update", got)
	}
}

func TestHandleUpdateAgentSyncConcurrentSkipsDuplicate(t *testing.T) {
	fakeBinary := []byte("#!/bin/sh\n# fake agent binary\n")
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "downloads") {
			downloads.Add(1)
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(fakeBinary)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "runic-agent")
	if err := os.WriteFile(binaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatalf("failed to create target binary: %v", err)
	}
	origPath := UpdateBinaryPath
	t.Cleanup(func() { UpdateBinaryPath = origPath })
	UpdateBinaryPath = binaryPath

	var exits atomic.Int32
	agent := &Agent{
		httpClient: server.Client(),
		exitFunc: func(code int) {
			exits.Add(1)
		},
	}

	const triggers = 4
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, triggers)
	for i := 0; i < triggers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			errs[idx] = agent.handleUpdateAgentSync(context.Background(), server.URL)
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	alreadyRunning := 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else if strings.Contains(err.Error(), "already in progress") {
			alreadyRunning++
		} else {
			t.Errorf("unexpected sync update error: %v", err)
		}
	}
	if successes != 1 {
		t.Errorf("successful sync updates = %d, want 1", successes)
	}
	if alreadyRunning != triggers-1 {
		t.Errorf("already-in-progress rejections = %d, want %d", alreadyRunning, triggers-1)
	}
	if got := exits.Load(); got != 1 {
		t.Errorf("exitFunc calls = %d, want 1", got)
	}
}
