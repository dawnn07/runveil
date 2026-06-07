// Integration tests for the runveil CLI. Builds the binary once into
// a temp directory at TestMain, then execs it with controlled args
// and an isolated --data-dir per test. Captures stdin/stdout/stderr.
package integration

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runveilBin holds the absolute path to the built runveil binary.
// Set by TestMain via go build; reused across tests.
var runveilBin string

func TestMain(m *testing.M) {
	// Integration tests run `runveil init` many times; skip the OS
	// trust-store install so they never touch (or hang on) the host's
	// trust store. Real trust install is covered by the trust package's
	// own integration test. Child processes inherit this env.
	os.Setenv("RUNVEIL_SKIP_TRUST", "1")

	tmpDir, err := os.MkdirTemp("", "runveil-bin-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: MkdirTemp: %v\n", err)
		os.Exit(2)
	}
	defer os.RemoveAll(tmpDir)

	binName := "runveil"
	if runtime.GOOS == "windows" {
		binName += ".exe" // Windows requires the .exe extension to exec
	}
	binPath := filepath.Join(tmpDir, binName)

	repoRoot := findRepoRootForCLITests()
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/runveil")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: go build: %v\n%s", err, string(out))
		os.Exit(2)
	}
	runveilBin = binPath
	os.Exit(m.Run())
}

func findRepoRootForCLITests() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	dir := wd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

// runCLI execs the runveil binary with the given args and returns
// stdout, stderr, and the exit code. exitCode is -1 if the process
// could not be started.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(runveilBin, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if err == nil {
		return stdout, stderr, 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return stdout, stderr, ee.ExitCode()
	}
	return stdout, stderr, -1
}

func TestCLI_Version(t *testing.T) {
	for _, alias := range []string{"version", "--version", "-v"} {
		t.Run(alias, func(t *testing.T) {
			stdout, stderr, code := runCLI(t, alias)
			if code != 0 {
				t.Errorf("exit code = %d, want 0; stderr=%q", code, stderr)
			}
			want := "runveil 0.1.0\n"
			if stdout != want {
				t.Errorf("stdout = %q, want %q", stdout, want)
			}
			if stderr != "" {
				t.Errorf("stderr should be empty, got %q", stderr)
			}
		})
	}
}

func TestCLI_TestPolicy_MissingArg(t *testing.T) {
	_, stderr, code := runCLI(t, "test-policy")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "test-policy") {
		t.Errorf("stderr should mention test-policy; got %q", stderr)
	}
}

func TestCLI_TestPolicy_MissingFile(t *testing.T) {
	_, stderr, code := runCLI(t, "test-policy", "/nonexistent/path/to/x.yaml")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "/nonexistent/path/to/x.yaml") {
		t.Errorf("stderr should mention the path; got %q", stderr)
	}
}

func TestCLI_TestPolicy_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
rules:
  - name: r
    match: {all: true}
    action: warn
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	stdout, stderr, code := runCLI(t, "test-policy", path)
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, path) || !strings.Contains(stdout, "ok") || !strings.Contains(stdout, "1 rules") {
		t.Errorf("stdout = %q, want path + ok + 1 rules", stdout)
	}
}

func TestCLI_TestPolicy_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
rules:
  - name: bad
    match: {path: "**/foo/**", pattern: aws_*}
    action: block
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	_, stderr, code := runCLI(t, "test-policy", path)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "path") {
		t.Errorf("stderr should mention 'path' from the loader error; got %q", stderr)
	}
}

func TestCLI_Init_FreshDataDir(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr, code := runCLI(t, "init", "--data-dir", dir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca", "ca.crt")); err != nil {
		t.Errorf("CA cert not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "policy.yaml")); err != nil {
		t.Errorf("policy.yaml not created: %v", err)
	}
	if !strings.Contains(stdout, "runveil proxy") {
		t.Errorf("stdout should include next-steps hint; got %q", stdout)
	}
}

func TestCLI_Init_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := runCLI(t, "init", "--data-dir", dir); code != 0 {
		t.Fatalf("first init failed")
	}
	first, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		t.Fatalf("read policy after first init: %v", err)
	}
	stdout, stderr, code := runCLI(t, "init", "--data-dir", dir)
	if code != 0 {
		t.Fatalf("second init: exit %d; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "already") {
		t.Errorf("stdout should mention CA already present; got %q", stdout)
	}
	second, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		t.Fatalf("read policy after second init: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("policy file changed between idempotent inits")
	}
}

func TestCLI_Init_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	custom := "version: 1\nrules:\n  - name: custom\n    match: {all: true}\n    action: block\n"
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(custom), 0o600); err != nil {
		t.Fatalf("write custom policy: %v", err)
	}
	stdout, _, code := runCLI(t, "init", "--data-dir", dir)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "skipping") {
		t.Errorf("stdout should mention skipping the existing policy; got %q", stdout)
	}
	got, _ := os.ReadFile(policyPath)
	if string(got) != custom {
		t.Errorf("existing policy was overwritten:\nwant: %s\ngot:  %s", custom, string(got))
	}
}

func TestCLI_Init_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	custom := "version: 1\nrules:\n  - name: custom\n    match: {all: true}\n    action: block\n"
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(custom), 0o600); err != nil {
		t.Fatalf("write custom policy: %v", err)
	}
	_, stderr, code := runCLI(t, "init", "--data-dir", dir, "--force")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	got, _ := os.ReadFile(policyPath)
	if string(got) == custom {
		t.Errorf("policy was NOT overwritten despite --force")
	}
	if !strings.Contains(string(got), "default-warn") {
		t.Errorf("policy should be the starter template; got %s", string(got))
	}
}

func TestCLI_Init_StarterPolicyParses(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := runCLI(t, "init", "--data-dir", dir); code != 0 {
		t.Fatalf("init failed")
	}
	stdout, stderr, code := runCLI(t, "test-policy", filepath.Join(dir, "policy.yaml"))
	if code != 0 {
		t.Fatalf("test-policy on starter: exit %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "ok") || !strings.Contains(stdout, "1 rules") {
		t.Errorf("stdout = %q, want 'ok (1 rules)'", stdout)
	}
}

func TestCLI_Status_NoDataDir(t *testing.T) {
	dir := t.TempDir()
	stdout, _, code := runCLI(t, "status", "--data-dir", dir)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "exists:      no") {
		t.Errorf("stdout should report CA not present; got %q", stdout)
	}
}

func TestCLI_Status_AfterInit(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := runCLI(t, "init", "--data-dir", dir); code != 0 {
		t.Fatalf("init failed")
	}
	stdout, _, code := runCLI(t, "status", "--data-dir", dir)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	for _, want := range []string{"CA:", "exists:      yes", "Policy:", "parses:      yes", "Proxy:", "running:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q; got:\n%s", want, stdout)
		}
	}
}

func TestCLI_Status_PolicyParseError(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := runCLI(t, "init", "--data-dir", dir); code != 0 {
		t.Fatalf("init failed")
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("not: valid: yaml: :"), 0o600); err != nil {
		t.Fatalf("write broken policy: %v", err)
	}
	stdout, _, code := runCLI(t, "status", "--data-dir", dir)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (status is informational)", code)
	}
	if !strings.Contains(stdout, "parses:      no") {
		t.Errorf("stdout should report parses: no; got %q", stdout)
	}
}

func TestCLI_Status_ProxyRunningDetected(t *testing.T) {
	ln, err := listenOnRandomPort()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	stdout, _, code := runCLI(t, "status", "--data-dir", dir, "--port", fmt.Sprintf("%d", port))
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "running:     yes") {
		t.Errorf("stdout should report running: yes; got %q", stdout)
	}
}

func TestCLI_Status_ProxyNotRunning(t *testing.T) {
	dir := t.TempDir()
	ln, err := listenOnRandomPort()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	stdout, _, code := runCLI(t, "status", "--data-dir", dir, "--port", fmt.Sprintf("%d", port))
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "running:     no") {
		t.Errorf("stdout should report running: no; got %q", stdout)
	}
}

func listenOnRandomPort() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func TestCLI_UnknownSubcommand(t *testing.T) {
	_, stderr, code := runCLI(t, "this-is-not-a-real-command")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown subcommand") {
		t.Errorf("stderr should mention 'unknown subcommand'; got %q", stderr)
	}
	if !strings.Contains(stderr, "this-is-not-a-real-command") {
		t.Errorf("stderr should echo the bad subcommand; got %q", stderr)
	}
}

func TestCLI_NoArgs(t *testing.T) {
	_, stderr, code := runCLI(t /* no args */)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr should contain usage; got %q", stderr)
	}
}

func TestCLI_Help(t *testing.T) {
	for _, alias := range []string{"help", "--help", "-h"} {
		t.Run(alias, func(t *testing.T) {
			_, stderr, code := runCLI(t, alias)
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
			if !strings.Contains(stderr, "Commands:") {
				t.Errorf("stderr should contain 'Commands:'; got %q", stderr)
			}
		})
	}
}

func TestCLI_Logs_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	_, stderr, code := runCLI(t, "logs", "--data-dir", dir)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "file not found") {
		t.Errorf("stderr should say 'file not found'; got %q", stderr)
	}
}

func TestCLI_Logs_LastN(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")

	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, fmt.Sprintf(`{"time":"2026-05-17T16:33:%02dZ","request_id":"r%d","host":"h","method":"GET","path":"/","status":200,"bytes_in":0,"bytes_out":0,"duration_ms":1,"decision":"continue"}`, i, i))
	}
	if err := os.WriteFile(auditPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	stdout, _, code := runCLI(t, "logs", "--data-dir", dir, "-n", "5")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	count := strings.Count(stdout, "\n")
	if count != 5 {
		t.Errorf("got %d output lines, want 5", count)
	}
}

func TestCLI_Logs_JSON(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	line := `{"time":"2026-05-17T16:33:12Z","request_id":"r","host":"h","method":"GET","path":"/","status":200,"bytes_in":0,"bytes_out":0,"duration_ms":1,"decision":"continue"}`
	if err := os.WriteFile(auditPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	stdout, _, code := runCLI(t, "logs", "--data-dir", dir, "--json", "-n", "5")
	if code != 0 {
		t.Errorf("exit code = %d", code)
	}
	if !strings.Contains(stdout, `"request_id":"r"`) {
		t.Errorf("stdout should contain raw JSON; got %q", stdout)
	}
}

func TestCLI_UpstreamOverride_RejectsMalformed(t *testing.T) {
	tmp := t.TempDir()
	// Bad value: not host:port (no port at all).
	_, stderr, code := runCLI(t,
		"proxy",
		"--port=0",
		"--data-dir="+tmp,
		"--upstream-override=nohost",
	)
	if code == 0 {
		t.Fatalf("runveil: expected non-zero exit; got 0; stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "invalid --upstream-override") {
		t.Errorf("stderr missing 'invalid --upstream-override': %q", stderr)
	}
}

func TestCLI_UpstreamCA_RejectsEmptyPEM(t *testing.T) {
	tmp := t.TempDir()
	// Write an empty file (no PEM certs).
	emptyPEM := filepath.Join(tmp, "empty.pem")
	if err := os.WriteFile(emptyPEM, []byte(""), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Pass both flags: --upstream-override validates first (clean host:port),
	// then --upstream-ca validation fires the "no valid PEM" error we assert.
	_, stderr, code := runCLI(t,
		"proxy",
		"--port=0",
		"--data-dir="+tmp,
		"--upstream-override=127.0.0.1:1234",
		"--upstream-ca="+emptyPEM,
	)
	if code == 0 {
		t.Fatalf("runveil: expected non-zero exit; got 0; stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "no valid PEM") {
		t.Errorf("stderr missing 'no valid PEM': %q", stderr)
	}
}
