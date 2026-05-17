package detector

import (
	"regexp"
	"testing"
)

func TestSeverity_String(t *testing.T) {
	cases := []struct {
		s    Severity
		want string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestScan_EmptyPatternsReturnsEmpty(t *testing.T) {
	findings := Scan("anything at all")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings with no patterns registered, got %d", len(findings))
	}
}

func TestScan_EmptyTextReturnsEmpty(t *testing.T) {
	findings := Scan("")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on empty text, got %d", len(findings))
	}
}

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		name string
		in   string
		min  float64
		max  float64
	}{
		{"empty", "", 0, 0},
		{"single char repeated", "aaaaaaaaaa", 0, 0.001},
		{"two equal chars", "abababab", 0.999, 1.001},
		{"random-looking 16-char suffix", "IOSFODNN7EXAMPLE", 3.4, 4.1},
		{"high-entropy hex", "0123456789abcdef0123456789abcdef", 3.9, 4.001},
	}
	for _, tc := range cases {
		got := shannonEntropy(tc.in)
		if got < tc.min || got > tc.max {
			t.Errorf("shannonEntropy(%q) = %f, want in [%f, %f]", tc.in, got, tc.min, tc.max)
		}
	}
}

func TestScan_AWSAccessKeyID_Positive(t *testing.T) {
	text := `here is my key AKIAIOSFODNN7EXAMPLE for the bucket`
	findings := Scan(text)
	want := "aws_access_key_id"
	found := false
	for _, f := range findings {
		if f.Pattern == want && f.Severity == SeverityHigh {
			found = true
			if got := text[f.Offset : f.Offset+f.Length]; got != "AKIAIOSFODNN7EXAMPLE" {
				t.Errorf("matched substring = %q, want %q", got, "AKIAIOSFODNN7EXAMPLE")
			}
		}
	}
	if !found {
		t.Fatalf("Scan did not find aws_access_key_id in %q; got %+v", text, findings)
	}
}

func TestScan_AWSAccessKeyID_LowEntropySuffixRejected(t *testing.T) {
	// AKIA + all-zeros suffix has entropy 0, must NOT match.
	text := "value: AKIA0000000000000000"
	findings := Scan(text)
	for _, f := range findings {
		if f.Pattern == "aws_access_key_id" {
			t.Fatalf("low-entropy AWS suffix should be filtered, but got finding %+v", f)
		}
	}
}

func TestScan_AWSAccessKeyID_NoFalseMatch(t *testing.T) {
	text := "this string contains the word akia in lowercase and AKIA only"
	findings := Scan(text)
	for _, f := range findings {
		if f.Pattern == "aws_access_key_id" {
			t.Fatalf("expected no aws_access_key_id finding in %q, got %+v", text, f)
		}
	}
}

// Each new pattern gets a positive + negative test. Test names follow
// the convention TestScan_<PatternName>_Positive / _Negative.

func TestScan_AWSSecretAccessKey_Positive(t *testing.T) {
	text := `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
	requireFinding(t, text, "aws_secret_access_key", SeverityHigh)
}
func TestScan_AWSSecretAccessKey_Negative(t *testing.T) {
	text := `secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
	requireNoFinding(t, text, "aws_secret_access_key")
}

func TestScan_AWSSessionToken_Positive(t *testing.T) {
	text := `tok=FwoGZXIvYXdzEHkaDFAKEFAKEFAKEFAKE` + repeat("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=", 3)
	requireFinding(t, text, "aws_session_token", SeverityHigh)
}
func TestScan_AWSSessionToken_Negative(t *testing.T) {
	requireNoFinding(t, "FwoGZXIvshort", "aws_session_token")
}

func TestScan_GitHubPATClassic_Positive(t *testing.T) {
	requireFinding(t, `token: ghp_abcdefghijklmnopqrstuvwxyz0123456789`, "github_pat_classic", SeverityHigh)
}
func TestScan_GitHubPATClassic_Negative(t *testing.T) {
	requireNoFinding(t, "ghp_too_short", "github_pat_classic")
}

func TestScan_GitHubPATFineGrained_Positive(t *testing.T) {
	requireFinding(t, `pat: github_pat_`+repeat("A", 82), "github_pat_fine_grained", SeverityHigh)
}
func TestScan_GitHubPATFineGrained_Negative(t *testing.T) {
	requireNoFinding(t, "github_pat_short", "github_pat_fine_grained")
}

func TestScan_GitHubOAuthToken_Positive(t *testing.T) {
	requireFinding(t, `gho_abcdefghijklmnopqrstuvwxyz0123456789`, "github_oauth_token", SeverityHigh)
}
func TestScan_GitHubOAuthToken_Negative(t *testing.T) {
	requireNoFinding(t, "gho_short", "github_oauth_token")
}

func TestScan_GitHubAppToken_Positive(t *testing.T) {
	requireFinding(t, `ghu_abcdefghijklmnopqrstuvwxyz0123456789`, "github_app_token", SeverityHigh)
	requireFinding(t, `ghs_abcdefghijklmnopqrstuvwxyz0123456789`, "github_app_token", SeverityHigh)
}
func TestScan_GitHubAppToken_Negative(t *testing.T) {
	requireNoFinding(t, "ghx_abcdefghijklmnopqrstuvwxyz0123456789", "github_app_token")
}

func TestScan_GitLabPAT_Positive(t *testing.T) {
	requireFinding(t, `pat: glpat-abcdefg-Hij_klmnopqr`, "gitlab_pat", SeverityHigh)
}
func TestScan_GitLabPAT_Negative(t *testing.T) {
	requireNoFinding(t, "glpat-short", "gitlab_pat")
}

func TestScan_StripeSecretLive_Positive(t *testing.T) {
	requireFinding(t, `sk_live_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF`, "stripe_secret_live", SeverityHigh)
}
func TestScan_StripeSecretLive_Negative(t *testing.T) {
	requireNoFinding(t, "sk_test_abcdefghijklmnopqrstuvwxyz", "stripe_secret_live")
}

func TestScan_StripeRestrictedLive_Positive(t *testing.T) {
	requireFinding(t, `rk_live_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF`, "stripe_restricted_live", SeverityHigh)
}
func TestScan_StripeRestrictedLive_Negative(t *testing.T) {
	requireNoFinding(t, "rk_test_abc", "stripe_restricted_live")
}

func TestScan_OpenAIAPIKey_Positive(t *testing.T) {
	requireFinding(t, `sk-proj-abcdefghijklmnopqrstuvwxyz0123456789`, "openai_api_key", SeverityHigh)
	requireFinding(t, `sk-abcdefghijklmnopqrstuvwxyz0123456789`, "openai_api_key", SeverityHigh)
}
func TestScan_OpenAIAPIKey_Negative(t *testing.T) {
	requireNoFinding(t, "sk-short", "openai_api_key")
}

func TestScan_AnthropicAPIKey_Positive(t *testing.T) {
	requireFinding(t, `key: sk-ant-`+repeat("A", 86), "anthropic_api_key", SeverityHigh)
}
func TestScan_AnthropicAPIKey_Negative(t *testing.T) {
	requireNoFinding(t, "sk-ant-short", "anthropic_api_key")
}

func TestScan_GoogleAPIKey_Positive(t *testing.T) {
	requireFinding(t, `key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456`, "google_api_key", SeverityHigh)
}
func TestScan_GoogleAPIKey_Negative(t *testing.T) {
	requireNoFinding(t, "AIzaShort", "google_api_key")
}

func TestScan_GoogleOAuthClientSecret_Positive(t *testing.T) {
	requireFinding(t, `secret: GOCSPX-abcdefghijklmnopqrstuvwxyzAB`, "google_oauth_client_secret", SeverityHigh)
}
func TestScan_GoogleOAuthClientSecret_Negative(t *testing.T) {
	requireNoFinding(t, "GOCSPX-short", "google_oauth_client_secret")
}

func TestScan_GoogleServiceAccountJSON_Positive(t *testing.T) {
	requireFinding(t,
		`{"type": "service_account", "project_id": "p", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE..."}`,
		"google_service_account_json", SeverityHigh)
}
func TestScan_GoogleServiceAccountJSON_Negative(t *testing.T) {
	requireNoFinding(t, `{"type":"user","private_key":"not a key"}`, "google_service_account_json")
}

func TestScan_SlackBotToken_Positive(t *testing.T) {
	requireFinding(t, `tok: xoxb-123456789-987654321-abcDEFghiJKLmnoPQRstu`, "slack_bot_token", SeverityHigh)
}
func TestScan_SlackBotToken_Negative(t *testing.T) {
	requireNoFinding(t, "xoxb-incomplete", "slack_bot_token")
}

func TestScan_SlackUserToken_Positive(t *testing.T) {
	requireFinding(t, `xoxp-123456789-987654321-555555555-abcdef0123456789`, "slack_user_token", SeverityHigh)
}
func TestScan_SlackUserToken_Negative(t *testing.T) {
	requireNoFinding(t, "xoxp-short", "slack_user_token")
}

func TestScan_SlackAppToken_Positive(t *testing.T) {
	requireFinding(t, `xapp-1-A0123ABCDE-1234567890-abcdef0123456789`, "slack_app_token", SeverityHigh)
}
func TestScan_SlackAppToken_Negative(t *testing.T) {
	requireNoFinding(t, "xapp-short", "slack_app_token")
}

func TestScan_SlackWebhook_Positive(t *testing.T) {
	requireFinding(t, `https://hooks.slack.com/services/T01234567/B01234567/abcdefghij`, "slack_webhook_url", SeverityMedium)
}
func TestScan_SlackWebhook_Negative(t *testing.T) {
	requireNoFinding(t, "https://example.com/hook", "slack_webhook_url")
}

func TestScan_DiscordBotToken_Positive(t *testing.T) {
	requireFinding(t, `MTAwMDAwMDAwMDAwMDAwMDAw.AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAA`, "discord_bot_token", SeverityHigh)
}
func TestScan_DiscordBotToken_Negative(t *testing.T) {
	requireNoFinding(t, "Mshortdiscord", "discord_bot_token")
}

func TestScan_DiscordWebhook_Positive(t *testing.T) {
	requireFinding(t, `https://discord.com/api/webhooks/123456789/abcdefg_hijkl`, "discord_webhook_url", SeverityMedium)
}
func TestScan_DiscordWebhook_Negative(t *testing.T) {
	requireNoFinding(t, "https://example.com/api/webhooks/123/abc", "discord_webhook_url")
}

func TestScan_NPMToken_Positive(t *testing.T) {
	requireFinding(t, `_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789`, "npm_token", SeverityHigh)
}
func TestScan_NPMToken_Negative(t *testing.T) {
	requireNoFinding(t, "npm_short", "npm_token")
}

func TestScan_PyPIToken_Positive(t *testing.T) {
	requireFinding(t, `pypi-AgEIcHlwaS5vcmc`+repeat("X", 50), "pypi_token", SeverityHigh)
}
func TestScan_PyPIToken_Negative(t *testing.T) {
	requireNoFinding(t, "pypi-short", "pypi_token")
}

func TestScan_PrivateKeyRSA_Positive(t *testing.T) {
	requireFinding(t, "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...", "private_key_rsa", SeverityHigh)
}
func TestScan_PrivateKeyOpenSSH_Positive(t *testing.T) {
	requireFinding(t, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...", "private_key_openssh", SeverityHigh)
}
func TestScan_PrivateKeyEC_Positive(t *testing.T) {
	requireFinding(t, "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIGZ4...", "private_key_ec", SeverityHigh)
}
func TestScan_PrivateKeyPKCS8_Positive(t *testing.T) {
	requireFinding(t, "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhk...", "private_key_pkcs8", SeverityHigh)
}

func TestScan_JWT_Positive(t *testing.T) {
	requireFinding(t,
		`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_xyz_at_least_ten_chars`,
		"jwt", SeverityMedium)
}
func TestScan_JWT_Negative(t *testing.T) {
	requireNoFinding(t, "not a jwt", "jwt")
}

func TestScan_DBURLWithPassword_Positive(t *testing.T) {
	requireFinding(t, `postgres://user:hunter2@db.example.com:5432/app`, "db_url_with_password", SeverityMedium)
}
func TestScan_DBURLWithPassword_Negative(t *testing.T) {
	requireNoFinding(t, "postgres://db.example.com:5432/app", "db_url_with_password")
}

func TestScan_GenericHighEntropy_Positive(t *testing.T) {
	requireFinding(t,
		`api_key = "Xy7Bz9Qf2vR8N3sM5tK1pL6wA0eD4hCg"`,
		"generic_high_entropy_assignment", SeverityLow)
}
func TestScan_GenericHighEntropy_NegativeLowEntropy(t *testing.T) {
	requireNoFinding(t, `password = "aaaaaaaaaaaaaaaaaaaaaaaa"`, "generic_high_entropy_assignment")
}

// --- test helpers ---

func requireFinding(t *testing.T, text, pattern string, sev Severity) {
	t.Helper()
	for _, f := range Scan(text) {
		if f.Pattern == pattern && f.Severity == sev {
			return
		}
	}
	t.Fatalf("Scan(%q) did not produce %s/%s; got %+v", text, pattern, sev, Scan(text))
}

func requireNoFinding(t *testing.T, text, pattern string) {
	t.Helper()
	for _, f := range Scan(text) {
		if f.Pattern == pattern {
			t.Fatalf("Scan(%q) produced unwanted finding %+v", text, f)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestAddPattern_RegistersAtRuntime(t *testing.T) {
	mu.RLock()
	before := len(patterns)
	mu.RUnlock()

	AddPattern(Pattern{
		Name:     "test_runtime_pattern",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`runtime-secret-[0-9]+`),
	})

	mu.RLock()
	after := len(patterns)
	mu.RUnlock()
	if after != before+1 {
		t.Fatalf("AddPattern did not grow registry: before=%d after=%d", before, after)
	}

	findings := Scan("here is runtime-secret-12345 in text")
	found := false
	for _, f := range findings {
		if f.Pattern == "test_runtime_pattern" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Scan did not see the runtime-added pattern; got %+v", findings)
	}
}

// TestScan_Base64WrappedSecret documents that Scan does not decode
// base64 before applying patterns. A secret embedded as base64 in
// text will not be detected. This test exists to make the limitation
// explicit; if future work adds base64 decoding, this test should
// flip to expecting a finding.
func TestScan_Base64WrappedSecret(t *testing.T) {
	// AKIAIOSFODNN7EXAMPLE base64-encoded.
	text := "wrapped: QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	for _, f := range Scan(text) {
		if f.Pattern == "aws_access_key_id" {
			t.Fatalf("base64 wrapper unexpectedly matched aws_access_key_id: %+v", f)
		}
	}
	// Test passes whether Scan returns zero findings or some findings of
	// other patterns — the contract is only that aws_access_key_id does
	// NOT fire on the base64 wrapper.
}
