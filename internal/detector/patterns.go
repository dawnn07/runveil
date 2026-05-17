// Pattern provenance: patterns in this file are derived from public
// catalogs in secretlint (MIT), gitleaks (MIT), and trufflehog. We have
// tightened several to reduce false positives.

package detector

import "regexp"

func init() {
	// --- AWS ---
	register(Pattern{
		Name:             "aws_access_key_id",
		Severity:         SeverityHigh,
		Regex:            regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		EntropyThreshold: 3.0,
		EntropySpan:      func(_ string, m []int) (int, int) { return m[0] + 4, m[1] },
	})
	register(Pattern{
		Name:             "aws_secret_access_key",
		Severity:         SeverityHigh,
		Regex:            regexp.MustCompile(`(?i)aws[_\-]?(?:secret|sk)[^\n=:]{0,30}[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
		EntropyThreshold: 4.5,
		EntropySpan: func(text string, m []int) (int, int) {
			if len(m) < 4 {
				return m[0], m[1]
			}
			return m[2], m[3]
		},
	})
	register(Pattern{
		Name:     "aws_session_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\b(?:FwoG|IQoJ)[A-Za-z0-9/+=]{100,}\b`),
	})

	// --- GitHub ---
	register(Pattern{
		Name:     "github_pat_classic",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
	})
	register(Pattern{
		Name:     "github_pat_fine_grained",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`),
	})
	register(Pattern{
		Name:     "github_oauth_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`),
	})
	register(Pattern{
		Name:     "github_app_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b`),
	})

	// --- GitLab ---
	register(Pattern{
		Name:     "gitlab_pat",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`),
	})

	// --- Stripe ---
	register(Pattern{
		Name:     "stripe_secret_live",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
	})
	register(Pattern{
		Name:     "stripe_restricted_live",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\brk_live_[A-Za-z0-9]{24,}\b`),
	})

	// --- OpenAI / Anthropic ---
	register(Pattern{
		Name:     "openai_api_key",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`),
	})
	register(Pattern{
		Name:     "anthropic_api_key",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{86,}\b`),
	})

	// --- Google ---
	register(Pattern{
		Name:     "google_api_key",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	})
	register(Pattern{
		Name:     "google_oauth_client_secret",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{28}\b`),
	})
	register(Pattern{
		Name:     "google_service_account_json",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`"type"\s*:\s*"service_account"[\s\S]{1,500}?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----`),
	})

	// --- Slack ---
	register(Pattern{
		Name:     "slack_bot_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b`),
	})
	register(Pattern{
		Name:     "slack_user_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bxoxp-[0-9]+-[0-9]+-[0-9]+-[A-Fa-f0-9]+\b`),
	})
	register(Pattern{
		Name:     "slack_app_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bxapp-[0-9]+-[A-Z0-9]+-[0-9]+-[A-Fa-f0-9]+\b`),
	})
	register(Pattern{
		Name:     "slack_webhook_url",
		Severity: SeverityMedium,
		Regex:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[A-Za-z0-9]+`),
	})

	// --- Discord ---
	register(Pattern{
		Name:     "discord_bot_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\b[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27}\b`),
	})
	register(Pattern{
		Name:     "discord_webhook_url",
		Severity: SeverityMedium,
		Regex:    regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`),
	})

	// --- Package registries ---
	register(Pattern{
		Name:     "npm_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
	})
	register(Pattern{
		Name:     "pypi_token",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`),
	})

	// --- Private keys ---
	register(Pattern{
		Name:     "private_key_rsa",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	})
	register(Pattern{
		Name:     "private_key_openssh",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
	})
	register(Pattern{
		Name:     "private_key_ec",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	})
	register(Pattern{
		Name:     "private_key_pkcs8",
		Severity: SeverityHigh,
		Regex:    regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
	})

	// --- JWT / DB URLs / generic ---
	register(Pattern{
		Name:     "jwt",
		Severity: SeverityMedium,
		Regex:    regexp.MustCompile(`\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	})
	register(Pattern{
		Name:     "db_url_with_password",
		Severity: SeverityMedium,
		Regex:    regexp.MustCompile(`\b(?:postgres|mysql|mongodb)(?:\+srv)?://[^\s:]+:[^@/\s]+@[^/\s]+`),
	})
	register(Pattern{
		Name:             "generic_high_entropy_assignment",
		Severity:         SeverityLow,
		Regex:            regexp.MustCompile(`(?i)(?:password|secret|api[_-]?key|token)\s*[:=]\s*['"]?([A-Za-z0-9/+=_-]{20,})['"]?`),
		EntropyThreshold: 4.0,
		EntropySpan: func(_ string, m []int) (int, int) {
			if len(m) < 4 {
				return m[0], m[1]
			}
			return m[2], m[3]
		},
	})
}

func register(p Pattern) {
	mu.Lock()
	patterns = append(patterns, p)
	mu.Unlock()
}
