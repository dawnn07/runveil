package main

// sourceInputs gathers the raw inputs for resolving the policy/SIEM
// endpoints and their auth, in priority order handled by resolveSources.
type sourceInputs struct {
	PolicyURLFlag    string
	SIEMURLFlag      string
	PolicyHeaderFlag string
	SIEMHeaderFlag   string
	PolicyTokenEnv   string // RUNVEIL_POLICY_TOKEN
	SIEMAuthEnv      string // RUNVEIL_SIEM_AUTH
	ConfigPolicyURL  string // config.PolicyURL()
	ConfigSIEMURL    string // config.SIEMURL()
	ConfigToken      string // config.DeviceToken
	EnrollToken      string // enrollment device token
}

// resolvedSources is the effective endpoint + auth selection.
type resolvedSources struct {
	PolicyURL        string
	SIEMURL          string
	PolicyAuthHeader string
	SIEMAuthHeader   string
	PolicyAuthValue  string
	SIEMAuthValue    string
}

// resolveSources applies precedence: explicit flag > config > local/enroll.
// When a URL is taken from config (not a flag) and no auth-header flag is
// set, the header defaults to "Authorization". Auth value precedence is
// env > config token > enrollment token. Pure; no I/O.
func resolveSources(in sourceInputs) resolvedSources {
	var r resolvedSources

	r.PolicyURL = first(in.PolicyURLFlag, in.ConfigPolicyURL)
	r.SIEMURL = first(in.SIEMURLFlag, in.ConfigSIEMURL)

	policyFromConfig := in.PolicyURLFlag == "" && in.ConfigPolicyURL != ""
	siemFromConfig := in.SIEMURLFlag == "" && in.ConfigSIEMURL != ""

	r.PolicyAuthHeader = authHeader(in.PolicyHeaderFlag, policyFromConfig)
	r.SIEMAuthHeader = authHeader(in.SIEMHeaderFlag, siemFromConfig)

	r.PolicyAuthValue = first(in.PolicyTokenEnv, in.ConfigToken, in.EnrollToken)
	r.SIEMAuthValue = first(in.SIEMAuthEnv, in.ConfigToken, in.EnrollToken)
	return r
}

func authHeader(flagVal string, fromConfig bool) string {
	if flagVal != "" {
		return flagVal
	}
	if fromConfig {
		return "Authorization"
	}
	return ""
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
