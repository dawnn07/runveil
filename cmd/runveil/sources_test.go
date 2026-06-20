package main

import "testing"

func TestResolveSources_FlagWinsOverConfig(t *testing.T) {
	r := resolveSources(sourceInputs{
		PolicyURLFlag:   "http://flag/v1/policy",
		ConfigPolicyURL: "http://cfg/v1/policy",
		ConfigToken:     "dt_cfg",
	})
	if r.PolicyURL != "http://flag/v1/policy" {
		t.Fatalf("policy url: %q", r.PolicyURL)
	}
	if r.PolicyAuthHeader != "" {
		t.Fatalf("flag url should not default header, got %q", r.PolicyAuthHeader)
	}
}

func TestResolveSources_ConfigFallbackDefaultsAuthHeader(t *testing.T) {
	r := resolveSources(sourceInputs{
		ConfigPolicyURL: "http://cfg/v1/policy",
		ConfigSIEMURL:   "http://cfg/v1/audit/batch",
		ConfigToken:     "dt_cfg",
	})
	if r.PolicyURL != "http://cfg/v1/policy" || r.SIEMURL != "http://cfg/v1/audit/batch" {
		t.Fatalf("urls: %+v", r)
	}
	if r.PolicyAuthHeader != "Authorization" || r.SIEMAuthHeader != "Authorization" {
		t.Fatalf("config urls should default header to Authorization, got %+v", r)
	}
	if r.PolicyAuthValue != "dt_cfg" || r.SIEMAuthValue != "dt_cfg" {
		t.Fatalf("auth values: %+v", r)
	}
}

func TestResolveSources_TokenPrecedence(t *testing.T) {
	r := resolveSources(sourceInputs{
		ConfigPolicyURL: "http://cfg/v1/policy",
		PolicyTokenEnv:  "env-tok",
		ConfigToken:     "dt_cfg",
		EnrollToken:     "enr-tok",
	})
	if r.PolicyAuthValue != "env-tok" {
		t.Fatalf("env should win: %q", r.PolicyAuthValue)
	}
}

func TestResolveSources_EnrollFallback(t *testing.T) {
	r := resolveSources(sourceInputs{
		PolicyURLFlag:    "http://flag/v1/policy",
		PolicyHeaderFlag: "Authorization",
		EnrollToken:      "enr-tok",
	})
	if r.PolicyAuthValue != "enr-tok" {
		t.Fatalf("enroll fallback: %q", r.PolicyAuthValue)
	}
	if r.PolicyAuthHeader != "Authorization" {
		t.Fatalf("explicit header flag should pass through: %q", r.PolicyAuthHeader)
	}
}

func TestResolveSources_AllEmptyIsLocal(t *testing.T) {
	r := resolveSources(sourceInputs{})
	if r.PolicyURL != "" || r.SIEMURL != "" {
		t.Fatalf("want local, got %+v", r)
	}
}
