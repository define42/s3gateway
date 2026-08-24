package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authz "github.com/define42/s3gateway/internal/authz"
	sigv4 "github.com/define42/s3gateway/internal/sigv4"
)

func TestSigV4AuthFromCtx(t *testing.T) {
	t.Run("missing context value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		if got := sigv4.AuthFromRequest(req); got != nil {
			t.Fatalf("sigV4AuthFromCtx() = %+v, want nil", got)
		}
	})

	t.Run("wrong context value type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4AuthKey, "not-auth"),
		)
		if got := sigv4.AuthFromRequest(req); got != nil {
			t.Fatalf("sigV4AuthFromCtx() = %+v, want nil for wrong context type", got)
		}
	})

	t.Run("valid auth value", func(t *testing.T) {
		want := &sigv4.Auth{
			AccessKey:    "access",
			Date:         "20260207",
			Region:       "us-east-1",
			Service:      "s3",
			SignatureHex: strings.Repeat("a", 64),
			AmzDate:      "20260207T010203Z",
		}
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4AuthKey, want),
		)
		got := sigv4.AuthFromRequest(req)
		if got != want {
			t.Fatalf("sigV4AuthFromCtx() pointer mismatch: got=%p want=%p", got, want)
		}
	})
}

func TestSigV4SecretFromCtx(t *testing.T) {
	t.Run("missing context value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		if got := sigv4.SecretFromRequest(req); got != "" {
			t.Fatalf("sigV4SecretFromCtx() = %q, want empty string", got)
		}
	})

	t.Run("wrong context value type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4SecretKey, 123),
		)
		if got := sigv4.SecretFromRequest(req); got != "" {
			t.Fatalf("sigV4SecretFromCtx() = %q, want empty string for wrong context type", got)
		}
	})

	t.Run("valid secret value", func(t *testing.T) {
		const want = "derived-secret"
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4SecretKey, want),
		)
		if got := sigv4.SecretFromRequest(req); got != want {
			t.Fatalf("sigV4SecretFromCtx() = %q, want %q", got, want)
		}
	})
}

func TestChunkSignatureVerifierFromRequestUsesSigV4AuthFromCtx(t *testing.T) {
	const mode = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"

	t.Run("missing sigv4 auth context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		req.Header.Set("x-amz-content-sha256", mode)

		verifier, err := sigv4.ChunkSignatureVerifierFromRequest(req)
		if !errors.Is(err, sigv4.ErrMissingSigV4AuthContext) {
			t.Fatalf("chunkSignatureVerifierFromRequest() error = %v, want %v", err, sigv4.ErrMissingSigV4AuthContext)
		}
		if verifier != nil {
			t.Fatalf("chunkSignatureVerifierFromRequest() verifier = %+v, want nil on missing context", verifier)
		}
	})

	t.Run("missing sigv4 secret context", func(t *testing.T) {
		auth := &sigv4.Auth{
			AccessKey:    "access",
			Date:         "20260207",
			Region:       "us-east-1",
			Service:      "s3",
			SignatureHex: strings.Repeat("b", 64),
			AmzDate:      "20260207T010203Z",
		}
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(
			context.WithValue(context.Background(), sigv4.CtxSigV4AuthKey, auth),
		)
		req.Header.Set("x-amz-content-sha256", mode)

		verifier, err := sigv4.ChunkSignatureVerifierFromRequest(req)
		if !errors.Is(err, sigv4.ErrMissingSigV4SecretContext) {
			t.Fatalf("chunkSignatureVerifierFromRequest() error = %v, want %v", err, sigv4.ErrMissingSigV4SecretContext)
		}
		if verifier != nil {
			t.Fatalf("chunkSignatureVerifierFromRequest() verifier = %+v, want nil on missing secret context", verifier)
		}
	})

	t.Run("with sigv4 auth context", func(t *testing.T) {
		auth := &sigv4.Auth{
			AccessKey:    "access",
			Date:         "20260207",
			Region:       "us-east-1",
			Service:      "s3",
			SignatureHex: strings.Repeat("b", 64),
			AmzDate:      "20260207T010203Z",
		}
		ctx := context.WithValue(context.Background(), sigv4.CtxSigV4AuthKey, auth)
		ctx = context.WithValue(ctx, sigv4.CtxSigV4SecretKey, "secret")
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil).WithContext(ctx)
		req.Header.Set("x-amz-content-sha256", mode)

		verifier, err := sigv4.ChunkSignatureVerifierFromRequest(req)
		if err != nil {
			t.Fatalf("chunkSignatureVerifierFromRequest() error = %v", err)
		}
		if verifier == nil {
			t.Fatalf("chunkSignatureVerifierFromRequest() verifier is nil")
		}
		if verifier.PrevSig != auth.SignatureHex {
			t.Fatalf("chunkSignatureVerifierFromRequest() prevSig = %q, want %q", verifier.PrevSig, auth.SignatureHex)
		}
	})
}

func TestParseGroupPermissions(t *testing.T) {
	tests := []struct {
		name       string
		group      string
		wantPrefix string
		wantPerm   authz.Perm
		wantOK     bool
	}{
		{
			name:       "read only",
			group:      "team2-r",
			wantPrefix: "team2",
			wantPerm:   authz.PermRead,
			wantOK:     true,
		},
		{
			name:       "read write",
			group:      "team2-rw",
			wantPrefix: "team2",
			wantPerm:   authz.PermRead | authz.PermWrite,
			wantOK:     true,
		},
		{
			name:       "full letters mixed order",
			group:      "team2-bcdwr",
			wantPrefix: "team2",
			wantPerm:   authz.PermRead | authz.PermWrite | authz.PermCreateBucket | authz.PermDeleteObject | authz.PermDeleteBucket,
			wantOK:     true,
		},
		{
			name:       "trimmed and case insensitive",
			group:      "  TEAM2-RWCDB  ",
			wantPrefix: "team2",
			wantPerm:   authz.PermRead | authz.PermWrite | authz.PermCreateBucket | authz.PermDeleteObject | authz.PermDeleteBucket,
			wantOK:     true,
		},
		{
			name:   "missing prefix",
			group:  "-r",
			wantOK: false,
		},
		{
			name:   "missing permission letters",
			group:  "team2-",
			wantOK: false,
		},
		{
			name:   "group has separator but no access flag",
			group:  "team2-   ",
			wantOK: false,
		},
		{
			name:   "unsupported permission letter",
			group:  "team2-rx",
			wantOK: false,
		},
		{
			name:   "multiple dashes: first dash used, rest treated as letters (invalid)",
			group:  "my-team-r",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrefix, gotPerm, gotOK := authz.ParseGroup(tt.group)
			if gotOK != tt.wantOK {
				t.Fatalf("parseGroup() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if !gotOK {
				return
			}
			if gotPrefix != tt.wantPrefix {
				t.Fatalf("parseGroup() prefix = %q, want %q", gotPrefix, tt.wantPrefix)
			}
			if gotPerm != tt.wantPerm {
				t.Fatalf("parseGroup() perm = %v, want %v", gotPerm, tt.wantPerm)
			}
		})
	}
}

func TestRulesFromGroupsCombinesPermissions(t *testing.T) {
	rules := authz.RulesFromGroups(map[string]struct{}{
		"team2-r": {},
		"team2-w": {},
		"team2-c": {},
		"team2-d": {},
		"team2-b": {},
	})
	bucket := "team2-bucket"

	if !authz.CanRead(rules, bucket) {
		t.Fatalf("expected read permission")
	}
	if !authz.CanWrite(rules, bucket) {
		t.Fatalf("expected write permission")
	}
	if !authz.CanCreateBucket(rules, bucket) {
		t.Fatalf("expected create-bucket permission")
	}
	if !authz.CanDeleteObject(rules, bucket) {
		t.Fatalf("expected delete-object permission")
	}
	if !authz.CanDeleteBucket(rules, bucket) {
		t.Fatalf("expected delete-bucket permission")
	}

	readOnlyRules := authz.RulesFromGroups(map[string]struct{}{
		"team2-r": {},
	})
	if authz.CanWrite(readOnlyRules, bucket) || authz.CanCreateBucket(readOnlyRules, bucket) || authz.CanDeleteObject(readOnlyRules, bucket) || authz.CanDeleteBucket(readOnlyRules, bucket) {
		t.Fatalf("read-only permissions unexpectedly granted write/create/delete")
	}
}

func TestRulesFromGroupsIgnoresGroupWithoutAccessFlag(t *testing.T) {
	rules := authz.RulesFromGroups(map[string]struct{}{
		"team2-":    {},
		"team2-   ": {},
	})

	if len(rules) != 0 {
		t.Fatalf("expected no rules from groups without access flags, got=%+v", rules)
	}
	if authz.CanRead(rules, "team2-any") || authz.CanWrite(rules, "team2-any") || authz.CanCreateBucket(rules, "team2-any") || authz.CanDeleteObject(rules, "team2-any") || authz.CanDeleteBucket(rules, "team2-any") {
		t.Fatalf("expected no permissions from groups without access flags")
	}
}
