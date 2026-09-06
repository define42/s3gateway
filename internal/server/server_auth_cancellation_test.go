package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/config"
)

func TestCanceledAuthenticationReleasesHTTPAdmissionSlot(t *testing.T) {
	for _, tc := range []struct {
		name string
		idle bool
	}{
		{name: "request cancellation"},
		{name: "transfer idle cancellation", idle: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const idle = time.Second
				gateway := New(config.Config{MaxConcurrentRequests: 1, TransferIdleTimeout: idle}, nil)
				lookupStarted := make(chan struct{})
				lookupFinished := make(chan struct{})
				releaseLookup := make(chan struct{})
				// Release the backend even if an assertion fails while it is blocked.
				defer func() {
					close(releaseLookup)
					synctest.Wait()
				}()
				gateway.fetchGroups = func(_ config.Config, username, password string) (map[string]struct{}, error) {
					if password != "synthetic-password" {
						return nil, errors.New("unexpected test password")
					}
					switch username {
					case "blocked-user":
						close(lookupStarted)
						<-releaseLookup
						close(lookupFinished)
					case "ready-user":
					default:
						return nil, errors.New("unexpected test username")
					}
					return map[string]struct{}{"team2-r": {}}, nil
				}
				handlerCalls := 0
				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handlerCalls++
					if UploaderFromRequest(r) != "ready-user" || !authz.CanRead(authz.RulesFromRequest(r), "team2-bucket") {
						t.Error("unexpected identity or permissions reached authenticated handler")
					}
					w.WriteHeader(http.StatusNoContent)
				})
				handler := NewHTTPServer(gateway.cfg, gateway.WithAuth(next, http.NotFoundHandler())).Handler
				newRequest := func(username string) *http.Request {
					request := httptest.NewRequest(http.MethodGet, "https://gateway.example/api/pop/team2", nil)
					request.SetBasicAuth(username, "synthetic-password")
					return request
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				firstDone := make(chan struct{})
				go func() {
					handler.ServeHTTP(httptest.NewRecorder(), newRequest("blocked-user").WithContext(ctx))
					close(firstDone)
				}()
				synctest.Wait()
				select {
				case <-lookupStarted:
				default:
					t.Fatal("request did not reach the blocked LDAP lookup")
				}
				overloaded := httptest.NewRecorder()
				handler.ServeHTTP(overloaded, newRequest("ready-user"))
				if overloaded.Code != http.StatusServiceUnavailable {
					t.Fatalf("occupied HTTP slot status=%d, want 503", overloaded.Code)
				}

				if tc.idle {
					time.Sleep(idle)
				} else {
					cancel()
				}
				synctest.Wait()
				select {
				case <-firstDone:
				default:
					t.Fatal("canceled authentication still occupies the HTTP handler")
				}
				select {
				case <-lookupFinished:
					t.Fatal("LDAP completed before testing HTTP slot release")
				default:
				}
				if handlerCalls != 0 {
					t.Fatal("canceled request reached the authenticated handler")
				}

				response := httptest.NewRecorder()
				handler.ServeHTTP(response, newRequest("ready-user"))
				if response.Code != http.StatusNoContent || handlerCalls != 1 {
					t.Fatalf("HTTP slot remained unavailable: status=%d handler calls=%d", response.Code, handlerCalls)
				}
				select {
				case <-lookupFinished:
					t.Fatal("replacement request needed the original LDAP lookup to complete")
				default:
				}
			})
		})
	}
}
