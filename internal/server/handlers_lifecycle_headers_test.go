package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBucketLifecycleTransitionSizeRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   string
		bad    bool
	}{
		{name: "absent"},
		{name: "varies by storage class", values: []string{"varies_by_storage_class"}, want: "varies_by_storage_class"},
		{name: "all classes", values: []string{"all_storage_classes_128K"}, want: "all_storage_classes_128K"},
		{name: "surrounding whitespace", values: []string{" varies_by_storage_class "}, want: "varies_by_storage_class"},
		{name: "unsupported mode", values: []string{"all_storage_classes"}, bad: true},
		{name: "empty mode", values: []string{""}, bad: true},
		{name: "repeated mode", values: []string{"varies_by_storage_class", "varies_by_storage_class"}, bad: true},
		{name: "conflicting modes", values: []string{"varies_by_storage_class", "all_storage_classes_128K"}, bad: true},
		{name: "combined modes", values: []string{"varies_by_storage_class,all_storage_classes_128K"}, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan http.Header, 1)
			gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				requests <- r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			})
			t.Cleanup(cleanup)
			req := httptest.NewRequest(http.MethodPut, "/team2-bucket?lifecycle", strings.NewReader(bucketConfigurationRoutes[0].body))
			for _, value := range tc.values {
				req.Header.Add(lifecycleTransitionSizeHeader, value)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if tc.bad {
				if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>InvalidArgument</Code>") {
					t.Fatalf("invalid transition size accepted: status=%d body=%s", rr.Code, rr.Body.String())
				}
				select {
				case <-requests:
					t.Error("invalid lifecycle configuration reached upstream")
				default:
				}
				return
			}
			if rr.Code != http.StatusOK {
				t.Fatalf("lifecycle update failed: status=%d body=%s", rr.Code, rr.Body.String())
			}
			select {
			case headers := <-requests:
				if got := headers.Get(lifecycleTransitionSizeHeader); got != tc.want {
					t.Errorf("upstream transition size=%q, want %q", got, tc.want)
				}
				if tc.want == "" && len(headers.Values(lifecycleTransitionSizeHeader)) != 0 {
					t.Error("absent transition size was added upstream")
				}
			default:
				t.Fatal("lifecycle update did not reach upstream")
			}
		})
	}
}

func TestBucketLifecycleTransitionSizeResponse(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			for _, mode := range []string{"", "varies_by_storage_class", "all_storage_classes_128K"} {
				t.Run("mode="+mode, func(t *testing.T) {
					gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
						_, _ = io.Copy(io.Discard, r.Body)
						if mode != "" {
							w.Header().Set(lifecycleTransitionSizeHeader, mode)
						}
						if method == http.MethodGet {
							w.Header().Set("Content-Type", "application/xml")
							_, _ = io.WriteString(w, bucketConfigurationRoutes[0].body)
						} else {
							w.WriteHeader(http.StatusOK)
						}
					})
					t.Cleanup(cleanup)
					body := ""
					if method == http.MethodPut {
						body = bucketConfigurationRoutes[0].body
					}
					req := httptest.NewRequest(method, "/team2-bucket?lifecycle", strings.NewReader(body))
					if method == http.MethodPut {
						// The response must report the upstream setting, independently
						// of the caller's requested setting.
						req.Header.Set(lifecycleTransitionSizeHeader, "varies_by_storage_class")
					}
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
					if rr.Code != http.StatusOK || rr.Header().Get(lifecycleTransitionSizeHeader) != mode {
						t.Fatalf("response status=%d transition size=%q, want %q; body=%s",
							rr.Code, rr.Header().Get(lifecycleTransitionSizeHeader), mode, rr.Body.String())
					}
					if mode == "" && len(rr.Header().Values(lifecycleTransitionSizeHeader)) != 0 {
						t.Error("absent response mode was synthesized")
					}
				})
			}
		})
	}
}
