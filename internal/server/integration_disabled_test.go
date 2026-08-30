//go:build !integration

package server

import "testing"

func requireIntegration(tb testing.TB) {
	tb.Helper()
	tb.Skip("requires the integration build tag")
}
