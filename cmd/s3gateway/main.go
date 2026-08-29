// Package main provides the s3gateway executable.
package main

import (
	"os"

	"github.com/define42/s3gateway/internal/app"
)

func main() {
	os.Exit(app.Run())
}
