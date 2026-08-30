package sigv4

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestTrailerGuardReader(t *testing.T) {
	const payload = "the final byte stays guarded"

	for _, bufferSize := range []int{1, 2, 3, 8, 32} {
		t.Run(fmt.Sprintf("valid/buffer=%d", bufferSize), func(t *testing.T) {
			guard := trailerGuardReader{r: strings.NewReader(payload)}
			got, err := readTrailerGuard(t, &guard, bufferSize)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if string(got) != payload {
				t.Fatalf("Read() = %q, want %q", got, payload)
			}
		})
	}

	validationErr := errors.New("validation failed")
	for _, bufferSize := range []int{1, 2, 3, 8, 32} {
		t.Run(fmt.Sprintf("invalid/buffer=%d", bufferSize), func(t *testing.T) {
			reader := &terminalErrorReader{
				Reader: strings.NewReader(payload),
				err:    validationErr,
			}
			guard := trailerGuardReader{r: reader}
			got, err := readTrailerGuard(t, &guard, bufferSize)
			if !errors.Is(err, validationErr) {
				t.Fatalf("Read() error = %v, want %v", err, validationErr)
			}
			if string(got) != payload[:len(payload)-1] {
				t.Fatalf("Read() = %q, want payload without final byte", got)
			}
		})
	}
}

func TestTrailerGuardReaderHandlesDataWithTerminalError(t *testing.T) {
	const payload = "terminal errors returned with data"
	validationErr := errors.New("validation failed")

	tests := []struct {
		name    string
		err     error
		want    string
		wantErr error
	}{
		{
			name: "EOF releases final byte",
			err:  io.EOF,
			want: payload,
		},
		{
			name:    "validation error withholds final byte",
			err:     validationErr,
			want:    payload[:len(payload)-1],
			wantErr: validationErr,
		},
	}

	for _, tc := range tests {
		for _, bufferSize := range []int{1, 2, 8, 32} {
			t.Run(fmt.Sprintf("%s/buffer=%d", tc.name, bufferSize), func(t *testing.T) {
				reader := &dataAndErrorReader{data: []byte(payload), err: tc.err}
				guard := trailerGuardReader{r: reader}
				got, err := readTrailerGuard(t, &guard, bufferSize)
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Read() error = %v, want %v", err, tc.wantErr)
				}
				if string(got) != tc.want {
					t.Fatalf("Read() = %q, want %q", got, tc.want)
				}
			})
		}
	}
}

func BenchmarkTrailerGuardReader(b *testing.B) {
	payload := make([]byte, 8<<20)

	for _, bufferSize := range []int{4 << 10, 32 << 10, 128 << 10} {
		b.Run(fmt.Sprintf("buffer=%dKiB", bufferSize>>10), func(b *testing.B) {
			buf := make([]byte, bufferSize)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				guard := trailerGuardReader{r: bytes.NewReader(payload)}
				total := 0
				for {
					n, err := guard.Read(buf)
					total += n
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						b.Fatalf("Read() error = %v", err)
					}
				}
				if total != len(payload) {
					b.Fatalf("read %d bytes, want %d", total, len(payload))
				}
			}
		})
	}
}

type terminalErrorReader struct {
	io.Reader
	err error
}

type dataAndErrorReader struct {
	data []byte
	err  error
	off  int
}

func (r *dataAndErrorReader) Read(p []byte) (int, error) {
	if r.off == len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	if r.off == len(r.data) {
		return n, r.err
	}
	return n, nil
}

func (r *terminalErrorReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		return n, nil
	}
	if errors.Is(err, io.EOF) {
		return 0, r.err
	}
	return 0, err
}

func readTrailerGuard(t *testing.T, guard *trailerGuardReader, bufferSize int) ([]byte, error) {
	t.Helper()

	buf := make([]byte, bufferSize)
	var got []byte
	for {
		n, err := guard.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return got, nil
			}
			return got, err
		}
		if n == 0 {
			t.Fatal("Read() made no progress")
		}
	}
}
