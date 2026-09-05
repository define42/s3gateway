package server

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/s3xml"
	"github.com/define42/s3gateway/internal/sigv4"
)

// These are the checksums of the standard test string "123456789".
var multipartChecksumCases = []struct {
	algorithm string
	value     string
}{
	{algorithm: "CRC32", value: "y/Q5Jg=="},
	{algorithm: "CRC32C", value: "4waSgw=="},
	{algorithm: "CRC64NVME", value: "rosUhgp5mIg="},
	{algorithm: "SHA1", value: "98O8HYCOBHMq32eZZczDTKeuNEE="},
	{algorithm: "SHA256", value: "FeKw08M4keuw8e9gnsQZQgwg4yDOlMZfvIwzEkSOsiU="},
}

type multipartChecksumRequest struct {
	header http.Header
	body   string
}

type multipartChecksumElement struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

func multipartChecksumStub(t *testing.T, headers http.Header, response string) (*Server, <-chan multipartChecksumRequest) {
	t.Helper()
	requests := make(chan multipartChecksumRequest, 1)
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream multipart request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- multipartChecksumRequest{header: r.Header.Clone(), body: string(body)}
		maps.Copy(w.Header(), headers)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, response)
	})
	t.Cleanup(cleanup)
	return gw, requests
}

func receiveMultipartChecksumRequest(t *testing.T, requests <-chan multipartChecksumRequest) multipartChecksumRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	default:
		t.Fatal("multipart request did not reach upstream")
		return multipartChecksumRequest{}
	}
}

func assertMultipartChecksumElements(t *testing.T, elements []multipartChecksumElement, algorithm, value string) {
	t.Helper()
	got := make(map[string]string)
	for _, element := range elements {
		got[element.XMLName.Local] = element.Value
	}
	for _, checksum := range multipartChecksumCases {
		name := "Checksum" + checksum.algorithm
		actual, present := got[name]
		if checksum.algorithm == algorithm {
			if !present || actual != value {
				t.Errorf("XML %s = %q (present=%v), want %q", name, actual, present, value)
			}
		} else if present {
			t.Errorf("unexpected XML checksum %s = %q", name, actual)
		}
	}
}

func TestMultipartChecksumsCreate(t *testing.T) {
	for _, tc := range multipartChecksumCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			checksumType := "COMPOSITE"
			if tc.algorithm == "CRC64NVME" {
				checksumType = "FULL_OBJECT"
			}
			headers := make(http.Header)
			headers.Set("x-amz-checksum-algorithm", tc.algorithm)
			headers.Set("x-amz-checksum-type", checksumType)
			gw, requests := multipartChecksumStub(t, headers, `<InitiateMultipartUploadResult><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`)
			req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploads", nil)
			req.Header = headers.Clone()
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("create status = %d, body = %s", rr.Code, rr.Body.String())
			}
			upstream := receiveMultipartChecksumRequest(t, requests)
			for name, values := range headers {
				if got := upstream.header.Get(name); got != values[0] {
					t.Errorf("upstream %s = %q, want %q", name, got, values[0])
				}
				if got := rr.Header().Get(name); got != values[0] {
					t.Errorf("response %s = %q, want %q", name, got, values[0])
				}
			}
		})
	}
}

func TestMultipartChecksumsUploadPart(t *testing.T) {
	for _, tc := range multipartChecksumCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			header := "x-amz-checksum-" + strings.ToLower(tc.algorithm)
			headers := make(http.Header)
			headers.Set(header, tc.value)
			headers.Set("ETag", `"part-etag"`)
			gw, requests := multipartChecksumStub(t, headers, "")
			req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object?uploadId=upload-1&partNumber=1", strings.NewReader("123456789"))
			req.Header.Set("x-amz-sdk-checksum-algorithm", tc.algorithm)
			req.Header.Set(header, tc.value)
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("upload part status = %d, body = %s", rr.Code, rr.Body.String())
			}
			upstream := receiveMultipartChecksumRequest(t, requests)
			if upstream.body != "123456789" {
				t.Errorf("upstream body = %q", upstream.body)
			}
			if got := upstream.header.Get(header); got != tc.value {
				t.Errorf("upstream checksum = %q, want %q", got, tc.value)
			}
			if got := rr.Header().Get(header); got != tc.value {
				t.Errorf("response checksum = %q, want %q", got, tc.value)
			}
			if got := rr.Header().Get("ETag"); got != `"part-etag"` {
				t.Errorf("response ETag = %q", got)
			}
		})
	}
}

func TestMultipartChecksumsUploadPartStreaming(t *testing.T) {
	for _, tc := range multipartChecksumCases {
		for _, sdkHeader := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/sdk-header=%v", tc.algorithm, sdkHeader), func(t *testing.T) {
				header := "x-amz-checksum-" + strings.ToLower(tc.algorithm)
				headers := make(http.Header)
				headers.Set(header, tc.value)
				gw, requests := multipartChecksumStub(t, headers, "")
				body := "9\r\n123456789\r\n0\r\n" + header + ":" + tc.value + "\r\n\r\n"
				req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object?uploadId=upload-1&partNumber=1", strings.NewReader(body))
				req.Header.Set("Content-Encoding", "aws-chunked")
				req.Header.Set("x-amz-content-sha256", sigv4.StreamingUnsignedPayloadTrailer)
				req.Header.Set("x-amz-decoded-content-length", "9")
				req.Header.Set("x-amz-trailer", header)
				if sdkHeader {
					req.Header.Set("x-amz-sdk-checksum-algorithm", tc.algorithm)
				}
				rr := httptest.NewRecorder()
				gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
				if rr.Code != http.StatusOK {
					t.Fatalf("streaming upload status = %d, body = %s", rr.Code, rr.Body.String())
				}
				upstream := receiveMultipartChecksumRequest(t, requests)
				if upstream.header.Get(header) != tc.value && !strings.Contains(upstream.body, header+":"+tc.value) {
					t.Errorf("upstream received no %s checksum: headers = %v, body = %q", tc.algorithm, upstream.header, upstream.body)
				}
				if got := rr.Header().Get(header); got != tc.value {
					t.Errorf("response checksum = %q, want %q", got, tc.value)
				}
			})
		}
	}
}

func TestChecksumUploadsStreamWithoutTemporaryStorage(t *testing.T) {
	for _, target := range []string{
		"/team2-bucket/object",
		"/team2-bucket/object?uploadId=upload-1&partNumber=1",
	} {
		t.Run(target, func(t *testing.T) {
			payload := strings.Repeat("stream checksum data ", 16_384)
			sum := crc32.ChecksumIEEE([]byte(payload))
			checksum := base64.StdEncoding.EncodeToString([]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)})
			upstreamStarted := make(chan struct{})
			gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				prefix := make([]byte, 1024)
				if _, err := io.ReadFull(r.Body, prefix); err != nil {
					t.Errorf("read upstream prefix: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				close(upstreamStarted)
				rest, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream tail: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				wireBody := string(prefix) + string(rest)
				if !strings.Contains(wireBody, "x-amz-checksum-crc32:"+checksum) {
					t.Errorf("upstream is missing the calculated checksum trailer")
				}
				w.Header().Set("x-amz-checksum-crc32", checksum)
				w.WriteHeader(http.StatusOK)
			})
			defer cleanup()
			// Configure the missing directory after the TLS stub has created its
			// certificate bundle. The upload itself must never require a spool.
			t.Setenv("TMPDIR", t.TempDir()+"/missing")
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			releaseTail := make(chan struct{})
			finishWriting := sync.OnceFunc(func() { close(releaseTail) })
			defer finishWriting()
			writerDone := make(chan error, 1)
			go func() {
				_, err := fmt.Fprintf(writer, "%x\r\n%s", len(payload), payload[:len(payload)/2])
				if err == nil {
					<-releaseTail
					_, err = fmt.Fprintf(writer, "%s\r\n0\r\nx-amz-checksum-crc32:%s\r\n\r\n", payload[len(payload)/2:], checksum)
				}
				_ = writer.CloseWithError(err)
				writerDone <- err
			}()
			req := httptest.NewRequest(http.MethodPut, target, reader)
			req.Header.Set("Content-Encoding", "aws-chunked")
			req.Header.Set("x-amz-content-sha256", sigv4.StreamingUnsignedPayloadTrailer)
			req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", len(payload)))
			req.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")
			req.Header.Set("x-amz-sdk-checksum-algorithm", "CRC32")
			rr := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
				close(done)
			}()
			select {
			case <-upstreamStarted:
			case <-done:
				t.Fatalf("upload ended before streaming upstream: status=%d body=%s", rr.Code, rr.Body.String())
			case <-time.After(10 * time.Second):
				t.Fatal("upstream did not receive data before the client finished its body")
			}
			finishWriting()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("streamed upload did not finish")
			}
			if err := <-writerDone; err != nil {
				t.Fatalf("write streamed upload: %v", err)
			}
			if rr.Code != http.StatusOK || rr.Header().Get("x-amz-checksum-crc32") != checksum {
				t.Fatalf("upload response = %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestUploadPartRejectsOversizedBody(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(http.ResponseWriter, *http.Request) {
		t.Error("oversized part reached upstream")
	})
	defer cleanup()
	req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object?uploadId=upload&partNumber=1", strings.NewReader("x"))
	req.ContentLength = maxUploadPartSize + 1
	req.Header.Set("x-amz-sdk-checksum-algorithm", "CRC32")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>EntityTooLarge</Code>") {
		t.Fatalf("oversized part response = %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMultipartChecksumsListParts(t *testing.T) {
	for _, tc := range multipartChecksumCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			checksumType := "COMPOSITE"
			if tc.algorithm == "CRC64NVME" {
				checksumType = "FULL_OBJECT"
			}
			field := "Checksum" + tc.algorithm
			response := `<ListPartsResult><Bucket>team2-bucket</Bucket><Key>object</Key><UploadId>upload-1</UploadId><ChecksumAlgorithm>` + tc.algorithm + `</ChecksumAlgorithm><ChecksumType>` + checksumType + `</ChecksumType><Part><PartNumber>1</PartNumber><ETag>"part-etag"</ETag><Size>9</Size><` + field + `>` + tc.value + `</` + field + `></Part></ListPartsResult>`
			gw, requests := multipartChecksumStub(t, nil, response)
			req := httptest.NewRequest(http.MethodGet, "/team2-bucket/object?uploadId=upload-1", nil)
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("list parts status = %d, body = %s", rr.Code, rr.Body.String())
			}
			_ = receiveMultipartChecksumRequest(t, requests)
			var result struct {
				Algorithm string `xml:"ChecksumAlgorithm"`
				Type      string `xml:"ChecksumType"`
				Parts     []struct {
					Fields []multipartChecksumElement `xml:",any"`
				} `xml:"Part"`
			}
			if err := xml.Unmarshal(rr.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Algorithm != tc.algorithm || result.Type != checksumType || len(result.Parts) != 1 {
				t.Fatalf("list parts response = %s", rr.Body.String())
			}
			assertMultipartChecksumElements(t, result.Parts[0].Fields, tc.algorithm, tc.value)
		})
	}
}

func TestMultipartChecksumsComplete(t *testing.T) {
	for _, tc := range multipartChecksumCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			checksumType := "FULL_OBJECT"
			objectChecksum := tc.value
			switch tc.algorithm {
			case "SHA1":
				checksumType = "COMPOSITE"
				objectChecksum = "zGcEPHvP9e6lVmvZsfPHT9mlz10=-1"
			case "SHA256":
				checksumType = "COMPOSITE"
				objectChecksum = "KSsNAHVmgy25S/rmic1w0at3KBH9RLn0nYVQ7p6mpJQ=-1"
			}
			field := "Checksum" + tc.algorithm
			response := `<CompleteMultipartUploadResult><ETag>"complete-etag"</ETag><` + field + `>` + objectChecksum + `</` + field + `><ChecksumType>` + checksumType + `</ChecksumType></CompleteMultipartUploadResult>`
			gw, requests := multipartChecksumStub(t, nil, response)
			body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"part-etag"</ETag><` + field + `>` + tc.value + `</` + field + `></Part></CompleteMultipartUpload>`
			req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1", strings.NewReader(body))
			header := "x-amz-checksum-" + strings.ToLower(tc.algorithm)
			req.Header.Set(header, objectChecksum)
			req.Header.Set("x-amz-checksum-type", checksumType)
			req.Header.Set("x-amz-mp-object-size", "9")
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("complete status = %d, body = %s", rr.Code, rr.Body.String())
			}
			upstream := receiveMultipartChecksumRequest(t, requests)
			for name, want := range map[string]string{header: objectChecksum, "x-amz-checksum-type": checksumType, "x-amz-mp-object-size": "9"} {
				if got := upstream.header.Get(name); got != want {
					t.Errorf("upstream %s = %q, want %q", name, got, want)
				}
			}
			var sent struct {
				Parts []struct {
					Fields []multipartChecksumElement `xml:",any"`
				} `xml:"Part"`
			}
			if err := xml.Unmarshal([]byte(upstream.body), &sent); err != nil {
				t.Fatal(err)
			}
			if len(sent.Parts) != 1 {
				t.Fatalf("upstream part count = %d", len(sent.Parts))
			}
			assertMultipartChecksumElements(t, sent.Parts[0].Fields, tc.algorithm, tc.value)
			var result struct {
				Type   string                     `xml:"ChecksumType"`
				Fields []multipartChecksumElement `xml:",any"`
			}
			if err := xml.Unmarshal(rr.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Type != checksumType {
				t.Errorf("response ChecksumType = %q", result.Type)
			}
			assertMultipartChecksumElements(t, result.Fields, tc.algorithm, objectChecksum)
		})
	}
}

func TestMultipartChecksumsAbsent(t *testing.T) {
	for _, tc := range []struct {
		name, method, target, body, response string
	}{
		{name: "create", method: http.MethodPost, target: "/team2-bucket/object?uploads", response: `<InitiateMultipartUploadResult><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`},
		{name: "upload part", method: http.MethodPut, target: "/team2-bucket/object?uploadId=upload-1&partNumber=1", body: "123456789"},
		{name: "list parts", method: http.MethodGet, target: "/team2-bucket/object?uploadId=upload-1", response: `<ListPartsResult><Part><PartNumber>1</PartNumber><ETag>"part-etag"</ETag><Size>9</Size></Part></ListPartsResult>`},
		{name: "complete", method: http.MethodPost, target: "/team2-bucket/object?uploadId=upload-1", body: completeMultipartDocument(1, "part-etag"), response: `<CompleteMultipartUploadResult><ETag>"complete-etag"</ETag></CompleteMultipartUploadResult>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, requests := multipartChecksumStub(t, nil, tc.response)
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			upstream := receiveMultipartChecksumRequest(t, requests)
			for _, headers := range []http.Header{upstream.header, rr.Header()} {
				for name := range headers {
					if strings.Contains(strings.ToLower(name), "checksum") || strings.EqualFold(name, "x-amz-mp-object-size") {
						t.Errorf("unexpected optional header %s = %q", name, headers.Values(name))
					}
				}
			}
			if strings.Contains(upstream.body, "<Checksum") || strings.Contains(rr.Body.String(), "<Checksum") {
				t.Errorf("unexpected checksum XML: request = %s, response = %s", upstream.body, rr.Body.String())
			}
		})
	}
}

func TestMultipartChecksumsValidation(t *testing.T) {
	for _, tc := range []struct {
		name, target, body, header, value, code string
	}{
		{name: "invalid creation type", target: "/team2-bucket/object?uploads", header: "x-amz-checksum-type", value: "INVALID", code: "InvalidArgument"},
		{name: "invalid completion type", header: "x-amz-checksum-type", value: "INVALID", code: "InvalidArgument"},
		{name: "negative size", header: "x-amz-mp-object-size", value: "-1", code: "InvalidArgument"},
		{name: "noninteger size", header: "x-amz-mp-object-size", value: "1.5", code: "InvalidArgument"},
		{name: "overflow size", header: "x-amz-mp-object-size", value: "9223372036854775808", code: "InvalidArgument"},
		{name: "malformed XML", body: `<CompleteMultipartUpload><Part><ChecksumCRC32>`, code: "MalformedXML"},
		{name: "oversized checksum", body: `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag><ChecksumCRC32>` + strings.Repeat("a", 257) + `</ChecksumCRC32></Part></CompleteMultipartUpload>`, code: "MalformedXML"},
		{name: "unsupported checksum element", body: `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag><ChecksumSHA512>incorrect</ChecksumSHA512></Part></CompleteMultipartUpload>`, code: "MalformedXML"},
		{name: "unsupported root checksum", body: `<CompleteMultipartUpload><ChecksumSHA512>incorrect</ChecksumSHA512><Part><PartNumber>1</PartNumber><ETag>etag</ETag></Part></CompleteMultipartUpload>`, code: "MalformedXML"},
		{name: "empty checksum element", body: `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag><ChecksumCRC32/></Part></CompleteMultipartUpload>`, code: "MalformedXML"},
		{name: "duplicate checksum element", body: `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag><ChecksumCRC32>AAAAAA==</ChecksumCRC32><ChecksumCRC32>BBBBBB==</ChecksumCRC32></Part></CompleteMultipartUpload>`, code: "MalformedXML"},
		{name: "nested checksum element", body: `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag><ChecksumCRC32>AAAAAA==<ChecksumSHA512>incorrect</ChecksumSHA512></ChecksumCRC32></Part></CompleteMultipartUpload>`, code: "MalformedXML"},
		{name: "checksum nested in ETag", body: `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag<ChecksumSHA512>incorrect</ChecksumSHA512></ETag></Part></CompleteMultipartUpload>`, code: "MalformedXML"},
		{name: "checksum nested in part number", body: `<CompleteMultipartUpload><Part><PartNumber>1<ChecksumSHA512>incorrect</ChecksumSHA512></PartNumber><ETag>etag</ETag></Part></CompleteMultipartUpload>`, code: "MalformedXML"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, requests := multipartChecksumStub(t, nil, `<CompleteMultipartUploadResult/>`)
			if tc.target == "" {
				tc.target = "/team2-bucket/object?uploadId=upload-1"
			}
			if tc.body == "" {
				tc.body = completeMultipartDocument(1, "part-etag")
			}
			req := httptest.NewRequest(http.MethodPost, tc.target, strings.NewReader(tc.body))
			if tc.header != "" {
				req.Header.Set(tc.header, tc.value)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>"+tc.code+"</Code>") {
				t.Errorf("status = %d, want %d; body = %s", rr.Code, http.StatusBadRequest, rr.Body.String())
			}
			select {
			case <-requests:
				t.Error("invalid multipart request reached upstream")
			default:
			}
		})
	}
}

func TestMultipartChecksumsXMLLimits(t *testing.T) {
	for _, tc := range multipartChecksumCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			for _, size := range []int{256, 257} {
				t.Run(fmt.Sprintf("bytes=%d", size), func(t *testing.T) {
					field := "Checksum" + tc.algorithm
					body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag><` + field + `>` + strings.Repeat("a", size) + `</` + field + `></Part></CompleteMultipartUpload>`
					_, err := decodeCompleteMultipartUpload(strings.NewReader(body))
					if size == 256 && err != nil {
						t.Fatalf("checksum at field limit rejected: %v", err)
					}
					if size == 257 && !errors.Is(err, s3xml.ErrXMLFieldTooLong) {
						t.Fatalf("oversized checksum error = %v, want %v", err, s3xml.ErrXMLFieldTooLong)
					}
				})
			}
		})
	}
	t.Run("ten thousand parts with checksum fields", func(t *testing.T) {
		var body strings.Builder
		body.WriteString("<CompleteMultipartUpload>")
		for i := 1; i <= 10_000; i++ {
			fmt.Fprintf(&body, "<Part><PartNumber>%d</PartNumber><ETag>etag</ETag>", i)
			for _, tc := range multipartChecksumCases {
				fmt.Fprintf(&body, "<Checksum%s>%s</Checksum%s>", tc.algorithm, tc.value, tc.algorithm)
			}
			body.WriteString("</Part>")
		}
		body.WriteString("</CompleteMultipartUpload>")
		upload, err := decodeCompleteMultipartUpload(strings.NewReader(body.String()))
		if err != nil {
			t.Fatalf("maximum multipart manifest rejected: %v", err)
		}
		if len(upload.Parts) != 10_000 {
			t.Fatalf("decoded %d parts, want 10000", len(upload.Parts))
		}
	})
}
