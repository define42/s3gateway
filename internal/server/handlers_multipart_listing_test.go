package server

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	minio "github.com/minio/minio-go/v7"
	minioCredentials "github.com/minio/minio-go/v7/pkg/credentials"
)

type multipartListingDocument struct {
	XMLName            xml.Name               `xml:"ListMultipartUploadsResult"`
	Bucket             string                 `xml:"Bucket"`
	EncodingType       string                 `xml:"EncodingType,omitempty"`
	KeyMarker          string                 `xml:"KeyMarker,omitempty"`
	UploadIDMarker     string                 `xml:"UploadIdMarker,omitempty"`
	NextKeyMarker      string                 `xml:"NextKeyMarker,omitempty"`
	NextUploadIDMarker string                 `xml:"NextUploadIdMarker,omitempty"`
	Prefix             string                 `xml:"Prefix,omitempty"`
	Delimiter          string                 `xml:"Delimiter,omitempty"`
	MaxUploads         int                    `xml:"MaxUploads"`
	IsTruncated        bool                   `xml:"IsTruncated"`
	CommonPrefixes     []string               `xml:"CommonPrefixes>Prefix"`
	Uploads            []multipartListingItem `xml:"Upload"`
}

type multipartListingItem struct {
	Key      string `xml:"Key"`
	UploadID string `xml:"UploadId"`
}

func encodeMultipartListingName(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func writeMultipartListing(t *testing.T, w http.ResponseWriter, doc multipartListingDocument) {
	t.Helper()
	w.Header().Set("Content-Type", "application/xml")
	if err := xml.NewEncoder(w).Encode(doc); err != nil {
		t.Errorf("encode upstream multipart listing: %v", err)
	}
}

func TestListMultipartUploadsPreservesEncodingAndPagination(t *testing.T) {
	for _, encodingType := range []string{"url", ""} {
		name := encodingType
		if name == "" {
			name = "upstream omitted encoding"
		}
		t.Run(name, func(t *testing.T) {
			encode := func(value string) string { return value }
			if encodingType == "url" {
				encode = encodeMultipartListingName
			}
			want := multipartListingDocument{
				Bucket: "team2-bucket", EncodingType: encodingType,
				KeyMarker: encode("folder/first +%.txt"), UploadIDMarker: "upload-first",
				NextKeyMarker: encode("folder/last æ.txt"), NextUploadIDMarker: "upload-last",
				Prefix: encode("folder/"), Delimiter: encode("/"), MaxUploads: 2, IsTruncated: true,
				CommonPrefixes: []string{encode("folder/nested directory/")},
				Uploads:        []multipartListingItem{{Key: encode("folder/literal%2F +æ.txt"), UploadID: "upload-item"}},
			}
			gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || !r.URL.Query().Has("uploads") || r.URL.Query().Get("encoding-type") != "url" {
					t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
				}
				writeMultipartListing(t, w, want)
			})
			t.Cleanup(cleanup)
			req := httptest.NewRequest(http.MethodGet, "/team2-bucket?uploads&encoding-type=url", nil)
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			var got multipartListingDocument
			if err := xml.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			got.XMLName = xml.Name{}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("multipart response changed: got=%+v want=%+v", got, want)
			}
			if encodingType == "" && strings.Contains(rr.Body.String(), "<EncodingType>") {
				t.Fatal("gateway invented an upstream encoding type")
			}
		})
	}
}

func TestMinioMultipartListingsDecodeKeysAndAbortUploads(t *testing.T) {
	keys := []string{"folder/name with spaces.txt", "folder/literal%2F plus+ æ.txt"}
	uploadIDs := []string{"upload-first", "upload-second"}
	var aborts atomic.Int32
	var listingPages atomic.Int32
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.Method == http.MethodDelete {
			index := slices.Index(keys, strings.TrimPrefix(r.URL.Path, "/team2-bucket/"))
			if index < 0 || r.URL.Path != "/team2-bucket/"+keys[index] || q.Get("uploadId") != uploadIDs[index] {
				t.Errorf("incorrect abort target: %s", r.URL)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			aborts.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/team2-bucket" || !q.Has("uploads") || q.Get("encoding-type") != "url" {
			t.Errorf("unexpected multipart listing request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		doc := multipartListingDocument{Bucket: "team2-bucket", EncodingType: "url", MaxUploads: 1}
		index := 0
		if prefix := q.Get("prefix"); prefix != "" {
			index = slices.Index(keys, prefix)
			if index < 0 {
				t.Errorf("cleanup prefix was not decoded: %q", prefix)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		} else {
			listingPages.Add(1)
			if q.Get("key-marker") == "" {
				doc.IsTruncated = true
				doc.NextKeyMarker = encodeMultipartListingName(keys[0])
				doc.NextUploadIDMarker = uploadIDs[0]
			} else {
				if q.Get("key-marker") != keys[0] || q.Get("upload-id-marker") != uploadIDs[0] {
					t.Errorf("pagination markers were not decoded: %s", r.URL.RawQuery)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				index = 1
			}
		}
		doc.Uploads = []multipartListingItem{{Key: encodeMultipartListingName(keys[index]), UploadID: uploadIDs[index]}}
		writeMultipartListing(t, w, doc)
	})
	t.Cleanup(cleanup)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gw.ServeHTTP(w, reqWithRules(r, fullTeam2Rule()))
	}))
	t.Cleanup(front.Close)
	endpoint, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := minio.New(endpoint.Host, &minio.Options{
		Region: "us-east-1", Creds: minioCredentials.NewStaticV4("test-access", "test-secret", ""),
		Secure: false, BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for item := range client.ListIncompleteUploads(t.Context(), "team2-bucket", "", true) {
		if item.Err != nil {
			t.Fatal(item.Err)
		}
		listed = append(listed, item.Key)
	}
	if !slices.Equal(listed, keys) || listingPages.Load() != 2 {
		t.Fatalf("listed keys=%q, pages=%d; want keys=%q in two pages", listed, listingPages.Load(), keys)
	}
	for i, key := range keys {
		if err := client.RemoveIncompleteUpload(t.Context(), "team2-bucket", key); err != nil {
			t.Fatal(err)
		}
		if aborts.Load() != int32(i+1) {
			t.Fatalf("cleanup returned success without aborting %q: abort count=%d", key, aborts.Load())
		}
	}
}
