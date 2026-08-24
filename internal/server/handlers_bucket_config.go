package server

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/xmlhelper"
)

// The gateway has no per-user S3 identities: every object is owned by the
// gateway's upstream credentials and access is decided by LDAP groups. ACL
// reads therefore report a single synthetic owner with FULL_CONTROL.
const (
	gatewayOwnerID          = "s3gateway"
	gatewayOwnerDisplayName = "s3gateway"

	// maxBucketConfigBodyBytes bounds XML request bodies for bucket
	// configuration operations (far above any legitimate payload).
	maxBucketConfigBodyBytes = 1 << 20
)

func isUpstreamNotFound(err error) bool {
	var respErr *smithyhttp.ResponseError
	return errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusNotFound
}

// requireBucketExists heads the bucket upstream so gateway-local answers keep
// S3's NoSuchBucket semantics. It writes the error response and returns false
// when the bucket is not available.
func (s *Server) requireBucketExists(w http.ResponseWriter, r *http.Request, bucket string) bool {
	if _, err := s.up.HeadBucket(r.Context(), &s3.HeadBucketInput{Bucket: &bucket}); err != nil {
		if isUpstreamNotFound(err) {
			xmlhelper.WriteXMLError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		} else {
			xmlhelper.WriteUpstreamError(w, err)
		}
		return false
	}
	return true
}

// requireObjectExists heads the object upstream so canned per-object answers
// keep S3's NoSuchKey semantics.
func (s *Server) requireObjectExists(w http.ResponseWriter, r *http.Request, bucket, key string) bool {
	in := &s3.HeadObjectInput{Bucket: &bucket, Key: &key}
	if versionID := strings.TrimSpace(r.URL.Query().Get("versionId")); versionID != "" {
		in.VersionId = aws.String(versionID)
	}
	if _, err := s.up.HeadObject(r.Context(), in); err != nil {
		if isUpstreamNotFound(err) {
			xmlhelper.WriteXMLError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist")
		} else {
			xmlhelper.WriteUpstreamError(w, err)
		}
		return false
	}
	return true
}

func writeCannedFullControlACL(w http.ResponseWriter) {
	xw := xmlhelper.BeginXMLWriterResponse(w, http.StatusOK)
	defer xmlhelper.FlushXMLWriterResponse(xw)

	xmlhelper.EncodeS3RootStart(xw, "AccessControlPolicy")
	xw.Start("Owner")
	xw.Elem("ID", gatewayOwnerID)
	xw.Elem("DisplayName", gatewayOwnerDisplayName)
	xw.End("Owner")
	xw.Start("AccessControlList")
	xw.Start("Grant")
	xw.Start("Grantee",
		xml.Attr{Name: xml.Name{Local: "xmlns:xsi"}, Value: "http://www.w3.org/2001/XMLSchema-instance"},
		xml.Attr{Name: xml.Name{Local: "xsi:type"}, Value: "CanonicalUser"},
	)
	xw.Elem("ID", gatewayOwnerID)
	xw.Elem("DisplayName", gatewayOwnerDisplayName)
	xw.End("Grantee")
	xw.Elem("Permission", "FULL_CONTROL")
	xw.End("Grant")
	xw.End("AccessControlList")
	xw.End("AccessControlPolicy")
}

// aclWriteIsNoOp reports whether a Put*Acl request keeps full control with the
// owner, i.e. is safe to accept as a no-op. Anything that would grant access
// to other parties (public/authenticated canned ACLs, explicit grant headers,
// or an AccessControlPolicy request body) is not.
func aclWriteIsNoOp(r *http.Request, bucketLevel bool) bool {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-grant-") {
			return false
		}
	}
	// An AccessControlPolicy request body may carry grants; a non-zero (or
	// unknown) length body is therefore not a no-op.
	if r.ContentLength != 0 {
		return false
	}
	switch strings.TrimSpace(r.Header.Get("x-amz-acl")) {
	case "", "private":
		return true
	case "bucket-owner-read", "bucket-owner-full-control":
		// Object-only canned ACLs; the bucket owner is the gateway itself.
		return !bucketLevel
	default:
		return false
	}
}

func (s *Server) handleGetBucketACL(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	if !s.requireBucketExists(w, r, bucket) {
		return
	}
	writeCannedFullControlACL(w)
}

func (s *Server) handlePutBucketACL(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanWrite(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	if !aclWriteIsNoOp(r, true) {
		xmlhelper.WriteXMLError(w, http.StatusNotImplemented, "NotImplemented", "Only the private canned ACL is supported; access is managed via LDAP groups")
		return
	}
	if !s.requireBucketExists(w, r, bucket) {
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetObjectACL(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	if !s.requireObjectExists(w, r, bucket, key) {
		return
	}
	writeCannedFullControlACL(w)
}

func (s *Server) handlePutObjectACL(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanWrite(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	if !aclWriteIsNoOp(r, false) {
		xmlhelper.WriteXMLError(w, http.StatusNotImplemented, "NotImplemented", "Only owner-retaining canned ACLs are supported; access is managed via LDAP groups")
		return
	}
	if !s.requireObjectExists(w, r, bucket, key) {
		return
	}
	w.WriteHeader(http.StatusOK)
}

// bucketConfigReadKeys are bucket configuration sub-resources the gateway
// answers locally on GET: it has no policies, CORS, website, replication,
// logging, notifications or transfer acceleration of its own, and every
// request is authenticated, so public access is always fully blocked.
var bucketConfigReadKeys = []string{
	"policy",
	"policyStatus",
	"cors",
	"website",
	"replication",
	"logging",
	"notification",
	"requestPayment",
	"accelerate",
	"publicAccessBlock",
}

func (s *Server) handleBucketConfigRead(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	if !s.requireBucketExists(w, r, bucket) {
		return
	}

	switch key {
	case "policy", "policyStatus":
		xmlhelper.WriteXMLError(w, http.StatusNotFound, "NoSuchBucketPolicy", "The bucket policy does not exist")
	case "cors":
		xmlhelper.WriteXMLError(w, http.StatusNotFound, "NoSuchCORSConfiguration", "The CORS configuration does not exist")
	case "website":
		xmlhelper.WriteXMLError(w, http.StatusNotFound, "NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration")
	case "replication":
		xmlhelper.WriteXMLError(w, http.StatusNotFound, "ReplicationConfigurationNotFoundError", "The replication configuration was not found")
	case "logging":
		writeEmptyConfigElement(w, "BucketLoggingStatus")
	case "notification":
		writeEmptyConfigElement(w, "NotificationConfiguration")
	case "accelerate":
		writeEmptyConfigElement(w, "AccelerateConfiguration")
	case "requestPayment":
		xw := xmlhelper.BeginXMLWriterResponse(w, http.StatusOK)
		defer xmlhelper.FlushXMLWriterResponse(xw)
		xmlhelper.EncodeS3RootStart(xw, "RequestPaymentConfiguration")
		xw.Elem("Payer", "BucketOwner")
		xw.End("RequestPaymentConfiguration")
	case "publicAccessBlock":
		xw := xmlhelper.BeginXMLWriterResponse(w, http.StatusOK)
		defer xmlhelper.FlushXMLWriterResponse(xw)
		xmlhelper.EncodeS3RootStart(xw, "PublicAccessBlockConfiguration")
		xw.ElemBool("BlockPublicAcls", true)
		xw.ElemBool("IgnorePublicAcls", true)
		xw.ElemBool("BlockPublicPolicy", true)
		xw.ElemBool("RestrictPublicBuckets", true)
		xw.End("PublicAccessBlockConfiguration")
	default:
		xmlhelper.WriteXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
	}
}

func writeEmptyConfigElement(w http.ResponseWriter, name string) {
	xw := xmlhelper.BeginXMLWriterResponse(w, http.StatusOK)
	defer xmlhelper.FlushXMLWriterResponse(xw)
	xmlhelper.EncodeS3RootStart(xw, name)
	xw.End(name)
}

// ---------- Bucket encryption (proxied) ----------

type sseConfigXML struct {
	XMLName xml.Name     `xml:"ServerSideEncryptionConfiguration"`
	Rules   []sseRuleXML `xml:"Rule"`
}

type sseRuleXML struct {
	Apply            *sseByDefaultXML `xml:"ApplyServerSideEncryptionByDefault,omitempty"`
	BucketKeyEnabled *bool            `xml:"BucketKeyEnabled,omitempty"`
}

type sseByDefaultXML struct {
	SSEAlgorithm   string `xml:"SSEAlgorithm"`
	KMSMasterKeyID string `xml:"KMSMasterKeyID,omitempty"`
}

func (s *Server) handlePutBucketEncryption(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanCreateBucket(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	var doc sseConfigXML
	if err := xml.NewDecoder(io.LimitReader(r.Body, maxBucketConfigBodyBytes)).Decode(&doc); err != nil || len(doc.Rules) == 0 {
		xmlhelper.WriteXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid server-side encryption configuration")
		return
	}

	sseRules := make([]types.ServerSideEncryptionRule, 0, len(doc.Rules))
	for _, rule := range doc.Rules {
		var out types.ServerSideEncryptionRule
		if rule.Apply != nil {
			out.ApplyServerSideEncryptionByDefault = &types.ServerSideEncryptionByDefault{
				SSEAlgorithm: types.ServerSideEncryption(rule.Apply.SSEAlgorithm),
			}
			if rule.Apply.KMSMasterKeyID != "" {
				out.ApplyServerSideEncryptionByDefault.KMSMasterKeyID = aws.String(rule.Apply.KMSMasterKeyID)
			}
		}
		out.BucketKeyEnabled = rule.BucketKeyEnabled
		sseRules = append(sseRules, out)
	}

	_, err := s.up.PutBucketEncryption(r.Context(), &s3.PutBucketEncryptionInput{
		Bucket: &bucket,
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
			Rules: sseRules,
		},
	})
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetBucketEncryption(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanRead(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	out, err := s.up.GetBucketEncryption(r.Context(), &s3.GetBucketEncryptionInput{Bucket: &bucket})
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}

	xw := xmlhelper.BeginXMLWriterResponse(w, http.StatusOK)
	defer xmlhelper.FlushXMLWriterResponse(xw)
	xmlhelper.EncodeS3RootStart(xw, "ServerSideEncryptionConfiguration")
	if out.ServerSideEncryptionConfiguration != nil {
		for _, rule := range out.ServerSideEncryptionConfiguration.Rules {
			xw.Start("Rule")
			if def := rule.ApplyServerSideEncryptionByDefault; def != nil {
				xw.Start("ApplyServerSideEncryptionByDefault")
				xw.Elem("SSEAlgorithm", string(def.SSEAlgorithm))
				if def.KMSMasterKeyID != nil {
					xw.Elem("KMSMasterKeyID", *def.KMSMasterKeyID)
				}
				xw.End("ApplyServerSideEncryptionByDefault")
			}
			if rule.BucketKeyEnabled != nil {
				xw.ElemBool("BucketKeyEnabled", *rule.BucketKeyEnabled)
			}
			xw.End("Rule")
		}
	}
	xw.End("ServerSideEncryptionConfiguration")
}

func (s *Server) handleDeleteBucketEncryption(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := authz.RulesFromRequest(r)
	if !authz.CanDeleteBucket(rules, bucket) {
		xmlhelper.WriteXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	_, err := s.up.DeleteBucketEncryption(r.Context(), &s3.DeleteBucketEncryptionInput{Bucket: &bucket})
	if err != nil {
		xmlhelper.WriteUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
