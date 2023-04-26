package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/go-kit/log/level"
	"github.com/iancoleman/strcase"
)

const (
	bucketNamingRulesDescription string = `
	The following rules apply for naming buckets in Amazon S3:
		* Bucket names must be unique.
		* Bucket names cannot be formatted as IP address.
		* Bucket names can be between 3 and 63 characters long.
		* Bucket names must not contain uppercase characters or underscores.
		* Bucket names must start and end with a lowercase letter or number.
`

	// See doc about BucketPolicyVersion https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
	bucketPolicyVersion string = "2012-10-17"
)

var (
	bucketPolicyWriteActions = []string{
		"s3:AbortMultipartUpload",
		"s3:CreateBucket",
		"s3:DeleteBucket",
		"s3:DeleteBucketPolicy",
		"s3:DeleteBucketWebsite",
		"s3:DeleteObject",
		"s3:DeleteObjectVersion",
		"s3:DeleteReplicationConfiguration",
		"s3:PutAccelerateConfiguration",
		"s3:PutBucketAcl",
		"s3:PutBucketCORS",
		"s3:PutBucketLogging",
		"s3:PutBucketNotification",
		"s3:PutBucketPolicy",
		"s3:PutBucketRequestPayment",
		"s3:PutBucketTagging",
		"s3:PutBucketVersioning",
		"s3:PutBucketWebsite",
		"s3:PutLifecycleConfiguration",
		"s3:PutObject",
		"s3:PutObjectAcl",
		"s3:PutObjectVersionAcl",
		"s3:PutReplicationConfiguration",
		"s3:RestoreObject",
	}

	bucketPolicyReadActions = []string{
		"s3:GetAccelerateConfiguration",
		"s3:GetBucketAcl",
		"s3:GetBucketCORS",
		"s3:GetBucketLocation",
		"s3:GetBucketLogging",
		"s3:GetBucketNotification",
		"s3:GetBucketPolicy",
		"s3:GetBucketRequestPayment",
		"s3:GetBucketTagging",
		"s3:GetBucketVersioning",
		"s3:GetBucketWebsite",
		"s3:GetLifecycleConfiguration",
		"s3:GetObject",
		"s3:GetObjectAcl",
		"s3:GetObjectTorrent",
		"s3:GetObjectVersion",
		"s3:GetObjectVersionAcl",
		"s3:GetObjectVersionTorrent",
		"s3:GetReplicationConfiguration",
		"s3:ListAllMyBuckets",
		"s3:ListBucket",
		"s3:ListBucketMultipartUploads",
		"s3:ListBucketVersions",
		"s3:ListMultipartUploadParts",
	}
)

type Bucket struct {
	Acl            BucketAcl       `yaml:"acl"`
	AclType        string          `yaml:"acl_type,omitempty"`
	BucketType     string          `yaml:"bucket_type,omitempty"`
	LifecycleRules []LifecycleRule `yaml:"lifecycle_rules"`
	LifecycleType  string          `yaml:"lifecycle_type,omitempty"`
	Versioning     string          `yaml:"versioning"`
	VersioningType string          `yaml:"versioning_type,omitempty"`
	name           string
	ctx            context.Context
}

type BucketAcl struct {
	Grants AclGrants `yaml:"grants"`
	Owner  AclOwner  `yaml:"owner"`
}

type LifecycleRule struct {
	ExpirationDays int32  `yaml:"cur_ver_expiration_days"`
	Id             string `yaml:"id"`
	NonCurrentDays int32  `yaml:"non_cur_ver_expiration_days"`
	Prefix         string `yaml:"prefix"`
	Status         string `yaml:"status"`
}

type buckets map[string]Bucket

type BucketPolicyPrincipal struct {
	PrincipalType []string `json:"AWS"`
}

type BucketPolicyStatement struct {
	Sid       string                `json:"Sid"`
	Action    []string              `json:"Action"`
	Effect    string                `json:"Effect"`
	Resource  []string              `json:"Resource"`
	Principal BucketPolicyPrincipal `json:"Principal"`
}

type BucketPolicy struct {
	Id        string                  `json:"Id"`
	Version   string                  `json:"Version"`
	Statement []BucketPolicyStatement `json:"Statement"`
}

type AclGrants struct {
	FullControl []string `yaml:"full_control"`
	Read        []string `yaml:"read"`
	Write       []string `yaml:"write"`
}

type AclOwner struct {
	DisplayName string `yaml:"display_name"`
	Id          string `yaml:"id"`
}

type s3ListBucketsAPI interface {
	ListBuckets(ctx context.Context,
		params *s3.ListBucketsInput,
		optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

type s3GetBucketAclAPI interface {
	GetBucketAcl(ctx context.Context,
		params *s3.GetBucketAclInput,
		optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
}

type s3GetBucketPolicyAPI interface {
	GetBucketPolicy(ctx context.Context,
		params *s3.GetBucketPolicyInput,
		optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
}

type s3GetBucketLfcAPI interface {
	GetBucketLifecycleConfiguration(ctx context.Context,
		params *s3.GetBucketLifecycleConfigurationInput,
		optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
}

type s3GetBucketVerAPI interface {
	GetBucketVersioning(ctx context.Context,
		params *s3.GetBucketVersioningInput,
		optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
}

type s3CreateBucketAPI interface {
	CreateBucket(ctx context.Context,
		params *s3.CreateBucketInput,
		optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error)
}

type s3DeleteBucketLifecycleAPI interface {
	DeleteBucketLifecycle(ctx context.Context,
		params *s3.DeleteBucketLifecycleInput,
		optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error)
}

type s3DeleteBucketPolicyAPI interface {
	DeleteBucketPolicy(ctx context.Context,
		params *s3.DeleteBucketPolicyInput,
		optFns ...func(*s3.Options)) (*s3.DeleteBucketPolicyOutput, error)
}

type s3PutBucketVerAPI interface {
	PutBucketVersioning(ctx context.Context,
		params *s3.PutBucketVersioningInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error)
}

// bucket ACL not supported yet in Ceph RGW S3
type s3PutBucketAclAPI interface {
	PutBucketAcl(ctx context.Context,
		params *s3.PutBucketAclInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error)
}

type s3PutBucketPolicyAPI interface {
	PutBucketPolicy(ctx context.Context,
		params *s3.PutBucketPolicyInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketPolicyOutput, error)
}

type s3PutBucketLifecycleConfigurationAPI interface {
	PutBucketLifecycleConfiguration(ctx context.Context,
		params *s3.PutBucketLifecycleConfigurationInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error)
}

func listBuckets(c context.Context, api s3ListBucketsAPI, input *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	return api.ListBuckets(c, input)
}

func getBucketAcl(c context.Context, api s3GetBucketAclAPI, input *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
	return api.GetBucketAcl(c, input)
}

func getBucketPolicy(c context.Context, api s3GetBucketPolicyAPI, input *s3.GetBucketPolicyInput) (*s3.GetBucketPolicyOutput, error) {
	return api.GetBucketPolicy(c, input)
}

func getBucketLifecycleConfiguration(c context.Context, api s3GetBucketLfcAPI, input *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return api.GetBucketLifecycleConfiguration(c, input)
}

func getBucketVersioning(c context.Context, api s3GetBucketVerAPI, input *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
	return api.GetBucketVersioning(c, input)
}

func createBucket(c context.Context, api s3CreateBucketAPI, input *s3.CreateBucketInput) (*s3.CreateBucketOutput, error) {
	return api.CreateBucket(c, input)
}

func deleteBucketLifecycle(c context.Context, api s3DeleteBucketLifecycleAPI, input *s3.DeleteBucketLifecycleInput) (*s3.DeleteBucketLifecycleOutput, error) {
	return api.DeleteBucketLifecycle(c, input)
}

func deleteBucketPolicy(c context.Context, api s3DeleteBucketPolicyAPI, input *s3.DeleteBucketPolicyInput) (*s3.DeleteBucketPolicyOutput, error) {
	return api.DeleteBucketPolicy(c, input)
}

func putBucketVersioning(c context.Context, api s3PutBucketVerAPI, input *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error) {
	return api.PutBucketVersioning(c, input)
}

// bucket ACL not supported yet in Ceph RGW S3
func putBucketAcl(c context.Context, api s3PutBucketAclAPI, input *s3.PutBucketAclInput) (*s3.PutBucketAclOutput, error) {
	return api.PutBucketAcl(c, input)
}

func putBucketPolicy(c context.Context, api s3PutBucketPolicyAPI, input *s3.PutBucketPolicyInput) (*s3.PutBucketPolicyOutput, error) {
	return api.PutBucketPolicy(c, input)
}

func putBucketLifecycleConfiguration(c context.Context, api s3PutBucketLifecycleConfigurationAPI, input *s3.PutBucketLifecycleConfigurationInput) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	return api.PutBucketLifecycleConfiguration(c, input)
}

// Get ACLs for bucket
// Warning: Bucket ACLs not supported yet in Ceph
func (b *Bucket) parseBucketAcl(c *Collector, aclResult *s3.GetBucketAclOutput) {
	level.Debug(c.Logger).Log("msg", "show ACL", "bucket", b.name, "value", fmt.Sprintf("%+v", *aclResult))

	for _, grants := range aclResult.Grants {
		switch gp := grants.Permission; gp {
		case "FULL_CONTROL":
			b.Acl.Grants.FullControl = append(b.Acl.Grants.FullControl, *grants.Grantee.ID)
		case "READ":
			b.Acl.Grants.Read = append(b.Acl.Grants.Read, *grants.Grantee.ID)
		case "WRITE":
			b.Acl.Grants.Write = append(b.Acl.Grants.Write, *grants.Grantee.ID)
		default:
			level.Warn(c.Logger).Log("msg", "permission type unsupported. Skip permission type", "bucket", b.name, "value", grants.Permission)
		}
	}

	b.Acl.Owner.DisplayName = *aclResult.Owner.DisplayName
	b.Acl.Owner.Id = *aclResult.Owner.ID
}

// Get ACLs for bucket
// Warning: Bucket ACLs not supported yet in Ceph
func (b *Bucket) getBucketAcl(c *Collector) error {
	var err error

	aclResult, err := getBucketAcl(c.ctx, c.CephClient, &s3.GetBucketAclInput{
		Bucket: &b.name,
	})

	if err != nil {
		level.Error(c.Logger).Log("msg", "error get bucket ACL", "bucket", b.name, "error", err.Error())

		b.AclType = "error"

		return err
	}

	b.parseBucketAcl(c, aclResult)

	return nil
}

func (b *Bucket) parseBucketPolicy(c *Collector, polResult *s3.GetBucketPolicyOutput, err error) error {
	if err != nil {
		var ae smithy.APIError

		if errors.As(err, &ae) {
			if ae.ErrorCode() == "NoSuchBucketPolicy" {
				level.Debug(c.Logger).Log("msg", "doesn't have bucket policy", "bucket", b.name)

				return nil
			} else {
				level.Error(c.Logger).Log("msg", "API error", "code", ae.ErrorCode(), "message", ae.ErrorMessage(), "error", ae.ErrorFault().String())

				b.AclType = "error"

				return err
			}
		} else {
			level.Error(c.Logger).Log("msg", "error get bucket policies", "bucket", b.name, "error", err.Error())

			b.AclType = "error"

			return err
		}
	}

	level.Debug(c.Logger).Log("msg", "show bucket policies", "bucket", b.name, "value", fmt.Sprintf("%+v", *polResult.Policy))

	var bp BucketPolicy

	err = json.Unmarshal([]byte(*polResult.Policy), &bp)

	if err != nil {
		level.Error(c.Logger).Log("msg", "error unmarshal Bucket policies", "bucket", b.name, "error", err.Error())

		b.AclType = "error"

		return err
	}

	level.Debug(c.Logger).Log("msg", "show bucket policies struct", "bucket", b.name, "value", fmt.Sprintf("%+v", bp))

	for _, st := range bp.Statement {
		switch statActionArray := st.Action; {
		case keyInArray(statActionArray, "s3:*"):
			b.Acl.Grants.FullControl = getUsersFromPrincipalArray(st.Principal.PrincipalType)
			// Always add owner
			if !keyInArray(b.Acl.Grants.FullControl, b.Acl.Owner.Id) {
				b.Acl.Grants.FullControl = append(b.Acl.Grants.FullControl, b.Acl.Owner.Id)
			}
		case (keyInArray(statActionArray, "s3:GetObject") && !keyInArray(statActionArray, "s3:PutObject")):
			b.Acl.Grants.Read = getUsersFromPrincipalArray(st.Principal.PrincipalType)
		case keyInArray(statActionArray, "s3:PutObject"):
			b.Acl.Grants.Write = getUsersFromPrincipalArray(st.Principal.PrincipalType)
		default:
			level.Error(c.Logger).Log("msg", "bucket policy statement error", "bucket", b.name, "value", fmt.Sprintf("%+v", statActionArray), "error", "action type unsupported")
		}
	}

	level.Debug(c.Logger).Log("msg", "ACL updated from bucket policies", "bucket", b.name, "value", fmt.Sprintf("%+v", b.Acl))

	return nil
}

// Get bucket's policy and rewrite ACL rules from bucket policies
func (b *Bucket) getBucketPolicy(c *Collector) error {
	var err error

	polResult, err := getBucketPolicy(c.ctx, c.CephClient, &s3.GetBucketPolicyInput{
		Bucket: &b.name,
	})

	err = b.parseBucketPolicy(c, polResult, err)

	return err
}

func (b *Bucket) parseBucketVersioning(c *Collector, vResult *s3.GetBucketVersioningOutput) {
	if len(vResult.Status) > 0 {
		b.Versioning = strings.ToLower(string(vResult.Status))
	} else {
		b.Versioning = "suspended"
	}

}

// Get bucket's versioning status
func (b *Bucket) getBucketVersioning(c *Collector) error {
	var err error

	// Get Bucket versioning status
	vResult, err := getBucketVersioning(c.ctx, c.CephClient, &s3.GetBucketVersioningInput{
		Bucket: aws.String(b.name),
	})

	if err != nil {
		level.Error(c.Logger).Log("msg", "error get versioning configuration", "error", err.Error())

		b.VersioningType = "error"

		return err
	}

	b.parseBucketVersioning(c, vResult)

	return nil
}

func (b *Bucket) parseBucketLifecycleConfiguration(c *Collector, lfResult *s3.GetBucketLifecycleConfigurationOutput, err error) {
	if err != nil {
		var ae smithy.APIError

		if errors.As(err, &ae) {
			if ae.ErrorCode() == "NoSuchLifecycleConfiguration" {
				level.Debug(c.Logger).Log("msg", "doesn't have Lifecycle configuration", "bucket", b.name)

				return
			} else {
				level.Error(c.Logger).Log("msg", "API error", "code", ae.ErrorCode(), "message", ae.ErrorMessage(), "error", ae.ErrorFault().String())

				return
			}
		} else {
			level.Error(c.Logger).Log("msg", "error get bucket lifecycle", "bucket", b.name, "error", err.Error())

			return
		}
	}

	if lfResult == nil {
		return
	}

	level.Debug(c.Logger).Log("msg", "show lifecycle configuration", "bucket", b.name, "value", fmt.Sprintf("%+v", *lfResult))

	for _, r := range lfResult.Rules {
		var lfr LifecycleRule

		if r.Filter != nil {
			// New version of Ceph return "Prefix" inside struct "Filter"
			if _, ok := r.Filter.(*types.LifecycleRuleFilterMemberPrefix); ok {
				lfr.Prefix = r.Filter.(*types.LifecycleRuleFilterMemberPrefix).Value
			} else {
				level.Error(c.Logger).Log("msg", "lifecycle rule of filter type not supported!", "bucket", b.name, "name", *r.ID, "type", fmt.Sprintf("%T", r.Filter))
			}

		} else if r.Prefix != nil {
			// Old version of Ceph return "Prefix" inside struct "LifecycleRule"
			lfr.Prefix = *r.Prefix
		}

		lfr.ExpirationDays = r.Expiration.Days
		lfr.Id = *r.ID

		if r.NoncurrentVersionExpiration != nil {

			lfr.NonCurrentDays = r.NoncurrentVersionExpiration.NoncurrentDays
		} else {

			lfr.NonCurrentDays = -1
		}

		lfr.Status = strings.ToLower(string(r.Status))

		b.LifecycleRules = append(b.LifecycleRules, lfr)
	}

}

// Get bucket's Lifecycle Configuration
func (b *Bucket) getBucketLifecycleConfiguration(c *Collector) error {
	var err error

	lfResult, err := getBucketLifecycleConfiguration(c.ctx, c.CephClient, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(b.name),
	})

	b.parseBucketLifecycleConfiguration(c, lfResult, err)

	return err
}

// Apply bucket's policy
func (b *Bucket) applyBucketPolicy(c *Collector) error {
	var err error
	var retryCount int
	var out interface{}

	level.Debug(c.Logger).Log("msg", "update bucket policy", "bucket", b.name)

	// Create Bucket policy JSON
	BucketPolicy, err := b.createBucketPolicy(c)

	if err != nil {
		level.Error(c.Logger).Log("msg", "error marshaling Bucket policy to JSON", "bucket", b.name, "error", err.Error())

		return err
	}

	level.Debug(c.Logger).Log("msg", "show bucket policy", "bucket", b.name, "value", fmt.Sprintf("%+v", BucketPolicy))

	retryCount = c.RetryNum

	for retryCount > 0 {

		if len(BucketPolicy) == 0 {
			// delete bucket policy
			level.Debug(c.Logger).Log("msg", "delete bucket policy", "bucket", b.name)

			out, err = deleteBucketPolicy(c.ctx, c.CephClient, &s3.DeleteBucketPolicyInput{
				Bucket: aws.String(b.name),
			})
		} else {
			// put bucket policy
			level.Debug(c.Logger).Log("msg", "put  bucket policy", "bucket", b.name)

			out, err = putBucketPolicy(c.ctx, c.CephClient, &s3.PutBucketPolicyInput{
				Bucket: aws.String(b.name),
				Policy: aws.String(BucketPolicy),
			})
		}

		retryCount--

		if err != nil {
			if retryCount > 0 {
				level.Warn(c.Logger).Log("msg", "error applying Bucket policy", "bucket", b.name, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "error", err.Error())

				time.Sleep(1 * time.Second)
			} else {
				level.Error(c.Logger).Log("msg", "error applying lifecycle configuration", "error", err.Error())

				return err
			}

		} else {

			break
		}
	}

	return nil
}

// Fill bucket's policy array
func (b *Bucket) fillBucketPolicy(op string, grants []string, bpsa []BucketPolicyStatement, c *Collector) []BucketPolicyStatement {

	var (
		bps              BucketPolicyStatement
		actionPrincipals []string
		policyActions    []string
		fullName         string
	)

	switch op {
	case "full":
		policyActions = []string{
			"s3:*",
		}
		fullName = "FULL_CONTROL"
	case "read":
		policyActions = bucketPolicyReadActions
		fullName = "READ"
	case "write":
		policyActions = bucketPolicyWriteActions
		policyActions = append(policyActions, bucketPolicyReadActions...)
		fullName = "WRITE"
	}

	for _, u := range grants {
		switch s := u; {
		case s == b.Acl.Owner.Id:
			level.Debug(c.Logger).Log("msg", "skip bucket owner", "value", s)
		case strings.Contains(s, ":"):
			actionPrincipals = append(actionPrincipals, fmt.Sprintf("arn:aws:iam:::user/%s", u))
		default:
			actionPrincipals = append(actionPrincipals, fmt.Sprintf("arn:aws:iam:::user/%s:%s", b.Acl.Owner.Id, u))
		}
	}

	bps = BucketPolicyStatement{
		Sid:    fmt.Sprintf("%s-%s-%v", b.name, op, time.Now().UnixNano()),
		Action: policyActions,
		Effect: "Allow",
		Resource: []string{
			fmt.Sprintf("arn:aws:s3:::%s", b.name),
		},
		Principal: BucketPolicyPrincipal{
			PrincipalType: actionPrincipals,
		},
	}

	if len(bps.Principal.PrincipalType) > 0 {
		bpsa = append(bpsa, bps)

		return bpsa
	}

	level.Debug(c.Logger).Log("msg", "bucket policy statement doesn't have principals. Skip. Show bucket policy template", "policy", fullName, "bucket", b.name, "value", fmt.Sprintf("%+v", bps))

	return bpsa
}

// Create bucket's policy JSON string
func (b *Bucket) createBucketPolicy(c *Collector) (string, error) {
	var (
		err  error
		bpsa []BucketPolicyStatement
		j    []byte
	)

	if len(b.Acl.Grants.FullControl) > 0 {

		bpsa = b.fillBucketPolicy("full", b.Acl.Grants.FullControl, bpsa, c)
	}

	if len(b.Acl.Grants.Read) > 0 {

		bpsa = b.fillBucketPolicy("read", b.Acl.Grants.Read, bpsa, c)
	}

	if len(b.Acl.Grants.Write) > 0 {

		bpsa = b.fillBucketPolicy("write", b.Acl.Grants.Write, bpsa, c)
	}

	if len(bpsa) == 0 {
		err = errors.New("bucket policy is blank")

		return "", err
	}

	bp := BucketPolicy{
		Version:   bucketPolicyVersion,
		Id:        fmt.Sprintf("Policy-%s-%v", b.name, time.Now().UnixNano()),
		Statement: bpsa,
	}

	j, err = json.MarshalIndent(bp, "", "  ")

	return string(j), err
}

func (b buckets) hasKey(k string) bool {
	_, ok := b[k]

	return ok
}

func compareBuckets(fc buckets, sc buckets, c *Collector) (buckets, bool) {
	var bucketsUpdated bool

	newBuckets := make(buckets)

	level.Debug(c.Logger).Log("msg", "compare local and server's configurations")

	for k, v := range fc {

		if sc.hasKey(k) {
			level.Debug(c.Logger).Log("msg", "bucket already exist on server", "bucket", k)
			level.Debug(c.Logger).Log("msg", "add server struct to result configuration", "value", fmt.Sprintf("%+v", sc[k]))

			newCfgBucket := sc[k]

			// Compare ACLs
			if !aclIsEqual(v, sc[k], k, c.Logger) {
				level.Debug(c.Logger).Log("msg", "update ACL for bucket", "bucket", k)

				newCfgBucket.Acl.Grants.FullControl = v.Acl.Grants.FullControl
				newCfgBucket.Acl.Grants.Read = v.Acl.Grants.Read
				newCfgBucket.Acl.Grants.Write = v.Acl.Grants.Write
				newCfgBucket.AclType = "updated"
				bucketsUpdated = true
			}

			// Compare versioning
			if sc[k].Versioning != v.Versioning {
				level.Debug(c.Logger).Log("msg", "versioning changed", "value", v.Versioning)
				level.Debug(c.Logger).Log("msg", "update versioning configuration for bucket", "bucket", k)

				newCfgBucket.Versioning = v.Versioning
				newCfgBucket.VersioningType = "updated"
				bucketsUpdated = true
			}

			// Compare Lifecycle Configurations
			if len(sc[k].LifecycleRules) > 0 || len(v.LifecycleRules) > 0 {
				if !lfcIsEqual(v.LifecycleRules, sc[k].LifecycleRules, k, c.Logger) {
					level.Debug(c.Logger).Log("msg", "update lifecycle configuration for bucket", "bucket", k)

					newCfgBucket.LifecycleRules = v.LifecycleRules
					newCfgBucket.LifecycleType = "updated"
					bucketsUpdated = true
				}
			}

			newBuckets[k] = newCfgBucket
		} else {
			level.Debug(c.Logger).Log("msg", "bucket doesn't exist on server", "bucket", k)

			v.AclType = "new"
			v.BucketType = "new"
			v.LifecycleType = "new"

			level.Debug(c.Logger).Log("msg", "add new bucket to server's configuration", "value", fmt.Sprintf("%+v", v))

			newBuckets[k] = v
			bucketsUpdated = true
		}

	}

	return newBuckets, bucketsUpdated
}

func (b *Bucket) applyBucketConfig(c *Collector) error {
	var retryCount int

	if b.BucketType == "new" {
		level.Info(c.Logger).Log("msg", "create bucket", "bucket", b.name)

		retryCount = c.RetryNum

		for retryCount > 0 {
			// Create bucket
			out, err := createBucket(b.ctx, c.CephClient, &s3.CreateBucketInput{
				Bucket: &b.name,
			})

			retryCount--

			if err != nil {

				if retryCount > 0 {
					level.Warn(c.Logger).Log("msg", "error creating bucket", "bucket", b.name, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "error", err.Error())

					time.Sleep(1 * time.Second)
				} else {
					level.Error(c.Logger).Log("msg", "error creating bucket", "error", err.Error())

					return err
				}

			} else {
				level.Debug(c.Logger).Log("msg", "bucket created", "bucket", b.name)

				break
			}
		}
	}

	// Apply versioning if VersioningType "updated"
	if b.VersioningType == "updated" {
		level.Info(c.Logger).Log("msg", "update versioning", "bucket", b.name)

		var status types.BucketVersioningStatus = types.BucketVersioningStatus(strcase.ToCamel(b.Versioning))

		level.Debug(c.Logger).Log("msg", "versioning status updated", "bucket", b.name, "value", fmt.Sprintf("%+v", status))

		retryCount = c.RetryNum

		for retryCount > 0 {

			level.Debug(c.Logger).Log("msg", "apply versioning", "bucket", b.name)

			// Apply versioning
			out, err := putBucketVersioning(b.ctx, c.CephClient, &s3.PutBucketVersioningInput{
				Bucket: aws.String(b.name),
				VersioningConfiguration: &types.VersioningConfiguration{
					Status: status,
				},
			})

			retryCount--

			if err != nil {
				if retryCount > 0 {
					level.Warn(c.Logger).Log("msg", "error set versioning", "bucket", b.name, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "error", err.Error())

					time.Sleep(1 * time.Second)
				} else {
					level.Error(c.Logger).Log("msg", "error set versioning", "bucket", b.name, "error", err.Error())

					return err
				}
			} else {

				break
			}
		}
	}

	// Apply Bucket ACLs and Bucket Policy
	switch b.AclType {
	case "new", "updated":

		// Bucket ACL not supported yet in Ceph RGW S3
		//
		//			err := applyS3Acl(bn, b, client)
		//
		//			if err != nil {
		//				return err
		//			}
		//
		if err := b.applyBucketPolicy(c); err != nil {

			return err
		}

	case "error":
		level.Warn(c.Logger).Log("msg", "ACL with type 'error' can't be applied! Skip.", "bucket", b.name)
	}

	// Apply Lifecycle Configuration
	switch b.LifecycleType {
	case "new":
		err := b.applyLifecycleConfiguration(c)

		if err != nil {

			return err
		}

	case "updated":
		err := b.applyLifecycleConfiguration(c)

		if err != nil {

			return err
		}

	case "error":
		level.Warn(c.Logger).Log("msg", "lifecycle configuration with type 'error' can't be applied! Skip.", "bucket", b.name)
	}

	return nil
}

func (b *Bucket) prepareLifecycleConfiguration(c *Collector) []types.LifecycleRule {
	lfcRules := []types.LifecycleRule{}

	if len(b.LifecycleRules) == 0 {

		return lfcRules
	}

	level.Info(c.Logger).Log("msg", "update lifecycle configuration", "bucket", b.name)

	for _, lcr := range b.LifecycleRules {
		var newLCRule = types.LifecycleRule{}

		level.Debug(c.Logger).Log("msg", "show lifecycle rule", "value", fmt.Sprintf("%+v", lcr))

		if (lcr.NonCurrentDays >= 0) && (b.Versioning == "suspended") {
			level.Warn(c.Logger).Log("msg", "lifecycle rule contains non-negative value for non-current version expiration, but bucket versioning is disabled!", "bucket", b.name, "value", fmt.Sprintf("%+v", lcr.Id))

			lcr.NonCurrentDays = -1
		}

		// Specifies the expiration for the lifecycle of the object
		status := strcase.ToCamel(lcr.Status)

		newLCRule = types.LifecycleRule{
			Expiration: &types.LifecycleExpiration{
				Days: lcr.ExpirationDays,
			},
			ID:     aws.String(lcr.Id),
			Status: types.ExpirationStatus(status),
		}

		if len(lcr.Prefix) > 0 {
			newLCRule.Filter = &types.LifecycleRuleFilterMemberPrefix{Value: lcr.Prefix}
		}

		if lcr.NonCurrentDays >= 0 {
			newLCRule.NoncurrentVersionExpiration = &types.NoncurrentVersionExpiration{NoncurrentDays: lcr.NonCurrentDays}
		}

		lfcRules = append(lfcRules, newLCRule)
	}

	return lfcRules
}

func (b *Bucket) applyLifecycleConfiguration(c *Collector) error {
	var retryCount int

	lfcRules := b.prepareLifecycleConfiguration(c)

	retryCount = c.RetryNum

	for retryCount > 0 {
		level.Debug(c.Logger).Log("msg", "set lifecycle configuration", "bucket", b.name, "value", fmt.Sprintf("%+v", lfcRules))

		// Recreate/Delete lifecycle rules
		// first: Delete old rules
		level.Debug(c.Logger).Log("msg", "delete old lifecycle configuration", "bucket", b.name)

		delLfcOut, err := deleteBucketLifecycle(c.ctx, c.CephClient, &s3.DeleteBucketLifecycleInput{
			Bucket: aws.String(b.name),
		})

		if err != nil {
			level.Error(c.Logger).Log("msg", "error deleting old lifecycle configuration", "bucket", b.name, "output", fmt.Sprintf("%+v", delLfcOut), "error", err.Error())

			return err
		}

		if len(lfcRules) == 0 {

			break
		}
		// Create new versions of rules

		level.Debug(c.Logger).Log("msg", "apply lifecycle configuration", "value", fmt.Sprintf("%+v", &s3.PutBucketLifecycleConfigurationInput{
			Bucket: aws.String(b.name),
			LifecycleConfiguration: &types.BucketLifecycleConfiguration{
				Rules: lfcRules,
			},
		}))

		putLfcOut, err := putBucketLifecycleConfiguration(c.ctx, c.CephClient, &s3.PutBucketLifecycleConfigurationInput{
			Bucket: aws.String(b.name),
			LifecycleConfiguration: &types.BucketLifecycleConfiguration{
				Rules: lfcRules,
			},
		})

		retryCount--

		if err != nil {
			if retryCount > 0 {
				level.Debug(c.Logger).Log("msg", "error applying lifecycle configuration", "bucket", b.name, "output", fmt.Sprintf("%+v", putLfcOut), "retry_attempts_left", retryCount, "error", err.Error())
			} else {
				level.Error(c.Logger).Log("msg", "error applying lifecycle configuration", "error", err.Error())

				return err
			}

			time.Sleep(1 * time.Second)

		} else {

			break
		}

	}

	return nil
}

func checkBucketName(b string) error {
	var re *regexp.Regexp
	// search comment strings starting from "#" or "//"
	re = regexp.MustCompile(`^(#|//)`)

	if re.MatchString(b) {
		// report comment as bucket name
		return newCommentStringError("")
	}

	// search blank strings
	re = regexp.MustCompile(`^[[:blank:]]*?$`)

	if re.MatchString(b) {
		// report blank string as bucket name
		return newBlankStringError("")
	}

	// check if bucket name formatted as IP address
	re = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)

	if re.MatchString(b) {
		// report IP address string as bucket name
		return newBucketNameError()
	}

	re = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

	if re.MatchString(b) {
		// return 'no error' if bucket name match naming rules
		return nil
	} else {
		// return error with description of bucket naming rules
		return newBucketNameError()
	}
}

func checkBucketNamePostfix(bucketName string, c *Collector) string {

	matchPattern := fmt.Sprintf("%s$", c.BucketsPostfix)
	re := regexp.MustCompile(matchPattern)

	if len(c.BucketsPostfix) == 0 {

		return bucketName
	}

	if re.MatchString(bucketName) {
		level.Debug(c.Logger).Log("msg", "bucket name contains postfix. Rename for configuration", "bucket", bucketName, "regexp_postfix", matchPattern)

		// Create name without postfix
		bucketName = re.ReplaceAllString(bucketName, "")
		level.Debug(c.Logger).Log("msg", "new bucket name", "value", bucketName)

		return bucketName
	} else {
		level.Warn(c.Logger).Log("msg", "bucket name doesn't contain postfix", "bucket", bucketName, "regexp_postfix", matchPattern)

		return bucketName
	}
}

func getBucketDetailsToMap(cephBucket types.Bucket, c *Collector) Bucket {
	var b Bucket

	// set bucket name as is
	b.name = *cephBucket.Name

	// Get Bucket ACL
	// Bucket ACL not supported yet in Ceph RGW S3 so we use only owner now
	level.Debug(c.Logger).Log("msg", "get bucket ACL", "bucket", b.name)

	if err := b.getBucketAcl(c); err != nil {
		level.Warn(c.Logger).Log("msg", "error get bucket ACL", "bucket", b.name, "error", err.Error())
	}

	// Get Bucket policies
	level.Debug(c.Logger).Log("msg", "get bucket policies", "bucket", b.name)

	if err := b.getBucketPolicy(c); err != nil {
		level.Debug(c.Logger).Log("msg", "error get bucket policy", "bucket", b.name, "error", err.Error())
	}

	// Get bucket versioning
	level.Debug(c.Logger).Log("msg", "get bucket versioning", "bucket", b.name)

	if err := b.getBucketVersioning(c); err != nil {
		level.Warn(c.Logger).Log("msg", "error get bucket versioning", "bucket", b.name, "error", err.Error())
	}

	level.Debug(c.Logger).Log("msg", "show versioning status", "bucket", b.name, "value", b.Versioning)
	level.Debug(c.Logger).Log("msg", "get bucket lifecycle", "bucket", b.name)

	if err := b.getBucketLifecycleConfiguration(c); err != nil {
		level.Debug(c.Logger).Log("msg", "error get lifecycle configuration", "bucket", b.name, "error", err.Error())
	}

	// set bucket name without prefix
	if len(c.BucketsPostfix) > 0 {
		// set bucket name without postfix
		level.Debug(c.Logger).Log("msg", "create bucket name without postfix", "bucket", *cephBucket.Name, "postfix", c.BucketsPostfix)
	}

	b.name = checkBucketNamePostfix(*cephBucket.Name, c)

	return b
}
