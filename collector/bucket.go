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
	"github.com/go-kit/log"
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
		* Bucket names must start with a lowercase letter or number.
`

	// See doc about BucketPolicyVersion https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
	bucketPolicyVersion string = "2012-10-17"
)

var (
	bucketPolicyWriteActions = []string{
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
		"s3:GetObjectAcl",
		"s3:GetObject",
		"s3:GetObjectTorrent",
		"s3:GetObjectVersionAcl",
		"s3:GetObjectVersion",
		"s3:GetObjectVersionTorrent",
		"s3:GetReplicationConfiguration",
		"s3:ListAllMyBuckets",
		"s3:ListBucketMultipartUploads",
		"s3:ListBucket",
		"s3:ListBucketVersions",
		"s3:ListMultipartUploadParts",
		"s3:DeleteObject",
		"s3:DeleteObjectVersion",
		"s3:PutObjectAcl",
		"s3:PutObject",
		"s3:PutObjectVersionAcl",
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
		"s3:GetObjectAcl",
		"s3:GetObject",
		"s3:GetObjectTorrent",
		"s3:GetObjectVersionAcl",
		"s3:GetObjectVersion",
		"s3:GetObjectVersionTorrent",
		"s3:GetReplicationConfiguration",
		"s3:ListAllMyBuckets",
		"s3:ListBucketMultipartUploads",
		"s3:ListBucket",
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

type Buckets map[string]Bucket

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

func (b *Bucket) getBucketAcl(c *Collector) error {
	var err error

	aclResult, err := getBucketAcl(c.ctx, c.CephClient, &s3.GetBucketAclInput{
		Bucket: &b.name,
	})

	if err != nil {
		level.Error(c.Logger).Log("msg", "error get bucket ACL", "bucket", b.name, "error", err.Error())

		b.AclType = "error"
	} else {
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

	return err
}

func (b *Bucket) getBucketPolicy(c *Collector) error {
	var err error

	// Rewrite ACL rules from bucket policies
	polResult, err := getBucketPolicy(c.ctx, c.CephClient, &s3.GetBucketPolicyInput{
		Bucket: &b.name,
	})

	if err != nil {
		var ae smithy.APIError

		if errors.As(err, &ae) {
			if ae.ErrorCode() == "NoSuchBucketPolicy" {
				level.Debug(c.Logger).Log("msg", "doesn't have bucket policy", "bucket", b.name)
			} else {
				level.Error(c.Logger).Log("msg", "API error", "code", ae.ErrorCode(), "message", ae.ErrorMessage(), "error", ae.ErrorFault().String())

				b.AclType = "error"
			}
		} else {
			level.Error(c.Logger).Log("msg", "error get bucket policies", "bucket", b.name, "error", err.Error())

			b.AclType = "error"
		}
	} else {
		level.Debug(c.Logger).Log("msg", "show bucket policies", "bucket", b.name, "value", fmt.Sprintf("%+v", *polResult.Policy))

		var bp BucketPolicy

		err := json.Unmarshal([]byte(*polResult.Policy), &bp)

		if err != nil {
			level.Error(c.Logger).Log("msg", "error unmarshal Bucket policies", "bucket", b.name, "error", err.Error())

			b.AclType = "error"
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
				level.Error(c.Logger).Log("msg", "bucket policy statement", "bucket", b.name, "value", statActionArray, "error", "action type unsupported")
			}
		}

		level.Debug(c.Logger).Log("msg", "ACL updated from bucket policies", "bucket", b.name, "value", fmt.Sprintf("%+v", b.Acl))
	}

	return err
}

func (b *Bucket) getBucketVersioning(bucket types.Bucket, c *Collector) error {
	var err error

	// Get Bucket versioning status
	vResult, err := getBucketVersioning(c.ctx, c.CephClient, &s3.GetBucketVersioningInput{
		Bucket: aws.String(*bucket.Name),
	})

	if err != nil {
		level.Error(c.Logger).Log("msg", "error get versioning configuration", "error", err.Error())

		b.VersioningType = "error"
	} else {
		if len(vResult.Status) > 0 {
			b.Versioning = strings.ToLower(string(vResult.Status))
		} else {
			b.Versioning = "suspended"
		}
	}

	return err
}

func (b *Bucket) getBucketLifecycleConfiguration(bucket types.Bucket, c *Collector) error {
	var err error

	lfResult, err := getBucketLifecycleConfiguration(c.ctx, c.CephClient, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(*bucket.Name),
	})

	if err != nil {
		var ae smithy.APIError

		if errors.As(err, &ae) {
			if ae.ErrorCode() == "NoSuchLifecycleConfiguration" {
				level.Debug(c.Logger).Log("msg", "doesn't have Lifecycle configuration", "bucket", *bucket.Name)
			} else {
				level.Error(c.Logger).Log("msg", "API error", "code", ae.ErrorCode(), "message", ae.ErrorMessage(), "error", ae.ErrorFault().String())
			}
		} else {
			level.Error(c.Logger).Log("msg", "error get bucket lifecycle", "bucket", *bucket.Name, "error", err.Error())
		}
	}

	if lfResult != nil {
		level.Debug(c.Logger).Log("msg", "show lifecycle configuration", "bucket", *bucket.Name, "value", fmt.Sprintf("%+v", *lfResult))

		for _, r := range lfResult.Rules {
			var lfr LifecycleRule

			if r.Filter != nil {
				if _, ok := r.Filter.(*types.LifecycleRuleFilterMemberPrefix); ok {
					if strings.Contains(fmt.Sprintf("%+v", r), "Filter") {
						// New version of Ceph return "Prefix" inside struct "Filter"
						lfr.Prefix = r.Filter.(*types.LifecycleRuleFilterMemberPrefix).Value
					} else if strings.Contains(fmt.Sprintf("%+v", r), "Prefix") {
						// Old version of Ceph return "Prefix" inside struct "LifecycleRule"
						lfr.Prefix = *r.Prefix
					}
				} else {
					level.Error(c.Logger).Log("msg", "lifecycle rule of filter type not supported!", "bucket", *bucket.Name, "name", *r.ID, "type", fmt.Sprintf("%T", r.Filter))
				}
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

	return err
}

func (b *Bucket) applyBucketPolicy(c *Collector) error {
	var err error
	var retryCount int
	var out interface{}

	level.Info(c.Logger).Log("msg", "update bucket policy", "bucket", b.name)
	level.Debug(c.Logger).Log("msg", "generate bucket policy", "bucket", b.name)

	// Create Bucket policy JSON
	BucketPolicy, err := b.createBucketPolicy(c)

	if err != nil {
		level.Error(c.Logger).Log("msg", "error marshaling Bucket policy to JSON", "bucket", b.name, "err", err.Error())

		return err
	}

	level.Info(c.Logger).Log("msg", "show bucket policy", "bucket", b.name, "value", fmt.Sprintf("%+v", BucketPolicy))

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
				level.Warn(c.Logger).Log("msg", "error applying Bucket policy", "bucket", b.name, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "err", err.Error())

				time.Sleep(1 * time.Second)
			} else {
				level.Error(c.Logger).Log("msg", "error applying lifecycle configuration", "err", err.Error())

				return err
			}

		} else {

			break
		}
	}

	return err
}

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

func (b *Bucket) fillBucketPolicy(op string, grants []string, bpsa []BucketPolicyStatement, c *Collector) []BucketPolicyStatement {

	var (
		bps       BucketPolicyStatement
		pta       []string
		polAction []string
		fullName  string
	)

	switch op {
	case "full":
		polAction = []string{
			"s3:*",
		}
		fullName = "FULL_CONTROL"
	case "read":
		polAction = bucketPolicyReadActions
		fullName = "READ"
	case "write":
		polAction = bucketPolicyWriteActions
		fullName = "WRITE"
	}

	for _, u := range grants {
		switch s := u; {
		case s == b.Acl.Owner.Id:
			level.Debug(c.Logger).Log("msg", "skip bucket owner", "value", s)
		case strings.Contains(s, ":"):
			pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s", u))
		default:
			pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s:%s", b.Acl.Owner.Id, u))

		}

	}

	bps = BucketPolicyStatement{
		Sid:    fmt.Sprintf("%s-%s-%v", b.name, op, time.Now().UnixNano()),
		Action: polAction,
		Effect: "Allow",
		Resource: []string{
			fmt.Sprintf("arn:aws:s3:::%s", b.name),
		},
		Principal: BucketPolicyPrincipal{
			PrincipalType: pta,
		},
	}

	if len(bps.Principal.PrincipalType) > 0 {
		bpsa = append(bpsa, bps)
		return bpsa
	} else {
		level.Debug(c.Logger).Log("msg", "bucket policy statement didn't have principals. Skip. Show bucket policy template", "policy", fullName, "bucket", b.name, "value", fmt.Sprintf("%+v", bps))
	}

	return bpsa
}

func (b Buckets) HasKey(k string) bool {
	_, ok := b[k]

	return ok
}

func compareBuckets(fc Buckets, sc Buckets, logger log.Logger) (Buckets, bool) {
	var bucketsUpdated bool

	newBuckets := make(Buckets)

	level.Debug(logger).Log("msg", "compare local and server's configurations")

	for k, v := range fc {

		if sc.HasKey(k) {
			level.Debug(logger).Log("msg", "bucket already exist on server", "bucket", k)
			level.Debug(logger).Log("msg", "add server struct to result configuration", "value", fmt.Sprintf("%+v", sc[k]))

			newCfgBucket := sc[k]

			// Compare ACLs
			// Bucket ACL not supported yet in Ceph RGW S3
			if !aclEqual(&v, sc[k], &k, logger) {
				level.Debug(logger).Log("msg", "update ACL for bucket", "bucket", k)

				newCfgBucket.Acl.Grants.FullControl = v.Acl.Grants.FullControl
				newCfgBucket.Acl.Grants.Read = v.Acl.Grants.Read
				newCfgBucket.Acl.Grants.Write = v.Acl.Grants.Write
				newCfgBucket.AclType = "updated"
				bucketsUpdated = true
			}

			// Compare versioning
			if sc[k].Versioning != v.Versioning {
				level.Debug(logger).Log("msg", "versioning changed", "value", v.Versioning)
				level.Debug(logger).Log("msg", "update versioning configuration for bucket", "bucket", k)

				newCfgBucket.Versioning = v.Versioning
				newCfgBucket.VersioningType = "updated"
				bucketsUpdated = true
			}

			// Compare Lifecycle Configurations
			if len(sc[k].LifecycleRules) > 0 || len(v.LifecycleRules) > 0 {
				if !lfcIsEqual(&v, sc[k], &k, logger) {
					level.Debug(logger).Log("msg", "update lifecycle configuration for bucket", "bucket", k)

					newCfgBucket.LifecycleRules = v.LifecycleRules
					newCfgBucket.LifecycleType = "updated"
					bucketsUpdated = true
				}
			}

			newBuckets[k] = newCfgBucket
		} else {
			level.Debug(logger).Log("msg", "bucket doesn't exist on server", "bucket", k)

			v.AclType = "new"
			v.BucketType = "new"
			v.LifecycleType = "new"

			level.Debug(logger).Log("msg", "add new bucket to server's configuration", "value", fmt.Sprintf("%+v", v))

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
					level.Warn(c.Logger).Log("msg", "error creating bucket", "bucket", b.name, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "err", err.Error())

					time.Sleep(1 * time.Second)
				} else {
					level.Error(c.Logger).Log("msg", "error creating bucket", "err", err.Error())

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
			input := &s3.PutBucketVersioningInput{
				Bucket: aws.String(b.name),
				VersioningConfiguration: &types.VersioningConfiguration{
					Status: status,
				},
			}

			level.Debug(c.Logger).Log("msg", "apply versioning", "bucket", b.name, "value", *input)

			// Apply versioning
			out, err := putBucketVersioning(b.ctx, c.CephClient, input)

			retryCount--

			if err != nil {
				if retryCount > 0 {
					level.Warn(c.Logger).Log("msg", "error set versioning", "bucket", b.name, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "err", err.Error())

					time.Sleep(1 * time.Second)
				} else {
					level.Error(c.Logger).Log("msg", "error set versioning", "bucket", b.name, "err", err.Error())

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

func (b *Bucket) applyLifecycleConfiguration(c *Collector) error {
	var retryCount int

	level.Info(c.Logger).Log("msg", "update lifecycle configuration", "bucket", b.name)

	lfcRules := []types.LifecycleRule{}
	for _, lc := range b.LifecycleRules {
		level.Debug(c.Logger).Log("msg", "show lifecycle rule", "value", fmt.Sprintf("%+v", lc))

		if (lc.NonCurrentDays >= 0) && (b.Versioning == "suspended") {
			level.Warn(c.Logger).Log("msg", "lifecycle rule contains non-negative value for non-current version expiration, but bucket versioning is disabled!", "bucket", b.name, "value", fmt.Sprintf("%+v", lc.Id))

			lc.NonCurrentDays = -1
		}

		// Specifies the expiration for the lifecycle of the object
		status := strcase.ToCamel(lc.Status)
		var newLCRule = types.LifecycleRule{}
		var lfcFilter types.LifecycleRuleFilter = &types.LifecycleRuleFilterMemberPrefix{Value: lc.Prefix}

		if lc.NonCurrentDays >= 0 {
			newLCRule = types.LifecycleRule{
				Expiration: &types.LifecycleExpiration{
					Days: lc.ExpirationDays,
				},
				Filter: lfcFilter,
				ID:     aws.String(lc.Id),
				NoncurrentVersionExpiration: &types.NoncurrentVersionExpiration{
					NoncurrentDays: lc.NonCurrentDays,
				},
				Status: types.ExpirationStatus(status),
			}
		} else {
			newLCRule = types.LifecycleRule{
				Expiration: &types.LifecycleExpiration{
					Days: lc.ExpirationDays,
				},
				Filter: lfcFilter,
				ID:     aws.String(lc.Id),
				Status: types.ExpirationStatus(status),
			}
		}

		lfcRules = append(lfcRules, newLCRule)
	}

	retryCount = c.RetryNum

	for retryCount > 0 {
		level.Debug(c.Logger).Log("msg", "set lifecycle configuration", "bucket", b.name, "value", fmt.Sprintf("%+v", lfcRules))

		// Recreate/Delete lifecycle rules
		// first: Delete old rules
		delLfcOut, err := deleteBucketLifecycle(c.ctx, c.CephClient, &s3.DeleteBucketLifecycleInput{
			Bucket: aws.String(b.name),
		})
		if err != nil {
			level.Error(c.Logger).Log("msg", "error deleting old lifecycle configuration", "bucket", b.name, "output", fmt.Sprintf("%+v", delLfcOut), "err", err.Error())

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
				level.Debug(c.Logger).Log("msg", "error applying lifecycle configuration", "bucket", b.name, "output", fmt.Sprintf("%+v", putLfcOut), "retry_attempts_left", retryCount, "err", err.Error())
			} else {
				level.Error(c.Logger).Log("msg", "error applying lifecycle configuration", "err", err.Error())

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
	re = regexp.MustCompile(`^$`)

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

func getBucketDetailsToMap(cephBucket types.Bucket, c *Collector) Bucket {
	var b Bucket

	b.name = checkBucketNamePostfix(cephBucket, c.BucketsPostfix, c.Logger)

	// create bucket name with postfix
	level.Debug(c.Logger).Log("msg", "create bucket name", "bucket", b.name)

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

	if err := b.getBucketVersioning(cephBucket, c); err != nil {
		level.Warn(c.Logger).Log("msg", "error get bucket versioning", "bucket", b.name, "error", err.Error())
	}

	level.Debug(c.Logger).Log("msg", "show versioning status", "bucket", b.name, "value", b.Versioning)
	level.Debug(c.Logger).Log("msg", "get bucket lifecycle", "bucket", b.name)

	if err := b.getBucketLifecycleConfiguration(cephBucket, c); err != nil {
		level.Debug(c.Logger).Log("msg", "error get lifecycle configuration", "bucket", b.name, "error", err.Error())
	}

	return b
}

func checkBucketNamePostfix(bucket types.Bucket, bucketPostfix string, logger log.Logger) string {
	var bn string

	matchPattern := fmt.Sprintf("%s$", bucketPostfix)
	re := regexp.MustCompile(matchPattern)

	if len(bucketPostfix) > 0 {
		if re.MatchString(*bucket.Name) {
			level.Debug(logger).Log("msg", "bucket name have to match pattern. Rename", "bucket", *bucket.Name, "regexp", matchPattern)

			// Create name without postfix
			bn = re.ReplaceAllString(*bucket.Name, "")
			level.Debug(logger).Log("msg", "new bucket name", "value", bn)
		} else {
			level.Warn(logger).Log("msg", "bucket name doesn't match pattern", "bucket", *bucket.Name, "regexp", matchPattern)

			bn = *bucket.Name
		}
	} else {
		bn = *bucket.Name
	}

	return bn
}
