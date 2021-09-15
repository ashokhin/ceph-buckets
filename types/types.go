package types

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
	EndpointUrl  string `yaml:"endpoint_url"`
	AwsAccessKey string `yaml:"access_key"`
	AwsSecretKey string `yaml:"secret_key"`
	DisableSSL   bool   `yaml:"disable_ssl"`
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

type Bucket struct {
	Acl            BucketAcl       `yaml:"acl"`
	AclType        string          `yaml:"acl_type,omitempty"`
	BucketType     string          `yaml:"bucket_type,omitempty"`
	LifecycleRules []LifecycleRule `yaml:"lifecycle_rules"`
	LifecycleType  string          `yaml:"lifecycle_type,omitempty"`
	Versioning     string          `yaml:"versioning"`
	VersioningType string          `yaml:"versioning_type,omitempty"`
}

type Buckets map[string]Bucket

func (conf *Config) SetDefaults() {
	conf.EndpointUrl = "127.0.0.1:8880"
	conf.DisableSSL = false
}

func (b Buckets) HasKey(k string) bool {
	_, ok := b[k]
	return ok
}

type BucketPolicyPricipal struct {
	PrincipalType []string `json:"AWS"`
}

type BucketPolicyStatement struct {
	Sid       string               `json:"Sid"`
	Action    []string             `json:"Action"`
	Effect    string               `json:"Effect"`
	Resource  []string             `json:"Resource"`
	Principal BucketPolicyPricipal `json:"Principal"`
}

type BucketPolicy struct {
	Id        string                  `json:"Id"`
	Version   string                  `json:"Version"`
	Statement []BucketPolicyStatement `json:"Statement"`
}

type S3ListBucketsAPI interface {
	ListBuckets(ctx context.Context,
		params *s3.ListBucketsInput,
		optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

/*
	Bucket ACL not supported yet in Ceph RGW S3
*/
type S3GetBucketAclAPI interface {
	GetBucketAcl(ctx context.Context,
		params *s3.GetBucketAclInput,
		optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
}

type S3GetBucketPolicyAPI interface {
	GetBucketPolicy(ctx context.Context,
		params *s3.GetBucketPolicyInput,
		optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
}

type S3GetBucketLfcAPI interface {
	GetBucketLifecycleConfiguration(ctx context.Context,
		params *s3.GetBucketLifecycleConfigurationInput,
		optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
}

type S3GetBucketVerAPI interface {
	GetBucketVersioning(ctx context.Context,
		params *s3.GetBucketVersioningInput,
		optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
}

type S3CreateBucketAPI interface {
	CreateBucket(ctx context.Context,
		params *s3.CreateBucketInput,
		optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error)
}

type S3PutBucketVerAPI interface {
	PutBucketVersioning(ctx context.Context,
		params *s3.PutBucketVersioningInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error)
}

/*
	Bucket ACL not supported yet in Ceph RGW S3
*/
type S3PutBucketAclAPI interface {
	PutBucketAcl(ctx context.Context,
		params *s3.PutBucketAclInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error)
}

type S3PutBucketPolicyAPI interface {
	PutBucketPolicy(ctx context.Context,
		params *s3.PutBucketPolicyInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketPolicyOutput, error)
}

type S3DeleteBucketLifecycleAPI interface {
	DeleteBucketLifecycle(ctx context.Context,
		params *s3.DeleteBucketLifecycleInput,
		optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error)
}

type S3PutBucketLifecycleConfigurationAPI interface {
	PutBucketLifecycleConfiguration(ctx context.Context,
		params *s3.PutBucketLifecycleConfigurationInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error)
}
