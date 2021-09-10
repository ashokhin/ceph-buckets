package funcs

import (
	"context"

	ut "github.com/ashokhin/ceph-buckets/types"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func ListBuckets(c context.Context, api ut.S3ListBucketsAPI, input *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	return api.ListBuckets(c, input)
}

func GetBucketAcl(c context.Context, api ut.S3GetBucketAclAPI, input *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
	return api.GetBucketAcl(c, input)
}

func GetBucketPolicy(c context.Context, api ut.S3GetBucketPolicyAPI, input *s3.GetBucketPolicyInput) (*s3.GetBucketPolicyOutput, error) {
	return api.GetBucketPolicy(c, input)
}

func GetBucketLifecycleConfiguration(c context.Context, api ut.S3GetBucketLfcAPI, input *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return api.GetBucketLifecycleConfiguration(c, input)
}

func GetBucketVersioning(c context.Context, api ut.S3GetBucketVerAPI, input *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
	return api.GetBucketVersioning(c, input)
}

func CreateBucket(c context.Context, api ut.S3CreateBucketAPI, input *s3.CreateBucketInput) (*s3.CreateBucketOutput, error) {
	return api.CreateBucket(c, input)
}

func PutBucketVersioning(c context.Context, api ut.S3PutBucketVerAPI, input *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error) {
	return api.PutBucketVersioning(c, input)
}

func PutBucketAcl(c context.Context, api ut.S3PutBucketAclAPI, input *s3.PutBucketAclInput) (*s3.PutBucketAclOutput, error) {
	return api.PutBucketAcl(c, input)
}

func PutBucketPolicy(c context.Context, api ut.S3PutBucketPolicyAPI, input *s3.PutBucketPolicyInput) (*s3.PutBucketPolicyOutput, error) {
	return api.PutBucketPolicy(c, input)
}

func DeleteBucketLifecycle(c context.Context, api ut.S3DeleteBucketLifecycleAPI, input *s3.DeleteBucketLifecycleInput) (*s3.DeleteBucketLifecycleOutput, error) {
	return api.DeleteBucketLifecycle(c, input)
}

func PutBucketLifecycleConfiguration(c context.Context, api ut.S3PutBucketLifecycleConfigurationAPI, input *s3.PutBucketLifecycleConfigurationInput) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	return api.PutBucketLifecycleConfiguration(c, input)
}
