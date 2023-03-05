package collector

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

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

func putBucketVersioning(c context.Context, api s3PutBucketVerAPI, input *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error) {
	return api.PutBucketVersioning(c, input)
}

func putBucketAcl(c context.Context, api s3PutBucketAclAPI, input *s3.PutBucketAclInput) (*s3.PutBucketAclOutput, error) {
	return api.PutBucketAcl(c, input)
}

func putBucketPolicy(c context.Context, api s3PutBucketPolicyAPI, input *s3.PutBucketPolicyInput) (*s3.PutBucketPolicyOutput, error) {
	return api.PutBucketPolicy(c, input)
}

func deleteBucketLifecycle(c context.Context, api s3DeleteBucketLifecycleAPI, input *s3.DeleteBucketLifecycleInput) (*s3.DeleteBucketLifecycleOutput, error) {
	return api.DeleteBucketLifecycle(c, input)
}

func deleteBucketPolicy(c context.Context, api s3DeleteBucketPolicyAPI, input *s3.DeleteBucketPolicyInput) (*s3.DeleteBucketPolicyOutput, error) {
	return api.DeleteBucketPolicy(c, input)
}

func putBucketLifecycleConfiguration(c context.Context, api s3PutBucketLifecycleConfigurationAPI, input *s3.PutBucketLifecycleConfigurationInput) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	return api.PutBucketLifecycleConfiguration(c, input)
}

/*
Bucket ACL not supported yet in Ceph RGW S3
*/
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

type s3PutBucketVerAPI interface {
	PutBucketVersioning(ctx context.Context,
		params *s3.PutBucketVersioningInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error)
}

/*
Bucket ACL not supported yet in Ceph RGW S3
*/
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

type s3PutBucketLifecycleConfigurationAPI interface {
	PutBucketLifecycleConfiguration(ctx context.Context,
		params *s3.PutBucketLifecycleConfigurationInput,
		optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error)
}

func keyInArray(arr []string, key string) bool {
	for _, k := range arr {

		if k == key {

			return true
		}
	}

	return false
}

func getUsersFromPrincipalArray(arr []string) []string {
	var u []string

	re := regexp.MustCompile(`^.+user\/`)

	for _, p := range arr {
		u = append(u, re.ReplaceAllString(p, ""))
	}

	return u
}

func arrayIsEqual(a1 []string, a2 []string) bool {
	sort.Strings(a1)
	sort.Strings(a2)

	if len(a1) == len(a2) {

		for i, v := range a1 {

			if v != a2[i] {

				return false
			}

		}
	} else {

		return false
	}

	return true
}

func recordToArr(r string) []string {
	return strings.Fields(r)
}

// Bucket ACL not supported yet in Ceph RGW S3
func aclEqual(lc *Bucket, sc Bucket, b *string, logger log.Logger) bool {
	level.Debug(logger).Log("msg", "compare ACLs for bucket", "bucket", *b)

	if !reflect.DeepEqual(lc.Acl.Grants.FullControl, sc.Acl.Grants.FullControl) {
		level.Debug(logger).Log("msg", fmt.Sprintf("ACL fullControl %+v != %+v", lc.Acl.Grants.FullControl, sc.Acl.Grants.FullControl))

		return false
	}

	if !arrayIsEqual(lc.Acl.Grants.Read, sc.Acl.Grants.Read) {
		level.Debug(logger).Log("msg", fmt.Sprintf("ACL read %+v != %+v", lc.Acl.Grants.Read, sc.Acl.Grants.Read))

		return false
	}

	if !arrayIsEqual(lc.Acl.Grants.Write, sc.Acl.Grants.Write) {
		level.Debug(logger).Log("msg", fmt.Sprintf("ACL write %+v != %+v", lc.Acl.Grants.Write, sc.Acl.Grants.Write))

		return false
	}

	return true
}

func lfcIsEqual(lc *Bucket, sc Bucket, b *string, logger log.Logger) bool {
	level.Debug(logger).Log("msg", "compare lifecycle configuration for bucket", "bucket", *b)

	if len(lc.LifecycleRules) == len(sc.LifecycleRules) {

		for i, v := range lc.LifecycleRules {

			if !reflect.DeepEqual(v, sc.LifecycleRules[i]) {
				level.Debug(logger).Log("msg", fmt.Sprintf("lifecycle configuration %+v != %+v", v, sc.LifecycleRules[i]))

				return false
			}
		}

		for i, v := range sc.LifecycleRules {

			if !reflect.DeepEqual(v, lc.LifecycleRules[i]) {
				level.Debug(logger).Log("msg", fmt.Sprintf("lifecycle configuration %+v != %+v", v, lc.LifecycleRules[i]))

				return false
			}
		}
	} else {

		return false
	}

	return true
}
