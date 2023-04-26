package collector

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var collector Collector

func init() {
	collector.Logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	collector.Logger = level.NewFilter(collector.Logger, level.AllowNone())
}

func TestParseBucketAcl(t *testing.T) {
	type expectedStruct struct {
		fullControlGrants []string
		readGrants        []string
		writeGrants       []string
		ownerDisplayName  string
		ownerId           string
	}
	parseBucketAclTests := map[string]struct {
		bucket   Bucket
		arg1     Collector
		arg2     *s3.GetBucketAclOutput
		expected expectedStruct
	}{
		// test PermissionReadAcp grants case
		"test01": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketAclOutput{
				Grants: []types.Grant{
					{Grantee: &types.Grantee{ID: aws.String("bob")}, Permission: types.PermissionReadAcp},
				},
				Owner: &types.Owner{DisplayName: aws.String("Admin Test01"), ID: aws.String("admintest01")},
			},
			expectedStruct{ownerDisplayName: "Admin Test01", ownerId: "admintest01"},
		},
		// test mixed grants case
		"test02": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketAclOutput{
				Grants: []types.Grant{
					{Grantee: &types.Grantee{ID: aws.String("admintest02")}, Permission: types.PermissionFullControl},
					{Grantee: &types.Grantee{ID: aws.String("alice")}, Permission: types.PermissionFullControl},
					{Grantee: &types.Grantee{ID: aws.String("bob")}, Permission: types.PermissionRead},
					{Grantee: &types.Grantee{ID: aws.String("alice")}, Permission: types.PermissionWrite},
					{Grantee: &types.Grantee{ID: aws.String("bob")}, Permission: types.PermissionWrite},
				},
				Owner: &types.Owner{DisplayName: aws.String("Admin Test02"), ID: aws.String("admintest02")},
			},
			expectedStruct{
				fullControlGrants: []string{"admintest02", "alice"},
				readGrants:        []string{"bob"},
				writeGrants:       []string{"alice", "bob"},
				ownerDisplayName:  "Admin Test02",
				ownerId:           "admintest02",
			},
		},
	}

	for testName, testData := range parseBucketAclTests {
		t.Run(testName, func(t *testing.T) {
			testData.bucket.name = testName
			testData.bucket.parseBucketAcl(&testData.arg1, testData.arg2)
			if !arrayIsEqual(testData.bucket.Acl.Grants.FullControl, testData.expected.fullControlGrants) {
				t.Errorf("Grants.FullControl output '%+v' not equal to expected '%+v'", testData.bucket.Acl.Grants.FullControl, testData.expected.fullControlGrants)
			}
			if !arrayIsEqual(testData.bucket.Acl.Grants.Read, testData.expected.readGrants) {
				t.Errorf("Grants.Read output '%+v' not equal to expected '%+v'", testData.bucket.Acl.Grants.Read, testData.expected.readGrants)
			}
			if !arrayIsEqual(testData.bucket.Acl.Grants.Write, testData.expected.writeGrants) {
				t.Errorf("Grants.Write output '%+v' not equal to expected '%+v'", testData.bucket.Acl.Grants.Write, testData.expected.writeGrants)
			}
			if testData.bucket.Acl.Owner.DisplayName != testData.expected.ownerDisplayName {
				t.Errorf("Acl.Owner.DisplayName output '%s' not equal to expected '%s'", testData.bucket.Acl.Owner.DisplayName, testData.expected.ownerDisplayName)
			}
			if testData.bucket.Acl.Owner.Id != testData.expected.ownerId {
				t.Errorf("Acl.Owner.Id output '%s' not equal to expected '%s'", testData.bucket.Acl.Owner.Id, testData.expected.ownerId)
			}
		})
	}
}

func TestParseBucketPolicy(t *testing.T) {
	parseBucketPolicyTests := map[string]struct {
		bucket      Bucket
		arg1        Collector
		arg2        *s3.GetBucketPolicyOutput
		arg3        error
		expectError bool
		expected    Bucket
	}{
		// test FullControl actions case
		"test01": {
			Bucket{
				Acl: BucketAcl{Owner: AclOwner{DisplayName: "Admin Test01", Id: "admintest01"}},
			},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketPolicyOutput{Policy: aws.String(`{"Id":"Policy-test01-full-control-actions-case","Version":"2012-10-17","Statement":[{"Sid":"test01-full-","Action":["s3:*"],"Effect":"Allow","Resource":["arn:aws:s3:::test01"],"Principal":{"AWS":["arn:aws:iam:::user/admintest01:alice"]}}]}`)},
			nil,
			false,
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{FullControl: []string{"admintest01:alice", "admintest01"}},
					Owner:  AclOwner{DisplayName: "Admin Test01", Id: "admintest01"}},
			},
		},
		// test Read actions case
		"test02": {
			Bucket{
				Acl: BucketAcl{
					Owner: AclOwner{DisplayName: "Admin Test02", Id: "admintest02"}},
			},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketPolicyOutput{Policy: aws.String(`{"Id":"Policy-test02-read-actions-case","Version":"2012-10-17","Statement":[{"Sid":"test02-read-","Action":["s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test02"],"Principal":{"AWS":["arn:aws:iam:::user/admintest02:alice","arn:aws:iam:::user/admintest02:bob"]}}]}`)},
			nil,
			false,
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{Read: []string{"admintest02:alice", "admintest02:bob"}},
					Owner:  AclOwner{DisplayName: "Admin Test02", Id: "admintest02"}},
			},
		},
		// test Write actions case
		"test03": {
			Bucket{
				Acl: BucketAcl{Owner: AclOwner{DisplayName: "Admin Test03", Id: "admintest03"}},
			},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketPolicyOutput{Policy: aws.String(`{"Id":"Policy-test03-write-actions-case","Version":"2012-10-17","Statement":[{"Sid":"test03-write-","Action":["s3:AbortMultipartUpload","s3:CreateBucket","s3:DeleteBucket","s3:DeleteBucketPolicy","s3:DeleteBucketWebsite","s3:DeleteObject","s3:DeleteObjectVersion","s3:DeleteReplicationConfiguration","s3:PutAccelerateConfiguration","s3:PutBucketAcl","s3:PutBucketCORS","s3:PutBucketLogging","s3:PutBucketNotification","s3:PutBucketPolicy","s3:PutBucketRequestPayment","s3:PutBucketTagging","s3:PutBucketVersioning","s3:PutBucketWebsite","s3:PutLifecycleConfiguration","s3:PutObject","s3:PutObjectAcl","s3:PutObjectVersionAcl","s3:PutReplicationConfiguration","s3:RestoreObject","s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test03"],"Principal":{"AWS":["arn:aws:iam:::user/admintest03:bob"]}}]}`)},
			nil,
			false,
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{Write: []string{"admintest03:bob"}},
					Owner:  AclOwner{DisplayName: "Admin Test03", Id: "admintest03"}},
			},
		},
		// test unsupported actions case
		"test04": {
			Bucket{
				Acl: BucketAcl{Owner: AclOwner{DisplayName: "Admin Test04", Id: "admintest04"}},
			},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketPolicyOutput{Policy: aws.String(`{"Id":"Policy-test04-unsupported-action-case","Version":"2012-10-17","Statement":[{"Sid":"test04-write-","Action":["s3:GetBucketEncryption"],"Effect":"Allow","Resource":["arn:aws:s3:::test04"],"Principal":{"AWS":["arn:aws:iam:::user/admintest04:bob"]}}]}`)},
			nil,
			false,
			Bucket{
				Acl: BucketAcl{
					Owner: AclOwner{DisplayName: "Admin Test04", Id: "admintest04"}},
			},
		},
		// test expected API error case
		"test05": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketPolicyOutput{Policy: aws.String("")},
			&smithy.GenericAPIError{Code: "NoSuchBucketPolicy", Message: "test expected API error case"},
			false,
			Bucket{},
		},
		// test unexpected API error case
		"test06": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketPolicyOutput{Policy: aws.String("")},
			&smithy.GenericAPIError{Code: "MethodNotAllowed", Message: "test unexpected API error case"},
			true,
			Bucket{AclType: "error"},
		},
		// test some other error case
		"test07": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketPolicyOutput{Policy: aws.String("")},
			fmt.Errorf("Test some other error case"),
			true,
			Bucket{AclType: "error"},
		},
		// test unmarshaled JSON error case
		"test08": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketPolicyOutput{Policy: aws.String("test-broken-json-case")},
			nil,
			true,
			Bucket{AclType: "error"},
		},
	}

	for testName, testData := range parseBucketPolicyTests {
		t.Run(testName, func(t *testing.T) {
			testData.bucket.name = testName
			err := testData.bucket.parseBucketPolicy(&testData.arg1, testData.arg2, testData.arg3)
			if err != nil {
				if !testData.expectError {
					t.Errorf("Output got unexpected error '%+v' with bucket '%s'", err, testData.bucket.name)
				}
			}

			if testData.bucket.AclType != testData.expected.AclType {
				t.Errorf("Output '%+v' not equal to expected '%+v'", testData.bucket.AclType, testData.expected.AclType)
			}

			if !reflect.DeepEqual(testData.bucket.Acl, testData.expected.Acl) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", testData.bucket.Acl, testData.expected.Acl)
			}
		})
	}
}

func TestParseBucketVersioning(t *testing.T) {
	parseBucketVersioningTests := map[string]struct {
		bucket   Bucket
		arg1     Collector
		arg2     *s3.GetBucketVersioningOutput
		expected Bucket
	}{
		// test Versioning.Status enabled case
		"test01": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusEnabled},
			Bucket{Versioning: "enabled"},
		},
		// test Versioning.Status suspended case
		"test02": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusSuspended},
			Bucket{Versioning: "suspended"},
		},
		// test Versioning.Status is empty case
		"test03": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketVersioningOutput{},
			Bucket{Versioning: "suspended"},
		},
	}

	for testName, testData := range parseBucketVersioningTests {
		t.Run(testName, func(t *testing.T) {
			testData.bucket.name = testName
			testData.bucket.parseBucketVersioning(&testData.arg1, testData.arg2)
			if !reflect.DeepEqual(testData.bucket.Versioning, testData.expected.Versioning) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", testData.bucket.Versioning, testData.expected.Versioning)
			}
		})
	}
}

func TestParseBucketLifecycleConfiguration(t *testing.T) {
	parseBucketLifecycleConfigurationTests := map[string]struct {
		bucket   Bucket
		arg1     Collector
		arg2     *s3.GetBucketLifecycleConfigurationOutput
		arg3     error
		expected Bucket
	}{
		// test expected API error case
		"test01": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			nil,
			&smithy.GenericAPIError{Code: "NoSuchLifecycleConfiguration", Message: "test expected API error"},
			Bucket{},
		},
		// test unexpected API error case
		"test02": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			nil,
			&smithy.GenericAPIError{Code: "NoSuchKey", Message: "test unexpected API error"},
			Bucket{},
		},
		// test some other error case
		"test03": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			nil,
			fmt.Errorf("test some other error case"),
			Bucket{},
		},
		// test nil GetBucketLifecycleConfigurationOutput result case
		"test04": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			nil,
			nil,
			Bucket{},
		},
		// test "disabled 30 days rule without filter" case
		"test05": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketLifecycleConfigurationOutput{Rules: []types.LifecycleRule{
				{ID: aws.String("test05-disabled-30-days-rule-without-filter"),
					Expiration: &types.LifecycleExpiration{Days: 30},
					Status:     types.ExpirationStatusDisabled}},
			},
			nil,
			Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 30,
						Id:             "test05-disabled-30-days-rule-without-filter",
						NonCurrentDays: -1,
						Status:         "disabled"}},
			},
		},
		// test "enabled 5 days rule without filter" case
		"test06": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketLifecycleConfigurationOutput{Rules: []types.LifecycleRule{
				{ID: aws.String("test06-enabled-5-days-rule-without-filter"),
					Expiration: &types.LifecycleExpiration{Days: 5},
					Status:     types.ExpirationStatusEnabled}},
			},
			nil,
			Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 5,
						Id:             "test06-enabled-5-days-rule-without-filter",
						NonCurrentDays: -1,
						Status:         "enabled"}},
			},
		},
		// test "mixed rules" case
		"test07": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketLifecycleConfigurationOutput{
				Rules: []types.LifecycleRule{
					{ID: aws.String("test07-disabled-20-days-rule-without-filter"),
						Expiration: &types.LifecycleExpiration{Days: 20},
						Status:     types.ExpirationStatusDisabled},
					{ID: aws.String("test07-enabled-10-days-rule-without-filter"),
						Expiration: &types.LifecycleExpiration{Days: 10},
						Status:     types.ExpirationStatusEnabled},
					{ID: aws.String("test07-enabled-5-days-rule-with-filter"),
						Expiration: &types.LifecycleExpiration{Days: 5},
						Status:     types.ExpirationStatusEnabled,
						Filter:     &types.LifecycleRuleFilterMemberPrefix{Value: "/test07"}},
					{ID: aws.String("test07-enabled-3-days-rule-with-non-current-versions-2-days"),
						Expiration:                  &types.LifecycleExpiration{Days: 3},
						Status:                      types.ExpirationStatusEnabled,
						NoncurrentVersionExpiration: &types.NoncurrentVersionExpiration{NoncurrentDays: 2}},
				},
			},
			nil,
			Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 20,
						Id:             "test07-disabled-20-days-rule-without-filter",
						NonCurrentDays: -1,
						Status:         "disabled"},
					{ExpirationDays: 10,
						Id:             "test07-enabled-10-days-rule-without-filter",
						NonCurrentDays: -1,
						Status:         "enabled"},
					{ExpirationDays: 5,
						Id:             "test07-enabled-5-days-rule-with-filter",
						NonCurrentDays: -1,
						Prefix:         "/test07",
						Status:         "enabled"},
					{ExpirationDays: 3,
						Id:             "test07-enabled-3-days-rule-with-non-current-versions-2-days",
						NonCurrentDays: 2,
						Status:         "enabled"},
				},
			},
		},
		// test "unexpected lifecycle rule filter type (!= LifecycleRuleFilterMemberPrefix)" case
		"test08": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketLifecycleConfigurationOutput{Rules: []types.LifecycleRule{
				{ID: aws.String("test08-disabled-30-days-rule-with-unexpected-filter"),
					Expiration: &types.LifecycleExpiration{Days: 30},
					Status:     types.ExpirationStatusDisabled,
					Filter:     &types.LifecycleRuleFilterMemberAnd{Value: types.LifecycleRuleAndOperator{Prefix: aws.String("/test08")}}}},
			},
			nil,
			Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 30,
						Id:             "test08-disabled-30-days-rule-with-unexpected-filter",
						NonCurrentDays: -1,
						Status:         "disabled"}},
			},
		},
		// test "deprecated Prefix not in Filter struct" case
		"test09": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			&s3.GetBucketLifecycleConfigurationOutput{Rules: []types.LifecycleRule{
				{ID: aws.String("test09-disabled-1-day-rule-with-deprecated-prefix-not-in-filter-struct"),
					Expiration: &types.LifecycleExpiration{Days: 1},
					Status:     types.ExpirationStatusDisabled,
					Prefix:     aws.String("/test09")}},
			},
			nil,
			Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 1,
						Id:             "test09-disabled-1-day-rule-with-deprecated-prefix-not-in-filter-struct",
						NonCurrentDays: -1,
						Prefix:         "/test09",
						Status:         "disabled"}},
			},
		},
	}
	for testName, testData := range parseBucketLifecycleConfigurationTests {
		t.Run(testName, func(t *testing.T) {
			testData.bucket.name = testName
			testData.bucket.parseBucketLifecycleConfiguration(&testData.arg1, testData.arg2, testData.arg3)
			if !reflect.DeepEqual(testData.bucket.LifecycleRules, testData.expected.LifecycleRules) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", testData.bucket.LifecycleRules, testData.expected.LifecycleRules)
			}
		})
	}
}

func TestFillBucketPolicy(t *testing.T) {
	var readWriteActions []string

	readWriteActions = append(readWriteActions, bucketPolicyWriteActions...)
	readWriteActions = append(readWriteActions, bucketPolicyReadActions...)

	fillBucketPolicyTests := map[string]struct {
		arg1     string
		arg2     []string
		arg4     Collector
		bucket   Bucket
		expected []BucketPolicyStatement
	}{
		"test01": {
			"full", []string{"admin", "alice", "bob"},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{FullControl: []string{"admin", "alice"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admin"}},
			},
			[]BucketPolicyStatement{
				{Sid: "test01-full-", Action: []string{"s3:*"}, Effect: "Allow",
					Resource: []string{"arn:aws:s3:::test01"},
					Principal: BucketPolicyPrincipal{
						PrincipalType: []string{"arn:aws:iam:::user/admin:alice", "arn:aws:iam:::user/admin:bob"}},
				},
			},
		},
		"test02": {
			"read", []string{"alice", "bob"},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{Read: []string{"alice"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admin02"}},
			},
			[]BucketPolicyStatement{
				{Sid: "test02-read-", Action: bucketPolicyReadActions, Effect: "Allow",
					Resource: []string{"arn:aws:s3:::test02"},
					Principal: BucketPolicyPrincipal{
						PrincipalType: []string{"arn:aws:iam:::user/admin02:alice", "arn:aws:iam:::user/admin02:bob"}},
				},
			},
		},
		"test03": {
			"write", []string{"alice", "admin03:bob"},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{Write: []string{"bob"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admin03"}},
			},
			[]BucketPolicyStatement{
				{Sid: "test03-write-", Action: readWriteActions, Effect: "Allow",
					Resource: []string{"arn:aws:s3:::test03"},
					Principal: BucketPolicyPrincipal{
						PrincipalType: []string{"arn:aws:iam:::user/admin03:alice", "arn:aws:iam:::user/admin03:bob"}},
				},
			},
		},
		"test04": {
			"read", []string{"admin04"},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			Bucket{
				Acl: BucketAcl{
					Owner: AclOwner{DisplayName: "Admin", Id: "admin04"}},
			},
			[]BucketPolicyStatement{},
		},
	}

	for testName, testData := range fillBucketPolicyTests {
		t.Run(testName, func(t *testing.T) {
			var bucketPolicyStatementArray []BucketPolicyStatement
			testData.bucket.name = testName
			bucketPolicyStatementArray = testData.bucket.fillBucketPolicy(testData.arg1, testData.arg2, bucketPolicyStatementArray, &testData.arg4)
			for index, bps := range bucketPolicyStatementArray {
				expectedBps := testData.expected[index]
				re := regexp.MustCompile(fmt.Sprintf("^%s", expectedBps.Sid))
				if !re.MatchString(bps.Sid) {
					t.Errorf("Output '%s' doesn't match expected Sid pattern '%s'", bps.Sid, expectedBps.Sid)
				}

				// Make generic Sid name the same as expected for reflect comparison
				bps.Sid = expectedBps.Sid
				if !reflect.DeepEqual(bps, expectedBps) {
					t.Errorf("Output %+v not equal to expected %+v", bps, expectedBps)
				}
			}
		})
	}
}

func TestCreateBucketPolicy(t *testing.T) {
	createBucketPolicyTests := map[string]struct {
		arg1     Collector
		bucket   Bucket
		expected string
	}{
		"test01": {
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{FullControl: []string{"admintest01", "alice"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admintest01"}},
			},
			`{"Id":"Policy-test01-","Version":"2012-10-17","Statement":[{"Sid":"test01-full-","Action":["s3:*"],"Effect":"Allow","Resource":["arn:aws:s3:::test01"],"Principal":{"AWS":["arn:aws:iam:::user/admintest01:alice"]}}]}`,
		},
		"test02": {
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{Read: []string{"alice", "bob"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admintest02"}},
			},
			`{"Id":"Policy-test02-","Version":"2012-10-17","Statement":[{"Sid":"test02-read-","Action":["s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test02"],"Principal":{"AWS":["arn:aws:iam:::user/admintest02:alice","arn:aws:iam:::user/admintest02:bob"]}}]}`,
		},
		"test03": {
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{Write: []string{"bob"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admintest03"}},
			},
			`{"Id":"Policy-test03-","Version":"2012-10-17","Statement":[{"Sid":"test03-write-","Action":["s3:AbortMultipartUpload","s3:CreateBucket","s3:DeleteBucket","s3:DeleteBucketPolicy","s3:DeleteBucketWebsite","s3:DeleteObject","s3:DeleteObjectVersion","s3:DeleteReplicationConfiguration","s3:PutAccelerateConfiguration","s3:PutBucketAcl","s3:PutBucketCORS","s3:PutBucketLogging","s3:PutBucketNotification","s3:PutBucketPolicy","s3:PutBucketRequestPayment","s3:PutBucketTagging","s3:PutBucketVersioning","s3:PutBucketWebsite","s3:PutLifecycleConfiguration","s3:PutObject","s3:PutObjectAcl","s3:PutObjectVersionAcl","s3:PutReplicationConfiguration","s3:RestoreObject","s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test03"],"Principal":{"AWS":["arn:aws:iam:::user/admintest03:bob"]}}]}`,
		},
		"test04": {
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admin"}},
			},
			``,
		},
		"test05": {
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{FullControl: []string{"admintest05", "alice"}, Read: []string{"bob"}, Write: []string{"bob", "alice"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admintest05"}},
			},
			`{"Id":"Policy-test05-","Version":"2012-10-17","Statement":[{"Sid":"test05-full-","Action":["s3:*"],"Effect":"Allow","Resource":["arn:aws:s3:::test05"],"Principal":{"AWS":["arn:aws:iam:::user/admintest05:alice"]}},{"Sid":"test05-read-","Action":["s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test05"],"Principal":{"AWS":["arn:aws:iam:::user/admintest05:bob"]}},{"Sid":"test05-write-","Action":["s3:AbortMultipartUpload","s3:CreateBucket","s3:DeleteBucket","s3:DeleteBucketPolicy","s3:DeleteBucketWebsite","s3:DeleteObject","s3:DeleteObjectVersion","s3:DeleteReplicationConfiguration","s3:PutAccelerateConfiguration","s3:PutBucketAcl","s3:PutBucketCORS","s3:PutBucketLogging","s3:PutBucketNotification","s3:PutBucketPolicy","s3:PutBucketRequestPayment","s3:PutBucketTagging","s3:PutBucketVersioning","s3:PutBucketWebsite","s3:PutLifecycleConfiguration","s3:PutObject","s3:PutObjectAcl","s3:PutObjectVersionAcl","s3:PutReplicationConfiguration","s3:RestoreObject","s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test05"],"Principal":{"AWS":["arn:aws:iam:::user/admintest05:bob","arn:aws:iam:::user/admintest05:alice"]}}]}`,
		},
	}

	for testName, testData := range createBucketPolicyTests {
		t.Run(testName, func(t *testing.T) {
			testData.bucket.name = testName
			got, err := testData.bucket.createBucketPolicy(&testData.arg1)
			rePolicy := regexp.MustCompile(fmt.Sprintf("\"Policy-%s-\\d{19,19}\"", testData.bucket.name))
			reSpaces := regexp.MustCompile(`\s|\n`)
			// replace unix time from generic Policy name
			got = rePolicy.ReplaceAllString(got, fmt.Sprintf("\"Policy-%s-\"", testData.bucket.name))

			// replace unix time from generic Sid name
			for _, operation := range []string{"full", "read", "write"} {
				reSid := regexp.MustCompile(fmt.Sprintf("\"%s-%s-\\d{19,19}\"", testData.bucket.name, operation))
				got = reSid.ReplaceAllString(got, fmt.Sprintf("\"%s-%s-\"", testData.bucket.name, operation))
			}
			// replace spaces and newline symbols from Policy string
			got = reSpaces.ReplaceAllString(got, "")

			if got != testData.expected {
				t.Errorf("Output '%s' not equal to expected '%s'", got, testData.expected)
			}

			if err != nil && testName != "test04" {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
		})
	}
}

func TestHasKey(t *testing.T) {
	hasKeyTests := map[string]struct {
		bucketsArray buckets
		key          string
		expected     bool
	}{
		"test01": {
			buckets{"bucketTest01-01": Bucket{}, "bucketTest01-02": Bucket{}, "bucketTest01-03": Bucket{}},
			"bucketTest01-01",
			true,
		},
		"test02": {
			buckets{"bucketTest02-01": Bucket{}, "bucketTest02-02": Bucket{}, "bucketTest02-03": Bucket{}},
			"bucketTest02-02",
			true,
		},
		"test03": {
			buckets{"bucketTest03-01": Bucket{}, "bucketTest03-02": Bucket{}, "bucketTest03-03": Bucket{}},
			"bucketTest03-00",
			false,
		},
	}

	for testName, testData := range hasKeyTests {
		t.Run(testName, func(t *testing.T) {
			if got := testData.bucketsArray.hasKey(testData.key); got != testData.expected {
				t.Errorf("Output '%t' not equal to expected '%t'", got, testData.expected)
			}
		})
	}
}

func TestCompareBuckets(t *testing.T) {
	compareBucketsTests := map[string]struct {
		arg1            buckets
		arg2            buckets
		expectedBuckets buckets
		expectedAnswer  bool
		arg3            Collector
	}{
		"test01": {
			buckets{"bucketTest01-01": Bucket{}, "bucketTest01-02": Bucket{}, "bucketTest01-03": Bucket{}},
			buckets{"bucketTest01-01": Bucket{}, "bucketTest01-02": Bucket{}, "bucketTest01-03": Bucket{}},
			buckets{"bucketTest01-01": Bucket{}, "bucketTest01-02": Bucket{}, "bucketTest01-03": Bucket{}},
			false,
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
		},
		"test02": {
			buckets{"bucketTest02-01": Bucket{}, "bucketTest02-02": Bucket{}, "bucketTest02-03": Bucket{}},
			buckets{"bucketTest02-01": Bucket{}, "bucketTest02-02": Bucket{}},
			buckets{"bucketTest02-01": Bucket{}, "bucketTest02-02": Bucket{}, "bucketTest02-03": Bucket{
				AclType: "new", BucketType: "new", LifecycleType: "new",
			}},
			true,
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
		},
		"test03": {
			buckets{"bucketTest03-01": Bucket{}, "bucketTest03-02": Bucket{}, "bucketTest03-03": Bucket{
				Acl: BucketAcl{
					Owner: AclOwner{DisplayName: "AdminTest03", Id: "admintest03"},
					Grants: AclGrants{
						FullControl: []string{"admintest03", "alice"},
						Read:        []string{"bob"},
						Write:       []string{"bob"}},
				},
			}},
			buckets{"bucketTest03-01": Bucket{}, "bucketTest03-02": Bucket{}, "bucketTest03-03": Bucket{}},
			buckets{"bucketTest03-01": Bucket{}, "bucketTest03-02": Bucket{},
				"bucketTest03-03": Bucket{
					Acl: BucketAcl{
						Grants: AclGrants{
							FullControl: []string{"admintest03", "alice"},
							Read:        []string{"bob"},
							Write:       []string{"bob"}},
					},
					AclType: "updated",
				}},
			true,
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
		},
		"test04": {
			buckets{"bucketTest04-01": Bucket{}, "bucketTest04-02": Bucket{}, "bucketTest04-03": Bucket{
				Versioning: "enabled",
			}},
			buckets{"bucketTest04-01": Bucket{}, "bucketTest04-02": Bucket{}, "bucketTest04-03": Bucket{}},
			buckets{"bucketTest04-01": Bucket{}, "bucketTest04-02": Bucket{}, "bucketTest04-03": Bucket{
				Versioning:     "enabled",
				VersioningType: "updated",
			}},
			true,
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
		},
		"test05": {
			buckets{"bucketTest05-01": Bucket{}, "bucketTest05-02": Bucket{}, "bucketTest05-03": Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 50, NonCurrentDays: 5, Prefix: "/test05", Status: "enabled"},
					{ExpirationDays: 55, NonCurrentDays: 15, Prefix: "/test05-02", Status: "disabled"},
				},
			}},
			buckets{"bucketTest05-01": Bucket{}, "bucketTest05-02": Bucket{}, "bucketTest05-03": Bucket{}},
			buckets{"bucketTest05-01": Bucket{}, "bucketTest05-02": Bucket{}, "bucketTest05-03": Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 50, NonCurrentDays: 5, Prefix: "/test05", Status: "enabled"},
					{ExpirationDays: 55, NonCurrentDays: 15, Prefix: "/test05-02", Status: "disabled"},
				},
				LifecycleType: "updated",
			}},
			true,
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
		},
	}

	for testName, testData := range compareBucketsTests {
		t.Run(testName, func(t *testing.T) {
			gotBuckets, gotAnswer := compareBuckets(testData.arg1, testData.arg2, &testData.arg3)
			if !reflect.DeepEqual(gotBuckets, testData.expectedBuckets) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", gotBuckets, testData.expectedBuckets)
			}
			if gotAnswer != testData.expectedAnswer {
				t.Errorf("Output '%t' not equal to expected '%t'", gotAnswer, testData.expectedAnswer)
			}
		})
	}
}

func TestPrepareLifecycleConfiguration(t *testing.T) {
	prepareLifecycleConfigurationTests := map[string]struct {
		bucket   Bucket
		arg1     Collector
		expected []types.LifecycleRule
	}{
		"test01": {
			Bucket{},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			[]types.LifecycleRule{},
		},
		"test02": {
			Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 20,
						Id:             "test02-enabled-20-days-rule-without-filter",
						NonCurrentDays: 5,
						Status:         "enabled"}},
				Versioning: "suspended",
			},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			[]types.LifecycleRule{
				{Expiration: &types.LifecycleExpiration{Days: 20},
					ID:     aws.String("test02-enabled-20-days-rule-without-filter"),
					Status: types.ExpirationStatusEnabled}},
		},
		"test03": {
			Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 30,
						Id:             "test03-enabled-30-days-rule-without-filter",
						NonCurrentDays: 5,
						Status:         "enabled"}},
				Versioning: "enabled",
			},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			[]types.LifecycleRule{
				{Expiration: &types.LifecycleExpiration{Days: 30},
					ID:                          aws.String("test03-enabled-30-days-rule-without-filter"),
					Status:                      types.ExpirationStatusEnabled,
					NoncurrentVersionExpiration: &types.NoncurrentVersionExpiration{NoncurrentDays: 5}}},
		},
		"test04": {
			Bucket{
				LifecycleRules: []LifecycleRule{
					{ExpirationDays: 40,
						Id:             "test04-enabled-40-days-rule-without-filter",
						NonCurrentDays: 5,
						Status:         "enabled",
						Prefix:         "/test04"}},
				Versioning: "enabled",
			},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			[]types.LifecycleRule{
				{Expiration: &types.LifecycleExpiration{Days: 40},
					ID:                          aws.String("test04-enabled-40-days-rule-without-filter"),
					Status:                      types.ExpirationStatusEnabled,
					NoncurrentVersionExpiration: &types.NoncurrentVersionExpiration{NoncurrentDays: 5},
					Filter:                      &types.LifecycleRuleFilterMemberPrefix{Value: "/test04"}}},
		},
	}

	for testName, testData := range prepareLifecycleConfigurationTests {
		t.Run(testName, func(t *testing.T) {
			testData.bucket.name = testName
			got := testData.bucket.prepareLifecycleConfiguration(&testData.arg1)
			if !reflect.DeepEqual(got, testData.expected) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", got, testData.expected)
			}
		})
	}
}

func TestCheckBucketName(t *testing.T) {
	checkBucketNameTests := map[string]struct {
		bucketName    string
		errorExpected bool
	}{
		"test01": {"abc", false},
		"test02": {"ab-c", false},
		"test03": {"", true},
		"test04": {"192.168.0.1", true},
		"test05": {"ab", true},
		"test06": {"test-long-bucket-name-more-than-63-characters-test-test-test-tes", true},
		"test07": {"# test comment string", true},
		"test08": {"abc-", true},
		"test09": {"ab_c", true},
		"test10": {"aBc", true},
	}

	for testName, testData := range checkBucketNameTests {
		t.Run(testName, func(t *testing.T) {
			gotError := checkBucketName(testData.bucketName)
			if gotError != nil {
				if !testData.errorExpected {
					t.Errorf("Output got unexpected error '%+v' with bucket name '%s'", gotError, testData.bucketName)
				}
			}

			if gotError == nil {
				if testData.errorExpected {
					t.Errorf("Output got nothing, but error expected with bucket name '%s'", testData.bucketName)
				}
			}
		})
	}
}

func TestCheckBucketNamePostfix(t *testing.T) {
	checkBucketNamePostfixTests := map[string]struct {
		bucket    types.Bucket
		collector Collector
		postfix   string
		expected  string
	}{
		"test01": {
			types.Bucket{Name: aws.String("test01-test")},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			"-test",
			"test01",
		},
		"test02": {
			types.Bucket{Name: aws.String("test02")},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			"-test",
			"test02",
		},
		"test03": {
			types.Bucket{Name: aws.String("test03")},
			Collector{Logger: collector.Logger, LoggerDebug: collector.LoggerDebug},
			"",
			"test03",
		},
	}

	for testName, testData := range checkBucketNamePostfixTests {
		t.Run(testName, func(t *testing.T) {
			testData.collector.BucketsPostfix = testData.postfix
			if got := checkBucketNamePostfix(*testData.bucket.Name, &testData.collector); got != testData.expected {
				t.Errorf("Output '%s' not equal to expected '%s'", got, testData.expected)
			}
		})
	}
}
