package collector

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var collector Collector

func init() {
	collector.Logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	collector.Logger = level.NewFilter(collector.Logger, level.AllowDebug())
}

func TestFillBucketPolicy(t *testing.T) {
	var readWriteActions []string

	readWriteActions = append(readWriteActions, bucketPolicyWriteActions...)
	readWriteActions = append(readWriteActions, bucketPolicyReadActions...)

	fillBucketPolicyTests := map[string]struct {
		arg1     string
		arg2     []string
		arg4     *Collector
		bucket   *Bucket
		expected []BucketPolicyStatement
	}{
		"test01": {
			"full", []string{"admin", "alice", "bob"},
			&collector,
			&Bucket{
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
			&collector,
			&Bucket{
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
			&collector,
			&Bucket{
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
			&collector,
			&Bucket{
				Acl: BucketAcl{
					Owner: AclOwner{DisplayName: "Admin", Id: "admin04"}},
			},
			[]BucketPolicyStatement{},
		},
	}

	var b *Bucket

	for fbpTestName, fbpTestData := range fillBucketPolicyTests {
		t.Run(fbpTestName, func(t *testing.T) {
			var bucketPolicyStatementArray []BucketPolicyStatement
			b = fbpTestData.bucket
			b.name = fbpTestName
			bucketPolicyStatementArray = b.fillBucketPolicy(fbpTestData.arg1, fbpTestData.arg2, bucketPolicyStatementArray, fbpTestData.arg4)
			for index, bps := range bucketPolicyStatementArray {
				expectedBps := fbpTestData.expected[index]
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
		collector *Collector
		bucket    *Bucket
		expected  string
	}{
		"test01": {
			&collector,
			&Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{FullControl: []string{"admintest01", "alice"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admintest01"}},
			},
			`{"Id":"Policy-test01-","Version":"2012-10-17","Statement":[{"Sid":"test01-full-","Action":["s3:*"],"Effect":"Allow","Resource":["arn:aws:s3:::test01"],"Principal":{"AWS":["arn:aws:iam:::user/admintest01:alice"]}}]}`,
		},
		"test02": {
			&collector,
			&Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{Read: []string{"alice", "bob"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admintest02"}},
			},
			`{"Id":"Policy-test02-","Version":"2012-10-17","Statement":[{"Sid":"test02-read-","Action":["s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test02"],"Principal":{"AWS":["arn:aws:iam:::user/admintest02:alice","arn:aws:iam:::user/admintest02:bob"]}}]}`,
		},
		"test03": {
			&collector,
			&Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{Write: []string{"bob"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admintest03"}},
			},
			`{"Id":"Policy-test03-","Version":"2012-10-17","Statement":[{"Sid":"test03-write-","Action":["s3:AbortMultipartUpload","s3:CreateBucket","s3:DeleteBucket","s3:DeleteBucketPolicy","s3:DeleteBucketWebsite","s3:DeleteObject","s3:DeleteObjectVersion","s3:DeleteReplicationConfiguration","s3:PutAccelerateConfiguration","s3:PutBucketAcl","s3:PutBucketCORS","s3:PutBucketLogging","s3:PutBucketNotification","s3:PutBucketPolicy","s3:PutBucketRequestPayment","s3:PutBucketTagging","s3:PutBucketVersioning","s3:PutBucketWebsite","s3:PutLifecycleConfiguration","s3:PutObject","s3:PutObjectAcl","s3:PutObjectVersionAcl","s3:PutReplicationConfiguration","s3:RestoreObject","s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test03"],"Principal":{"AWS":["arn:aws:iam:::user/admintest03:bob"]}}]}`,
		},
		"test04": {
			&collector,
			&Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admin"}},
			},
			``,
		},
		"test05": {
			&collector,
			&Bucket{
				Acl: BucketAcl{
					Grants: AclGrants{FullControl: []string{"admintest05", "alice"}, Read: []string{"bob"}, Write: []string{"bob", "alice"}},
					Owner:  AclOwner{DisplayName: "Admin", Id: "admintest05"}},
			},
			`{"Id":"Policy-test05-","Version":"2012-10-17","Statement":[{"Sid":"test05-full-","Action":["s3:*"],"Effect":"Allow","Resource":["arn:aws:s3:::test05"],"Principal":{"AWS":["arn:aws:iam:::user/admintest05:alice"]}},{"Sid":"test05-read-","Action":["s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test05"],"Principal":{"AWS":["arn:aws:iam:::user/admintest05:bob"]}},{"Sid":"test05-write-","Action":["s3:AbortMultipartUpload","s3:CreateBucket","s3:DeleteBucket","s3:DeleteBucketPolicy","s3:DeleteBucketWebsite","s3:DeleteObject","s3:DeleteObjectVersion","s3:DeleteReplicationConfiguration","s3:PutAccelerateConfiguration","s3:PutBucketAcl","s3:PutBucketCORS","s3:PutBucketLogging","s3:PutBucketNotification","s3:PutBucketPolicy","s3:PutBucketRequestPayment","s3:PutBucketTagging","s3:PutBucketVersioning","s3:PutBucketWebsite","s3:PutLifecycleConfiguration","s3:PutObject","s3:PutObjectAcl","s3:PutObjectVersionAcl","s3:PutReplicationConfiguration","s3:RestoreObject","s3:GetAccelerateConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetBucketLocation","s3:GetBucketLogging","s3:GetBucketNotification","s3:GetBucketPolicy","s3:GetBucketRequestPayment","s3:GetBucketTagging","s3:GetBucketVersioning","s3:GetBucketWebsite","s3:GetLifecycleConfiguration","s3:GetObject","s3:GetObjectAcl","s3:GetObjectTorrent","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTorrent","s3:GetReplicationConfiguration","s3:ListAllMyBuckets","s3:ListBucket","s3:ListBucketMultipartUploads","s3:ListBucketVersions","s3:ListMultipartUploadParts"],"Effect":"Allow","Resource":["arn:aws:s3:::test05"],"Principal":{"AWS":["arn:aws:iam:::user/admintest05:bob","arn:aws:iam:::user/admintest05:alice"]}}]}`,
		},
	}

	var b *Bucket

	for testName, testData := range createBucketPolicyTests {
		t.Run(testName, func(t *testing.T) {
			b = testData.bucket
			b.name = testName
			gotString, err := b.createBucketPolicy(testData.collector)
			rePolicy := regexp.MustCompile(fmt.Sprintf("\"Policy-%s-\\d{19,19}\"", testData.bucket.name))
			reSpaces := regexp.MustCompile(`\s|\n`)
			// replace unix time from generic Policy name
			gotString = rePolicy.ReplaceAllString(gotString, fmt.Sprintf("\"Policy-%s-\"", testData.bucket.name))

			// replace unix time from generic Sid name
			for _, operation := range []string{"full", "read", "write"} {
				reSid := regexp.MustCompile(fmt.Sprintf("\"%s-%s-\\d{19,19}\"", testData.bucket.name, operation))
				gotString = reSid.ReplaceAllString(gotString, fmt.Sprintf("\"%s-%s-\"", testData.bucket.name, operation))
			}
			// replace spaces and newline symbols from Policy string
			gotString = reSpaces.ReplaceAllString(gotString, "")

			if gotString != testData.expected {
				t.Errorf("Output '%s' not equal to expected '%s'", gotString, testData.expected)
			}

			if err != nil && testName != "test04" {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
		})
	}
}

func TestHasKey(t *testing.T) {
	hasKeyTests := map[string]struct {
		b    buckets
		key  string
		want bool
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
			if got := testData.b.hasKey(testData.key); got != testData.want {
				t.Errorf("Output %t not equal to expected %t", got, testData.want)
			}
		})
	}
}

func TestCompareBuckets(t *testing.T) {
	compareBucketsTests := map[string]struct {
		localBuckets    buckets
		serverBuckets   buckets
		expectedBuckets buckets
		expectedAnswer  bool
		collector       *Collector
	}{
		"test01": {
			buckets{"bucketTest01-01": Bucket{}, "bucketTest01-02": Bucket{}, "bucketTest01-03": Bucket{}},
			buckets{"bucketTest01-01": Bucket{}, "bucketTest01-02": Bucket{}, "bucketTest01-03": Bucket{}},
			buckets{"bucketTest01-01": Bucket{}, "bucketTest01-02": Bucket{}, "bucketTest01-03": Bucket{}},
			false,
			&collector,
		},
		"test02": {
			buckets{"bucketTest02-01": Bucket{}, "bucketTest02-02": Bucket{}, "bucketTest02-03": Bucket{}},
			buckets{"bucketTest02-01": Bucket{}, "bucketTest02-02": Bucket{}},
			buckets{"bucketTest02-01": Bucket{}, "bucketTest02-02": Bucket{}, "bucketTest02-03": Bucket{
				AclType: "new", BucketType: "new", LifecycleType: "new",
			}},
			true,
			&collector,
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
			&collector,
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
			&collector,
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
			&collector,
		},
	}

	for testName, testData := range compareBucketsTests {
		t.Run(testName, func(t *testing.T) {
			gotBuckets, gotAnswer := compareBuckets(testData.localBuckets, testData.serverBuckets, testData.collector.Logger)
			if !reflect.DeepEqual(gotBuckets, testData.expectedBuckets) {
				t.Errorf("Output %+v not equal to expected %+v", gotBuckets, testData.expectedBuckets)
			}
			if gotAnswer != testData.expectedAnswer {
				t.Errorf("Output %t not equal to expected %t", gotAnswer, testData.expectedAnswer)
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
					t.Errorf("Output got unexpected error %v", gotError)
				}
			}

			if gotError == nil {
				if testData.errorExpected {
					t.Error("Output got nothing, but error expected")
				}
			}
		})
	}
}

func TestCheckBucketNamePostfix(t *testing.T) {
	checkBucketNamePostfixTests := map[string]struct {
		bucket    types.Bucket
		collector *Collector
		postfix   string
		want      string
	}{
		"test01": {
			types.Bucket{Name: aws.String("test01-test")},
			&collector,
			"-test",
			"test01",
		},
		"test02": {
			types.Bucket{Name: aws.String("test02")},
			&collector,
			"-test",
			"test02",
		},
		"test03": {
			types.Bucket{Name: aws.String("test03")},
			&collector,
			"",
			"test03",
		},
	}

	for testName, testData := range checkBucketNamePostfixTests {
		t.Run(testName, func(t *testing.T) {
			testData.collector.BucketsPostfix = testData.postfix
			if got := checkBucketNamePostfix(testData.bucket, testData.collector); got != testData.want {
				t.Errorf("Output '%s' not equal to expected '%s'", got, testData.want)
			}
		})
	}
}
