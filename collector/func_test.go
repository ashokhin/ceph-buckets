package collector

import (
	"os"
	"testing"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var logger log.Logger

func init() {
	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	logger = level.NewFilter(logger, level.AllowNone())
}

func TestKeyInArray(t *testing.T) {
	type keyInArayTest struct {
		keyArg   string
		arrayArg []string
		want     bool
	}

	keyInArayTests := []keyInArayTest{
		{"testKey01", []string{"someKey01", "someKey02", "testKey01", "someKey03"}, true},
		{"testKey02", []string{"someKey01", "someKey02", "testKey03", "someKey03"}, false},
		{},
	}

	for _, test := range keyInArayTests {
		if got := keyInArray(test.arrayArg, test.keyArg); got != test.want {
			t.Errorf("Output %v not equal to expected %v", got, test.want)
		}
	}
}

func TestArrayIsEqual(t *testing.T) {
	type arrayIsEqualTest struct {
		arraysOfStrings [][]string
		want            bool
	}

	arrayIsEqualTests := []arrayIsEqualTest{
		{
			[][]string{
				{"a", "b", "c", "d"},
				{"b", "a", "d", "c"},
			},
			true,
		},
		{
			[][]string{
				{"a", "b", "c", "d"},
				{"b", "a", "c", "c"},
			},
			false,
		},
	}

	for _, test := range arrayIsEqualTests {
		if got := arrayIsEqual(test.arraysOfStrings[0], test.arraysOfStrings[1]); got != test.want {
			t.Errorf("Output %v not equal to expected %v", got, test.want)
		}
	}
}

func BenchmarkArrayIsEqual(b *testing.B) {
	arrOfArr := [][]string{
		{"a", "b", "c", "d"},
		{"b", "a", "c", "d"},
	}

	for i := 0; i < b.N; i++ {
		arrayIsEqual(arrOfArr[0], arrOfArr[1])
	}
}

func TestGetUsersFromPrincipalArray(t *testing.T) {
	type getUsersFromPrincipalArrayTest struct {
		inArray       []string
		expectedArray []string
	}

	getUsersFromPrincipalArrayTests := []getUsersFromPrincipalArrayTest{
		{
			[]string{"arn:aws:iam::123:user/bob", "arn:aws:iam::123:user/bob:alice", "arn:aws:iam::123:user/carol"},
			[]string{"bob", "bob:alice", "carol"},
		},
		{
			[]string{"arn:aws:iam::123:user/alice:bob", "arn:aws:iam::123:user/bob:carol", "arn:aws:iam::123:user/alice"},
			[]string{"alice:bob", "bob:carol", "alice"},
		},
	}

	for _, test := range getUsersFromPrincipalArrayTests {
		if got := getUsersFromPrincipalArray(test.inArray); !arrayIsEqual(got, test.expectedArray) {
			t.Errorf("Output %v not equal to expected %v", got, test.expectedArray)
		}
	}
}

func TestRecordToArr(t *testing.T) {
	type recToArrTest struct {
		arg  string
		want []string
	}

	recToArrTests := []recToArrTest{
		{"alice bob", []string{"alice", "bob"}},
		{"carol chuck", []string{"carol", "chuck"}},
	}

	for _, test := range recToArrTests {
		if got := recordToArr(test.arg); !arrayIsEqual(got, test.want) {
			t.Errorf("Output %v not equal to expected %v", got, test.want)
		}
	}
}

func TestAclEqual(t *testing.T) {
	type aclEqualTest struct {
		arg1 Bucket
		arg2 Bucket
		arg3 string
		want bool
	}

	aclEqualTests := []aclEqualTest{
		{
			Bucket{Acl: BucketAcl{Grants: AclGrants{FullControl: []string{"alice", "bob", "carol"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{FullControl: []string{"bob", "carol", "alice"}}}},
			"test01fullControlAliceBobCarolEqual",
			true,
		},
		{
			Bucket{Acl: BucketAcl{Grants: AclGrants{Read: []string{"alice", "bob"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{Read: []string{"bob", "alice"}}}},
			"test02readAliceBobEqual",
			true,
		},
		{
			Bucket{Acl: BucketAcl{Grants: AclGrants{Write: []string{"alice", "carol"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{Write: []string{"carol", "alice"}}}},
			"test03writeAliceCarolEqual",
			true,
		},
		{
			Bucket{Acl: BucketAcl{Grants: AclGrants{FullControl: []string{"bob", "alice"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{FullControl: []string{"alice", "carol"}}}},
			"test04fullControlBobAliceNotEqual",
			false,
		},
		{
			Bucket{Acl: BucketAcl{Grants: AclGrants{Read: []string{"alice", "bob"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{Read: []string{"bob", "carol"}}}},
			"test05readAliceBobNotEqual",
			false,
		},
		{
			Bucket{Acl: BucketAcl{Grants: AclGrants{Write: []string{"carol", "alice"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{Write: []string{"alice", "bob", "carol"}}}},
			"test06writeCarolAliceNotEqual",
			false,
		},
	}

	for _, test := range aclEqualTests {
		if got := aclIsEqual(test.arg1, test.arg2, test.arg3, logger); got != test.want {
			t.Errorf("Output %v not equal to expected %v in test %v", got, test.want, test.arg3)
		}
	}
}

func TestLfcIsEqual(t *testing.T) {
	type lfcIsEqualTest struct {
		arg1 []LifecycleRule
		arg2 []LifecycleRule
		arg3 string
		want bool
	}

	lfcIsEqualTests := []lfcIsEqualTest{
		{
			[]LifecycleRule{
				{ExpirationDays: 30, Id: "test01a", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 15, Id: "test01b", NonCurrentDays: 10, Prefix: "/delete", Status: "Disabled"},
			},
			[]LifecycleRule{
				{ExpirationDays: 30, Id: "test01a", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 15, Id: "test01b", NonCurrentDays: 10, Prefix: "/delete", Status: "Disabled"},
			},
			"test01Equal",
			true,
		},
		{
			[]LifecycleRule{
				{ExpirationDays: 30, Id: "test02a", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 15, Id: "test02b", NonCurrentDays: 10, Prefix: "/delete", Status: "Disabled"},
			},
			[]LifecycleRule{
				{ExpirationDays: 30, Id: "test02a", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
			},
			"test02NotEqual",
			false,
		},
		{
			[]LifecycleRule{
				{ExpirationDays: 14, Id: "test03a", NonCurrentDays: 5, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 10, Id: "test03b", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
			},
			[]LifecycleRule{
				{ExpirationDays: 14, Id: "test03a", NonCurrentDays: 5, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 10, Id: "test03b", NonCurrentDays: 3, Prefix: "/delete", Status: "Disabled"},
			},
			"test03NotEqual",
			false,
		},
		{
			[]LifecycleRule{
				{ExpirationDays: 14, Id: "test04a", NonCurrentDays: 5, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 10, Id: "test04b", NonCurrentDays: 3, Prefix: "/delete", Status: "Disabled"},
			},
			[]LifecycleRule{
				{ExpirationDays: 10, Id: "test04b", NonCurrentDays: 3, Prefix: "/delete", Status: "Disabled"},
				{ExpirationDays: 14, Id: "test04a", NonCurrentDays: 5, Prefix: "/done", Status: "Enabled"},
			},
			"test04NotEqual",
			false,
		},
	}

	for _, test := range lfcIsEqualTests {
		if got := lfcIsEqual(test.arg1, test.arg2, test.arg3, logger); got != test.want {
			t.Errorf("Output %v not equal to expected %v in test %v", got, test.want, test.arg3)
		}
	}
}
