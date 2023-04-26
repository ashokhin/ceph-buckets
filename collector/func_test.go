package collector

import (
	"testing"

	"github.com/go-kit/log"
)

func TestKeyInArray(t *testing.T) {
	keyInArrayTests := map[string]struct {
		arg1     []string
		arg2     string
		expected bool
	}{
		"test01": {
			[]string{"someKey01", "someKey02", "testKey01", "someKey03"}, "testKey01", true,
		},
		"test02": {
			[]string{"someKey01", "someKey02", "testKey03", "someKey03"}, "testKey02", false,
		},
	}

	for testName, testData := range keyInArrayTests {
		t.Run(testName, func(t *testing.T) {
			if got := keyInArray(testData.arg1, testData.arg2); got != testData.expected {
				t.Errorf("Output '%t' not equal to expected '%t'", got, testData.expected)
			}
		})
	}
}

func TestArrayIsEqual(t *testing.T) {
	arrayIsEqualTests := map[string]struct {
		arg1     []string
		arg2     []string
		expected bool
	}{
		"test01": {
			[]string{"a", "b", "c", "d"}, []string{"b", "a", "d", "c"}, true,
		},
		"test02": {
			[]string{"a", "b", "c", "d"}, []string{"b", "a", "c", "e"}, false,
		},
	}

	for testName, testData := range arrayIsEqualTests {
		t.Run(testName, func(t *testing.T) {
			if got := arrayIsEqual(testData.arg1, testData.arg2); got != testData.expected {
				t.Errorf("Output '%t' not equal to expected '%t'", got, testData.expected)
			}
		})
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
	getUsersFromPrincipalArrayTests := map[string]struct {
		arg1     []string
		expected []string
	}{
		"test01": {
			[]string{"arn:aws:iam::123:user/bob", "arn:aws:iam::123:user/bob:alice", "arn:aws:iam::123:user/carol"},
			[]string{"bob", "bob:alice", "carol"},
		},
		"test02": {
			[]string{"arn:aws:iam::123:user/alice:bob", "arn:aws:iam::123:user/bob:carol", "arn:aws:iam::123:user/alice"},
			[]string{"alice:bob", "bob:carol", "alice"},
		},
	}

	for testName, testData := range getUsersFromPrincipalArrayTests {
		t.Run(testName, func(t *testing.T) {
			if got := getUsersFromPrincipalArray(testData.arg1); !arrayIsEqual(got, testData.expected) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", got, testData.expected)
			}
		})
	}
}

func TestRecordToArr(t *testing.T) {
	recordToArrTests := map[string]struct {
		arg1     string
		expected []string
	}{
		"test01": {"alice bob", []string{"alice", "bob"}},
		"test02": {"carol chuck", []string{"carol", "chuck"}},
	}

	for testName, testData := range recordToArrTests {
		t.Run(testName, func(t *testing.T) {
			if got := recordToArr(testData.arg1); !arrayIsEqual(got, testData.expected) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", got, testData.expected)
			}
		})
	}
}

func TestAclIsEqual(t *testing.T) {
	aclIsEqualTests := map[string]struct {
		arg1     Bucket
		arg2     Bucket
		arg3     string
		arg4     log.Logger
		expected bool
	}{
		"test01": {
			Bucket{Acl: BucketAcl{Grants: AclGrants{FullControl: []string{"alice", "bob", "carol"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{FullControl: []string{"bob", "carol", "alice"}}}},
			"test01fullControlAliceBobCarolEqual",
			collector.Logger,
			true,
		},
		"test02": {
			Bucket{Acl: BucketAcl{Grants: AclGrants{Read: []string{"alice", "bob"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{Read: []string{"bob", "alice"}}}},
			"test02readAliceBobEqual",
			collector.Logger,
			true,
		},
		"test03": {
			Bucket{Acl: BucketAcl{Grants: AclGrants{Write: []string{"alice", "carol"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{Write: []string{"carol", "alice"}}}},
			"test03writeAliceCarolEqual",
			collector.Logger,
			true,
		},
		"test04": {
			Bucket{Acl: BucketAcl{Grants: AclGrants{FullControl: []string{"bob", "alice"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{FullControl: []string{"alice", "carol"}}}},
			"test04fullControlBobAliceNotEqual",
			collector.Logger,
			false,
		},
		"test05": {
			Bucket{Acl: BucketAcl{Grants: AclGrants{Read: []string{"alice", "bob"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{Read: []string{"bob", "carol"}}}},
			"test05readAliceBobNotEqual",
			collector.Logger,
			false,
		},
		"test06": {
			Bucket{Acl: BucketAcl{Grants: AclGrants{Write: []string{"carol", "alice"}}}},
			Bucket{Acl: BucketAcl{Grants: AclGrants{Write: []string{"alice", "bob", "carol"}}}},
			"test06writeCarolAliceNotEqual",
			collector.Logger,
			false,
		},
	}

	for testName, testData := range aclIsEqualTests {
		t.Run(testName, func(t *testing.T) {
			if got := aclIsEqual(testData.arg1, testData.arg2, testData.arg3, testData.arg4); got != testData.expected {
				t.Errorf("Output '%t' not equal to expected '%t' in test '%s'", got, testData.expected, testData.arg3)
			}
		})
	}
}

func TestLfcIsEqual(t *testing.T) {
	lfcIsEqualTests := map[string]struct {
		arg1     []LifecycleRule
		arg2     []LifecycleRule
		arg3     string
		arg4     log.Logger
		expected bool
	}{
		"test01": {
			[]LifecycleRule{
				{ExpirationDays: 30, Id: "test01a", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 15, Id: "test01b", NonCurrentDays: 10, Prefix: "/delete", Status: "Disabled"},
			},
			[]LifecycleRule{
				{ExpirationDays: 30, Id: "test01a", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 15, Id: "test01b", NonCurrentDays: 10, Prefix: "/delete", Status: "Disabled"},
			},
			"test01Equal",
			collector.Logger,
			true,
		},
		"test02": {
			[]LifecycleRule{
				{ExpirationDays: 30, Id: "test02a", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 15, Id: "test02b", NonCurrentDays: 10, Prefix: "/delete", Status: "Disabled"},
			},
			[]LifecycleRule{
				{ExpirationDays: 30, Id: "test02a", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
			},
			"test02NotEqual",
			collector.Logger,
			false,
		},
		"test03": {
			[]LifecycleRule{
				{ExpirationDays: 14, Id: "test03a", NonCurrentDays: 5, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 10, Id: "test03b", NonCurrentDays: 1, Prefix: "/done", Status: "Enabled"},
			},
			[]LifecycleRule{
				{ExpirationDays: 14, Id: "test03a", NonCurrentDays: 5, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 10, Id: "test03b", NonCurrentDays: 3, Prefix: "/delete", Status: "Disabled"},
			},
			"test03NotEqual",
			collector.Logger,
			false,
		},
		"test04": {
			[]LifecycleRule{
				{ExpirationDays: 14, Id: "test04a", NonCurrentDays: 5, Prefix: "/done", Status: "Enabled"},
				{ExpirationDays: 10, Id: "test04b", NonCurrentDays: 3, Prefix: "/delete", Status: "Disabled"},
			},
			[]LifecycleRule{
				{ExpirationDays: 10, Id: "test04b", NonCurrentDays: 3, Prefix: "/delete", Status: "Disabled"},
				{ExpirationDays: 14, Id: "test04a", NonCurrentDays: 5, Prefix: "/done", Status: "Enabled"},
			},
			"test04NotEqual",
			collector.Logger,
			false,
		},
	}

	for testName, testData := range lfcIsEqualTests {
		t.Run(testName, func(t *testing.T) {
			if got := lfcIsEqual(testData.arg1, testData.arg2, testData.arg3, testData.arg4); got != testData.expected {
				t.Errorf("Output '%t' not equal to expected '%t' in test '%s'", got, testData.expected, testData.arg3)
			}
		})
	}
}
