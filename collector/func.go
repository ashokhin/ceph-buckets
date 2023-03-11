package collector

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func keyInArray(arr []string, key string) bool {
	for _, k := range arr {

		if k == key {

			return true
		}
	}

	return false
}

func arrayIsEqual(a1 []string, a2 []string) bool {
	sort.Strings(a1)
	sort.Strings(a2)

	return reflect.DeepEqual(a1, a2)
}

func getUsersFromPrincipalArray(arr []string) []string {
	var u []string

	re := regexp.MustCompile(`^.+user\/`)

	for _, p := range arr {
		u = append(u, re.ReplaceAllString(p, ""))
	}

	return u
}

func recordToArr(r string) []string {
	return strings.Fields(r)
}

func aclIsEqual(lc Bucket, sc Bucket, b string, logger log.Logger) bool {
	level.Debug(logger).Log("msg", "compare ACLs for bucket", "bucket", b)

	if !arrayIsEqual(lc.Acl.Grants.FullControl, sc.Acl.Grants.FullControl) {
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

func lfcIsEqual(localLfcRules []LifecycleRule, serverLfcRules []LifecycleRule, b string, logger log.Logger) bool {
	level.Debug(logger).Log("msg", "compare lifecycle configuration for bucket", "bucket", b)

	if len(localLfcRules) != len(serverLfcRules) {
		level.Debug(logger).Log("msg", "number of lifecycle rules not equal", "local", len(localLfcRules), "server", len(serverLfcRules))

		return false
	}

	for i, v := range localLfcRules {

		if !reflect.DeepEqual(v, serverLfcRules[i]) {
			level.Debug(logger).Log("msg", fmt.Sprintf("lifecycle configuration %+v != %+v", v, serverLfcRules[i]))

			return false
		}
	}

	return true
}
