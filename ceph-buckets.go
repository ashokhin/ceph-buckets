package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	uf "github.com/ashokhin/ceph-buckets/funcs"
	ut "github.com/ashokhin/ceph-buckets/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/iancoleman/strcase"
	"gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

const (
	awsRegion string = "us-east-1"

	// In Ceph need to set "HostnameImmutable" option to true for resolving path to bucket right
	forcePath bool = true
	retryNum  int  = 10

	// See doc about BucketPolicyVersion https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
	BucketPolicyVersion string = "2012-10-17"
)

var (
	logger log.Logger

	appName      = "ceph-buckets"
	appBranch    = "None"
	appVersion   = "dev"
	appRevision  = "0"
	AppOrigin    = "./"
	appBuildUser = "nobody"
	appBuildDate = "None"

	app   = kingpin.New("ceph-buckets", "A command-line application for manage Ceph configuration of Amazon S3-compatible storage based on Ceph.")
	debug = app.Flag("debug", "Enable debug mode.").Bool()

	appFlags     = app.Command("app", "Create/Update Ceph configuration YAML-file from application's TXT-file.")
	appAppConfig = appFlags.Flag("app-config", "Application's TXT-file, contains buckets list.").Default("./app_buckets_config.txt").String()
	appS3Config  = appFlags.Flag("ceph-config", "Ceph configuration YAML-file.").Default("./ceph_config.yml").String()

	createFlags         = app.Command("create", "Create/Update Ceph configuration YAML-file from server.")
	createS3Config      = createFlags.Flag("ceph-config", "Ceph configuration YAML-file.").Default("./ceph_config.yml").String()
	createCredentials   = createFlags.Flag("credentials", "Ceph credentials YAML-file.").Default("./ceph_credentials.yml").String()
	createBucketPostfix = createFlags.Flag("bucket-postfix", "Bucket postfix to be deleted from the bucket name.").Default("").String()

	cfgFlags         = app.Command("config", "Create/Update Ceph configuration on server from YAML-file.")
	cfgS3Config      = cfgFlags.Flag("ceph-config", "Ceph configuration YAML-file.").Default("./ceph_config.yml").String()
	cfgCredentials   = cfgFlags.Flag("credentials", "Ceph credentials YAML-file.").Default("./ceph_credentials.yml").String()
	cfgBucketPostfix = cfgFlags.Flag("bucket-postfix", "Bucket postfix to be added to the bucket name.").Default("").String()

	BucketPolicyWriteAction = []string{
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

	BucketPolicyReadAction = []string{
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

func printVersion() string {
	return fmt.Sprintf(`%q build info:
	version:              %q
	repo:                 %q
	branch:               %q
	revision:             %q
	build_user:           %q
	build_date:           %q`, appName, appVersion, AppOrigin, appBranch, appRevision, appBuildUser, appBuildDate)
}

func fileExists(filepath string) bool {

	fileinfo, err := os.Stat(filepath)

	if os.IsNotExist(err) {
		return false
	}
	// Return false if the fileinfo says the file path is a directory.
	return !fileinfo.IsDir()
}

func readFile(fs *string) ([]byte, bool) {
	var f []byte
	var readOk bool

	level.Debug(logger).Log("msg", "read file", "file", *fs)

	readOk = fileExists(*fs)

	f, err := ioutil.ReadFile(*fs)

	if err != nil {
		level.Warn(logger).Log("msg", "error reading file", "file", *fs, "err", err.Error())

		readOk = false
	}

	return f, readOk
}

func writeFile(fs *string, data *[]byte) error {
	level.Debug(logger).Log("msg", "write file", "file", *fs)

	err := ioutil.WriteFile(*fs, *data, 0644)
	return err
}

func loadConfig(fs *string) (*ut.Config, bool) {
	var cfg *ut.Config

	f, readOk := readFile(fs)

	err := yaml.Unmarshal(f, &cfg)

	if err != nil {
		level.Error(logger).Log("msg", "error unmarshaling YAML-config", "err", err.Error())

		os.Exit(2)
	}

	return cfg, readOk
}

func checkBucketName(b string) bool {

	// Ignore comment strings starting from "#" or "//" and blank strings
	comre := regexp.MustCompile(`^(#|//|$)`)

	if comre.MatchString(b) {
		// Skip comment as bucket name
		return false
	}

	re := regexp.MustCompile(`^[a-z][a-z0-9-]{1,61}[a-z]$`)

	if re.MatchString(b) {
		return true
	} else {
		level.Warn(logger).Log("msg", `String doesn't match naming rules and will be skipped.
The following rules apply for naming buckets in Amazon S3:
	* Bucket names must be between 3 and 63 characters long.
	* Bucket names can consist only of lowercase letters, numbers, and hyphens (-).
	* Bucket names must begin and end with a lowercase letter.
	`, "value", b)

		return false
	}

}

func writeConfig(cfg interface{}, fs *string) error {
	data, err := yaml.Marshal(&cfg)

	if err != nil {
		return err
	}

	err = writeFile(fs, &data)
	return err
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

func createS3SvcClient(credsPath *string) *s3.Client {
	var s3Url string

	yamlConfig := new(ut.Config)

	level.Debug(logger).Log("msg", "create client for specified context")
	level.Debug(logger).Log("msg", "loading S3 connection settings from file", "file", *credsPath)

	yamlConfigFromFile, loadOk := loadConfig(credsPath)

	if loadOk {
		yamlConfig = yamlConfigFromFile
	} else {
		level.Warn(logger).Log("msg", "config isn't loaded from file. Use default values", "file", *credsPath)
		yamlConfig.SetDefaults()
	}

	level.Debug(logger).Log("msg", "show yamlConfig", "value", fmt.Sprintf("%+v", *yamlConfig))

	if yamlConfig.DisableSSL {
		s3Url = fmt.Sprintf("http://%s/", yamlConfig.EndpointUrl)
	} else {
		s3Url = fmt.Sprintf("https://%s/", yamlConfig.EndpointUrl)
	}

	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			PartitionID:       "aws",
			URL:               s3Url,
			SigningRegion:     awsRegion,
			HostnameImmutable: forcePath,
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(yamlConfig.AwsAccessKey,
			yamlConfig.AwsSecretKey, "")))

	if err != nil {
		level.Error(logger).Log("msg", "failed to load configuration", "err", err.Error())

		os.Exit(1)
	}

	return s3.NewFromConfig(cfg)
}

func getS3Config(credsPath *string, bucketPostfix *string) ut.Buckets {
	client := createS3SvcClient(credsPath)

	level.Info(logger).Log("msg", "list buckets from S3 storage")

	inputList := &s3.ListBucketsInput{}
	listResult, err := uf.ListBuckets(context.TODO(), client, inputList)

	if err != nil {
		level.Error(logger).Log("msg", "error retrieving buckets", "err", err.Error())

		os.Exit(1)
	}

	level.Info(logger).Log("msg", "buckets listed successfully")

	buckets := make(ut.Buckets)
	matchPattern := fmt.Sprintf("%s$", *bucketPostfix)
	re := regexp.MustCompile(matchPattern)

	for _, bucket := range listResult.Buckets {
		var b ut.Bucket
		var bn string

		if len(*bucketPostfix) > 0 {
			if re.MatchString(*bucket.Name) {
				level.Debug(logger).Log("msg", "bucket name was match pattern. Rename", "bucket", *bucket.Name, "regexp", matchPattern)

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

		// Get Bucket ACL
		// Bucket ACL not supported yet in Ceph RGW S3 we use only owner now
		level.Debug(logger).Log("msg", "get bucket ACL", "bucket", *bucket.Name)

		inputAcl := &s3.GetBucketAclInput{
			Bucket: bucket.Name,
		}
		aclResult, err := uf.GetBucketAcl(context.TODO(), client, inputAcl)

		if err != nil {
			level.Error(logger).Log("msg", "error retriving bucket ACL", "bucket", *bucket.Name, "err", err.Error())

			b.AclType = "error"
		} else {
			level.Debug(logger).Log("msg", "show ACL", "bucket", *bucket.Name, "value", fmt.Sprintf("%+v", *aclResult))

			for _, grants := range aclResult.Grants {

				switch gp := grants.Permission; gp {
				case "FULL_CONTROL":
					b.Acl.Grants.FullControl = append(b.Acl.Grants.FullControl, *grants.Grantee.ID)
				case "READ":
					b.Acl.Grants.Read = append(b.Acl.Grants.Read, *grants.Grantee.ID)
				case "WRITE":
					b.Acl.Grants.Write = append(b.Acl.Grants.Write, *grants.Grantee.ID)
				default:
					level.Warn(logger).Log("msg", "permission type unsupported. Skip permission type", "bucket", *bucket.Name, "value", grants.Permission)
				}
			}

			b.Acl.Owner.DisplayName = *aclResult.Owner.DisplayName
			b.Acl.Owner.Id = *aclResult.Owner.ID
		}

		level.Debug(logger).Log("msg", "get bucket policies", "bucket", *bucket.Name)

		// Get Bucket policies
		// Rewrite ACL rules from bucket policies
		inputPol := &s3.GetBucketPolicyInput{
			Bucket: bucket.Name,
		}

		polResult, err := uf.GetBucketPolicy(context.TODO(), client, inputPol)

		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if ae.ErrorCode() == "NoSuchBucketPolicy" {
					level.Debug(logger).Log("msg", "didn't have bucket policy", "bucket", *bucket.Name)
				} else {
					level.Error(logger).Log("msg", "API error", "code", ae.ErrorCode(), "message", ae.ErrorMessage(), "err", ae.ErrorFault().String())

					b.AclType = "error"
				}
			} else {
				level.Error(logger).Log("msg", "error retriving bucket policies", "bucket", *bucket.Name, "err", err.Error())

				b.AclType = "error"
			}
		} else {
			level.Debug(logger).Log("msg", "show bucket policies", "bucket", *bucket.Name, "value", fmt.Sprintf("%+v", *polResult.Policy))

			var bp ut.BucketPolicy

			err := json.Unmarshal([]byte(*polResult.Policy), &bp)

			if err != nil {
				level.Error(logger).Log("msg", "error unmarshaling Bucket policies", "bucket", *bucket.Name, "err", err.Error())

				b.AclType = "error"
			}

			level.Debug(logger).Log("msg", "show bucket policies struct", "bucket", *bucket.Name, "value", fmt.Sprintf("%+v", bp))

			for _, st := range bp.Statement {

				switch sat := st.Action; {
				case keyInArray(sat, "s3:*"):
					b.Acl.Grants.FullControl = getUsersFromPrincipalArray(st.Principal.PrincipalType)
					// Always add owner
					if !keyInArray(b.Acl.Grants.FullControl, b.Acl.Owner.Id) {
						b.Acl.Grants.FullControl = append(b.Acl.Grants.FullControl, b.Acl.Owner.Id)
					}
				case (keyInArray(sat, "s3:GetObject") && !keyInArray(sat, "s3:PutObject")):
					b.Acl.Grants.Read = getUsersFromPrincipalArray(st.Principal.PrincipalType)
				case keyInArray(sat, "s3:PutObject"):
					b.Acl.Grants.Write = getUsersFromPrincipalArray(st.Principal.PrincipalType)
				default:
					level.Error(logger).Log("msg", "bucket policy statement", "bucket", *bucket.Name, "value", sat, "err", "action type unsupported")
				}

			}

			level.Debug(logger).Log("msg", "ACL updated from bucket policies", "bucket", *bucket.Name, "value", fmt.Sprintf("%+v", b.Acl))

		}

		level.Debug(logger).Log("msg", "get bucket versioning", "bucket", *bucket.Name)

		inputVer := &s3.GetBucketVersioningInput{
			Bucket: aws.String(*bucket.Name),
		}

		// Get Bucket versioning status
		vResult, err := uf.GetBucketVersioning(context.TODO(), client, inputVer)

		if err != nil {
			level.Error(logger).Log("msg", "error while retriving versioning configuration", "err", err.Error())

			b.VersioningType = "error"
		} else {
			if len(vResult.Status) > 0 {
				b.Versioning = strings.ToLower(string(vResult.Status))
			} else {
				b.Versioning = "suspended"
			}
		}

		level.Debug(logger).Log("msg", "show versioning status", "bucket", *bucket.Name, "value", b.Versioning)
		level.Debug(logger).Log("msg", "get bucket lifecycle", "bucket", *bucket.Name)

		input := &s3.GetBucketLifecycleConfigurationInput{
			Bucket: aws.String(*bucket.Name),
		}

		lfResult, err := uf.GetBucketLifecycleConfiguration(context.TODO(), client, input)

		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if ae.ErrorCode() == "NoSuchLifecycleConfiguration" {
					level.Debug(logger).Log("msg", "didn't have Lifecycle configuration", "bucket", *bucket.Name)
				} else {
					level.Error(logger).Log("msg", "API error", "code", ae.ErrorCode(), "message", ae.ErrorMessage(), "err", ae.ErrorFault().String())
				}
			} else {
				level.Error(logger).Log("msg", "error retriving bucket lifecycle", "bucket", *bucket.Name, "err", err.Error())
			}
		}

		if lfResult != nil {
			level.Debug(logger).Log("msg", "show lifecycle configuration", "bucket", *bucket.Name, "value", fmt.Sprintf("%+v", *lfResult))

			for _, r := range lfResult.Rules {
				var lfr ut.LifecycleRule

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
						level.Error(logger).Log("msg", "lifecycle rule of filter type not supported!", "bucket", *bucket.Name, "name", *r.ID, "type", fmt.Sprintf("%T", r.Filter))
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

		buckets[bn] = b

	}

	level.Debug(logger).Log("msg", "show buckets golang struct", "value", fmt.Sprintf("%+v", buckets))
	level.Debug(logger).Log("msg", "test YAML marshaling")

	data, err := yaml.Marshal(&buckets)

	if err != nil {
		level.Error(logger).Log("msg", "error marshaling buckets to YAML", "err", err.Error())

		os.Exit(1)
	}

	level.Debug(logger).Log("msg", "show buckets YAML", "value", string(data))

	return buckets
}

func createS3ConfigFile(confPath string, credsPath string, bucketPostfix string) error {
	buckets := getS3Config(&credsPath, &bucketPostfix)
	level.Info(logger).Log("msg", "write config to file", "file", confPath)

	err := writeConfig(&buckets, &confPath)

	if err != nil {
		level.Error(logger).Log("msg", "error writing file", "file", confPath, "err", err.Error())

		return err
	}

	return nil
}

func loadS3ConfigFile(fs *string) (ut.Buckets, error) {
	cfg := make(ut.Buckets)
	f, readOk := readFile(fs)

	if !readOk {
		err := fmt.Errorf("file %s isn't readed", *fs)
		level.Error(logger).Log("msg", "file isn't readed", "file", *fs)

		return cfg, err
	}

	err := yaml.Unmarshal(f, &cfg)

	if err != nil {
		level.Error(logger).Log("msg", "error unmarshaling YAML-config", "err", err.Error())

		os.Exit(1)
	}

	return cfg, nil
}

func updateConfigFromApp(appPath string, confPath string) error {
	var appBuckets []string
	var b ut.Bucket

	needUpdate := false

	level.Info(logger).Log("msg", "read file", "file", appPath)

	fc, err := os.Open(appPath)

	if err != nil {
		level.Error(logger).Log("msg", "error openning file", "file", appPath, "err", err.Error())

		return err
	}

	defer fc.Close()

	scanner := bufio.NewScanner(fc)

	for scanner.Scan() {
		s := scanner.Text()

		if checkBucketName(s) {
			level.Debug(logger).Log("msg", "bucket founded in file", "bucket", s, "file", appPath)

		} else {
			continue
		}

		appBuckets = append(appBuckets, s)
	}

	level.Debug(logger).Log("msg", "show application buckets", "value", fmt.Sprintf("%+v", appBuckets))
	level.Info(logger).Log("msg", "load buckets configuration from file", "file", confPath)

	confBuckets, err := loadS3ConfigFile(&confPath)

	if err == nil {

		if *debug {
			level.Debug(logger).Log("msg", "buckets loaded")

			for bucketName := range confBuckets {
				level.Debug(logger).Log("msg", "bucket loaded", "bucket", bucketName)
			}

		}

	} else {
		level.Warn(logger).Log("msg", "create new configuration")

		confBuckets = make(ut.Buckets)
	}

	for _, appBucket := range appBuckets {

		if _, ok := confBuckets[appBucket]; ok {
			level.Debug(logger).Log("msg", "bucket already in file", "bucket", appBucket, "file", confPath)

			continue
		}

		level.Info(logger).Log("msg", "bucket is new. Add in file", "bucket", appBucket, "file", confPath)

		needUpdate = true
		// Versioning disabled by default
		b.Versioning = "suspended"

		confBuckets[appBucket] = b
	}

	if needUpdate {
		level.Debug(logger).Log("msg", "new buckets config", "value", fmt.Sprintf("%+v", confBuckets))
		level.Info(logger).Log("msg", "write new configuration to file", "file", confPath)

		err := writeConfig(&confBuckets, &confPath)

		if err != nil {
			level.Error(logger).Log("msg", "error writing file", "file", confPath, "err", err.Error())

			return err
		}

	} else {
		level.Info(logger).Log("msg", "configuration in file already is up to date", "file", confPath)
	}

	return nil
}

// Bucket ACL not supported yet in Ceph RGW S3
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

// Bucket ACL not supported yet in Ceph RGW S3
func aclEqual(lc *ut.Bucket, sc ut.Bucket, b *string) bool {
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

func lfcIsEqual(lc *ut.Bucket, sc ut.Bucket, b *string) bool {
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

func compareConfigs(lc ut.Buckets, sc ut.Buckets) (ut.Buckets, bool) {
	var needUpdate bool = false

	newCfg := make(ut.Buckets)

	level.Info(logger).Log("msg", "compare local and server's configurations")

	for k, v := range lc {

		if sc.HasKey(k) {
			level.Debug(logger).Log("msg", "bucket already exist on server", "bucket", k)
			level.Debug(logger).Log("msg", "add server struct to result configuration", "value", fmt.Sprintf("%+v", sc[k]))

			newCfgBucket := sc[k]

			// Compare ACLs
			// Bucket ACL not supported yet in Ceph RGW S3
			if !aclEqual(&v, sc[k], &k) {
				level.Info(logger).Log("msg", "update ACL for bucket", "bucket", k)

				newCfgBucket.Acl.Grants.FullControl = v.Acl.Grants.FullControl
				newCfgBucket.Acl.Grants.Read = v.Acl.Grants.Read
				newCfgBucket.Acl.Grants.Write = v.Acl.Grants.Write
				newCfgBucket.AclType = "updated"
				needUpdate = true
			}

			// Compare versioning
			if sc[k].Versioning != v.Versioning {
				level.Info(logger).Log("msg", "update versioning configuration for bucket", "bucket", k)
				level.Debug(logger).Log("msg", "versioning changed", "value", v.Versioning)

				newCfgBucket.Versioning = v.Versioning
				newCfgBucket.VersioningType = "updated"
				needUpdate = true
			}

			// Compare Lifecycle Configurations
			if len(sc[k].LifecycleRules) > 0 || len(v.LifecycleRules) > 0 {

				if !lfcIsEqual(&v, sc[k], &k) {
					level.Info(logger).Log("msg", "update lifecycle configuration for bucket", "bucket", k)

					newCfgBucket.LifecycleRules = v.LifecycleRules
					newCfgBucket.LifecycleType = "updated"
					needUpdate = true
				}

			}

			newCfg[k] = newCfgBucket

		} else {
			level.Debug(logger).Log("msg", "bucket doesn't exist on server", "bucket", k)

			v.AclType = "new"
			v.BucketType = "new"
			v.LifecycleType = "new"

			level.Debug(logger).Log("msg", "add new bucket to server's configuration", "value", fmt.Sprintf("%+v", v))

			newCfg[k] = v
			needUpdate = true
		}

	}

	return newCfg, needUpdate
}

func fillBucketPolicy(bn *string, b *ut.Bucket, op string, grants []string, bpsa []ut.BucketPolicyStatement) []ut.BucketPolicyStatement {
	var (
		bps       ut.BucketPolicyStatement
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
		polAction = BucketPolicyReadAction
		fullName = "READ"
	case "write":
		polAction = BucketPolicyWriteAction
		fullName = "WRITE"
	}

	for _, u := range grants {
		switch s := u; {
		case s == b.Acl.Owner.Id:
			level.Debug(logger).Log("msg", "skip bucket owner", "value", s)
		case strings.Contains(s, ":"):
			pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s", u))
		default:
			pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s:%s", b.Acl.Owner.Id, u))

		}

	}

	bps = ut.BucketPolicyStatement{
		Sid:    fmt.Sprintf("%s-%s-%v", *bn, op, time.Now().UnixNano()),
		Action: polAction,
		Effect: "Allow",
		Resource: []string{
			fmt.Sprintf("arn:aws:s3:::%s", *bn),
		},
		Principal: ut.BucketPolicyPricipal{
			PrincipalType: pta,
		},
	}

	if len(bps.Principal.PrincipalType) > 0 {
		bpsa = append(bpsa, bps)
	} else {
		level.Debug(logger).Log("msg", "bucket policy statement didn't have principals. Skip. Show bucket policy template", "policy", fullName, "bucket", *bn, "value", fmt.Sprintf("%+v", bps))
	}

	return bpsa
}

func createBucketPolicy(bn *string, b *ut.Bucket) (string, error) {
	var (
		err  error
		bpsa []ut.BucketPolicyStatement
		j    []byte
	)

	if len(b.Acl.Grants.FullControl) > 0 {
		bpsa = fillBucketPolicy(bn, b, "full", b.Acl.Grants.FullControl, bpsa)
	}

	if len(b.Acl.Grants.Read) > 0 {
		bpsa = fillBucketPolicy(bn, b, "read", b.Acl.Grants.Read, bpsa)
	}

	if len(b.Acl.Grants.Write) > 0 {
		bpsa = fillBucketPolicy(bn, b, "write", b.Acl.Grants.Write, bpsa)
	}

	if len(bpsa) == 0 {
		return "", err
	}

	bp := ut.BucketPolicy{
		Version:   BucketPolicyVersion,
		Id:        fmt.Sprintf("Policy-%s-%v", *bn, time.Now().UnixNano()),
		Statement: bpsa,
	}

	j, err = json.MarshalIndent(bp, "", "  ")

	return string(j), err

}

// Bucket ACL not supported yet in Ceph RGW S3
func applyS3Acl(bn string, b ut.Bucket, client *s3.Client) error {
	var retryCount int

	level.Info(logger).Log("msg", "update ACL", "bucket", bn)
	level.Debug(logger).Log("msg", "get owner", "bucket", bn)

	retryCount = retryNum
	input := &s3.GetBucketAclInput{
		Bucket: aws.String(bn),
	}

	ba, err := uf.GetBucketAcl(context.TODO(), client, input)

	if err != nil {
		level.Error(logger).Log("msg", "error retriving ACL", "err", err.Error())

		return err
	}

	owner := *ba.Owner.DisplayName
	ownerId := *ba.Owner.ID

	grants := (s3.GetBucketAclOutput{}).Grants

	// If "FULL_CONTROL" grants is blank, than always add grants to owner
	if len(b.Acl.Grants.FullControl) == 0 {
		b.Acl.Grants.FullControl = append(b.Acl.Grants.FullControl, ownerId)
	}

	for _, g := range b.Acl.Grants.FullControl {
		newGrantee := types.Grantee{ID: aws.String(g), Type: types.Type("CanonicalUser")}
		newGrant := types.Grant{Grantee: &newGrantee, Permission: types.Permission("FULL_CONTROL")}
		grants = append(grants, newGrant)
	}

	for _, g := range b.Acl.Grants.Read {
		newGrantee := types.Grantee{ID: aws.String(g), Type: types.Type("CanonicalUser")}
		newGrant := types.Grant{Grantee: &newGrantee, Permission: types.Permission("READ")}
		grants = append(grants, newGrant)
	}

	for _, g := range b.Acl.Grants.Write {
		newGrantee := types.Grantee{ID: aws.String(g), Type: types.Type("CanonicalUser")}
		newGrant := types.Grant{Grantee: &newGrantee, Permission: types.Permission("WRITE")}
		grants = append(grants, newGrant)
	}

	level.Debug(logger).Log("msg", "set grants", "bucket", bn, "value", fmt.Sprintf("%+v", grants))

	retryCount = retryNum

	for retryCount > 0 {
		input := &s3.PutBucketAclInput{
			Bucket: aws.String(bn),
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: grants,
				Owner: &types.Owner{
					DisplayName: aws.String(owner),
					ID:          aws.String(ownerId),
				},
			},
		}

		level.Debug(logger).Log("msg", "apply ACL", "bucket", bn, "value", fmt.Sprintf("%+v", *input))

		out, err := uf.PutBucketAcl(context.TODO(), client, input)

		retryCount--

		if err != nil {
			if retryCount > 0 {
				level.Debug(logger).Log("msg", "error applying ACL", "bucket", bn, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "err", err.Error())

				time.Sleep(1 * time.Second)
			} else {
				level.Error(logger).Log("msg", "error applying ACL:", "err", err.Error())

				return err
			}
		} else {
			break
		}

	}

	return nil

}

func applyS3LifecycleConfiguration(bn string, b ut.Bucket, client *s3.Client) error {
	var retryCount int

	level.Info(logger).Log("msg", "update lifecycle configuration", "bucket", bn)

	lfcRules := []types.LifecycleRule{}
	for _, lc := range b.LifecycleRules {
		level.Debug(logger).Log("msg", "show lifecycle rule", "value", fmt.Sprintf("%+v", lc))

		if (lc.NonCurrentDays >= 0) && (b.Versioning == "suspended") {
			level.Warn(logger).Log("msg", "lifecycle rule contains non-negative value for non-current version expiration, but bucket versioning is disabled!", "bucket", bn, "value", fmt.Sprintf("%+v", lc.Id))

			lc.NonCurrentDays = -1
		}

		// Specifies the expiration for the lifecycle of the object
		status := strcase.ToCamel(lc.Status)
		newLCRule := types.LifecycleRule{}
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

	retryCount = retryNum

	for retryCount > 0 {
		level.Debug(logger).Log("msg", "set lifecycle configuration", "bucket", bn, "value", fmt.Sprintf("%+v", lfcRules))

		// Recreate/Delete lifecycle rules
		// first: Delete old rules
		delLfc := &s3.DeleteBucketLifecycleInput{
			Bucket: aws.String(bn),
		}

		delLfcOut, err := uf.DeleteBucketLifecycle(context.TODO(), client, delLfc)
		if err != nil {
			level.Error(logger).Log("msg", "error deleting old lifecycle configuration", "bucket", bn, "output", fmt.Sprintf("%+v", delLfcOut), "err", err.Error())

			return err
		}

		if len(lfcRules) == 0 {
			break
		}
		// Create new versions of rules
		putLfc := &s3.PutBucketLifecycleConfigurationInput{
			Bucket: aws.String(bn),
			LifecycleConfiguration: &types.BucketLifecycleConfiguration{
				Rules: lfcRules,
			},
		}

		level.Debug(logger).Log("msg", "apply lifecycle configuration", "value", fmt.Sprintf("%+v", *putLfc))

		putLfcOut, err := uf.PutBucketLifecycleConfiguration(context.TODO(), client, putLfc)

		retryCount--

		if err != nil {
			if retryCount > 0 {
				level.Debug(logger).Log("msg", "error applying lifecycle configuration", "bucket", bn, "output", fmt.Sprintf("%+v", putLfcOut), "retry_attempts_left", retryCount, "err", err.Error())
			} else {
				level.Error(logger).Log("msg", "error applying lifecycle configuration", "err", err.Error())

				return err
			}

			time.Sleep(1 * time.Second)

		} else {
			break
		}

	}

	return nil
}

func applyS3BucketPolicy(bn string, b ut.Bucket, client *s3.Client) error {
	var retryCount int

	level.Info(logger).Log("msg", "update bucket policy", "bucket", bn)
	level.Debug(logger).Log("msg", "generate bucket policy", "bucket", bn)

	// Create Bucket policy JSON
	BucketPolicy, err := createBucketPolicy(&bn, &b)

	if err != nil {
		level.Error(logger).Log("msg", "error marshaling Bucket policy to JSON", "bucket", bn, "err", err.Error())

		return err
	}

	level.Debug(logger).Log("msg", "show bucket policy", "bucket", bn, "value", fmt.Sprintf("%+v", BucketPolicy))

	retryCount = retryNum

	for retryCount > 0 {
		if len(BucketPolicy) == 0 {
			break
		}

		input := &s3.PutBucketPolicyInput{
			Bucket: aws.String(bn),
			Policy: aws.String(BucketPolicy),
		}

		out, err := uf.PutBucketPolicy(context.TODO(), client, input)

		retryCount--

		if err != nil {
			if retryCount > 0 {
				level.Debug(logger).Log("msg", "error applying Bucket policy", "bucket", bn, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "err", err.Error())

				time.Sleep(1 * time.Second)
			} else {
				level.Error(logger).Log("msg", "error applying lifecycle configuration", "err", err.Error())

				return err
			}

		} else {
			break
		}

	}

	return nil
}

func applyS3Config(c *ut.Buckets, credsPath *string, bucketPostfix string) error {
	level.Info(logger).Log("msg", "apply new configuration on server")

	var retryCount int

	client := createS3SvcClient(credsPath)

	for bn, b := range *c {
		// Create bucket
		bn = bn + bucketPostfix

		if b.BucketType == "new" {
			level.Info(logger).Log("msg", "create bucket", "bucket", bn)

			retryCount = retryNum

			for retryCount > 0 {
				input := &s3.CreateBucketInput{
					Bucket: &bn,
				}
				out, err := uf.CreateBucket(context.TODO(), client, input)

				retryCount--

				if err != nil {
					if retryCount > 0 {
						level.Debug(logger).Log("msg", "error creating bucket", "bucket", bn, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "err", err.Error())

						time.Sleep(1 * time.Second)
					} else {
						level.Error(logger).Log("msg", "error creating bucket", "err", err.Error())

						return err
					}

				} else {
					level.Debug(logger).Log("msg", "bucket created", "bucket", bn)

					break
				}

			}

		}

		// Apply versioning if bucketType "new" or "updated"
		if b.VersioningType == "updated" {
			level.Info(logger).Log("msg", "update versioning", "bucket", bn)

			var status types.BucketVersioningStatus = types.BucketVersioningStatus(strcase.ToCamel(b.Versioning))

			level.Debug(logger).Log("msg", "versioning status updated", "bucket", bn, "value", fmt.Sprintf("%+v", status))

			retryCount = retryNum

			for retryCount > 0 {
				input := &s3.PutBucketVersioningInput{
					Bucket: aws.String(bn),
					VersioningConfiguration: &types.VersioningConfiguration{
						Status: status,
					},
				}

				level.Debug(logger).Log("msg", "apply versioning", "bucket", bn, "value", *input)

				out, err := uf.PutBucketVersioning(context.TODO(), client, input)

				retryCount--

				if err != nil {
					if retryCount > 0 {
						level.Debug(logger).Log("msg", "error set versioning", "bucket", bn, "output", fmt.Sprintf("%+v", out), "retry_attempts_left", retryCount, "err", err.Error())

						time.Sleep(1 * time.Second)
					} else {
						level.Error(logger).Log("msg", "error set versioning", "bucket", bn, "err", err.Error())

						return err
					}

				} else {
					break
				}

			}

		}

		// Apply Bucket ACLs and Bucket Policy
		switch aclType := b.AclType; aclType {
		case "new", "updated":

			// Bucket ACL not supported yet in Ceph RGW S3
			/*
				err := applyS3Acl(bn, b, client)

				if err != nil {
					return err
				}
			*/
			err := applyS3BucketPolicy(bn, b, client)

			if err != nil {
				return err
			}

		case "error":
			level.Warn(logger).Log("msg", "ACL with type 'error' can't be applied! Skip.", "bucket", bn)
		}

		// Apply Lifecycle Configuration
		switch LfcType := b.LifecycleType; LfcType {
		case "new":
			err := applyS3LifecycleConfiguration(bn, b, client)

			if err != nil {
				return err
			}

		case "updated":
			err := applyS3LifecycleConfiguration(bn, b, client)

			if err != nil {
				return err
			}

		case "error":
			level.Warn(logger).Log("msg", "lifecycle configuration with type 'error' can't be applied! Skip.", "bucket", bn)
		}

	}

	return nil
}

func configureS3Server(confPath string, credsPath string, bucketPostfix string) (bool, error) {
	level.Info(logger).Log("msg", "load buckets configuration from file", "file", confPath)

	localCfg, err := loadS3ConfigFile(&confPath)

	if err != nil {
		level.Error(logger).Log("msg", "error loading file", "file", fmt.Sprintf("%+v", localCfg))

		return false, err
	}

	level.Debug(logger).Log("msg", "loaded local configuration", "file", fmt.Sprintf("%+v", localCfg))
	level.Info(logger).Log("msg", "load buckets configuration from server")

	srvCfg := getS3Config(&credsPath, &bucketPostfix)

	level.Debug(logger).Log("msg", "loaded server configuration", fmt.Sprintf("%+v", srvCfg))

	newSrvConfig, cfgUpdated := compareConfigs(localCfg, srvCfg)

	if cfgUpdated {
		// Test and sort configuration struct
		yaml_model, _ := yaml.Marshal(&newSrvConfig)
		err := yaml.Unmarshal(yaml_model, newSrvConfig)

		if err != nil {
			level.Error(logger).Log("msg", "test new configuration was failed", "err", err.Error())
			level.Debug(logger).Log("msg", "broken configuration", "value", fmt.Sprintf("%+v", newSrvConfig))

			return false, err
		}

		level.Debug(logger).Log("msg", "show new configuration", "value", fmt.Sprintf("%+v", newSrvConfig))

		err = applyS3Config(&newSrvConfig, &credsPath, bucketPostfix)

		if err != nil {
			return false, err
		}
	} else {
		level.Info(logger).Log("msg", "server's configuration already up to date")

		return true, nil
	}

	return true, nil
}

func init() {
	app.Version(printVersion())
	kingpin.MustParse(app.Parse(os.Args[1:]))

	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))

	if *debug {
		logger = level.NewFilter(logger, level.AllowDebug())
	} else {
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	timestampFormat := log.TimestampFormat(
		func() time.Time { return time.Now().UTC() },
		"2006-01-02T15:04:05.0000000Z07:00",
	)
	logger = log.With(logger, "timestamp", timestampFormat, "caller", log.DefaultCaller)
}

func main() {
	var err error
	var cfgUpdated bool

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case appFlags.FullCommand():
		level.Debug(logger).Log("command", appFlags.FullCommand())
		level.Debug(logger).Log("flag", "--app-config", "value", *appAppConfig)
		level.Debug(logger).Log("flag", "--ceph-config", "value", *appS3Config)

		*appAppConfig, _ = filepath.Abs(*appAppConfig)
		*appS3Config, _ = filepath.Abs(*appS3Config)
		err = updateConfigFromApp(*appAppConfig, *appS3Config)
	case createFlags.FullCommand():
		level.Debug(logger).Log("command", createFlags.FullCommand())
		level.Debug(logger).Log("flag", "--ceph-config", "value", *createS3Config)
		level.Debug(logger).Log("flag", "--credentials", "value", *createCredentials)
		level.Debug(logger).Log("flag", "--bucket-postfix", "value", *createBucketPostfix)

		*createS3Config, _ = filepath.Abs(*createS3Config)
		*createCredentials, _ = filepath.Abs(*createCredentials)
		err = createS3ConfigFile(*createS3Config, *createCredentials, *createBucketPostfix)
	case cfgFlags.FullCommand():
		level.Debug(logger).Log("command", cfgFlags.FullCommand())
		level.Debug(logger).Log("flag", "--ceph-config", "value", *cfgS3Config)
		level.Debug(logger).Log("flag", "--credentials", "value", *cfgCredentials)
		level.Debug(logger).Log("flag", "--bucket-postfix", "value", *cfgBucketPostfix)

		*cfgS3Config, _ = filepath.Abs(*cfgS3Config)
		*cfgCredentials, _ = filepath.Abs(*cfgCredentials)
		cfgUpdated, err = configureS3Server(*cfgS3Config, *cfgCredentials, *cfgBucketPostfix)

		if cfgUpdated {
			level.Info(logger).Log("msg", "server configuration updated successfully")
			level.Info(logger).Log("msg", "update local config from server")

			err = createS3ConfigFile(*cfgS3Config, *cfgCredentials, *cfgBucketPostfix)
		}
	}

	if err != nil {
		level.Error(logger).Log("msg", "exit main", "err", err.Error())

		os.Exit(1)
	}

	level.Debug(logger).Log("msg", "exit")

	os.Exit(0)

}
