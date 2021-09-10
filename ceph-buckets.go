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
	"github.com/iancoleman/strcase"
	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v3"
)

const (
	awsRegion string = "us-east-1"
	forcePath bool   = true
	retryNum  int    = 10
	// See doc about BucketPolicyVersion https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
	BucketPolicyVersion string = "2012-10-17"
)

var (
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

func FileExists(filepath string) bool {

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

	log.Debugf("Read file %q", *fs)

	readOk = FileExists(*fs)

	f, err := ioutil.ReadFile(*fs)

	if err != nil {
		log.Warnf("Error while read file: %q", err.Error())

		readOk = false
	}

	return f, readOk
}

func writeFile(fs *string, data *[]byte) error {
	log.Debugf("Write file %q", *fs)

	err := ioutil.WriteFile(*fs, *data, 0644)
	return err
}

func loadConfig(fs *string) (*ut.Config, bool) {
	var cfg *ut.Config

	f, readOk := readFile(fs)

	err := yaml.Unmarshal(f, &cfg)

	if err != nil {
		log.Errorf("Error unmarshaling YAML-config: %q", err.Error())

		os.Exit(2)
	}

	return cfg, readOk
}

func checkBucketName(b string) bool {

	re := regexp.MustCompile(`^[a-z][a-z0-9-]{1,61}[a-z]$`)

	if re.MatchString(b) {
		return true
	} else {
		log.Warnf(`String %q doesn't match naming rules and will be skipped.
The following rules apply for naming buckets in Amazon S3:
* Bucket names must be between 3 and 63 characters long.
* Bucket names can consist only of lowercase letters, numbers, and hyphens (-).
* Bucket names must begin and end with a lowercase letter.
	`, b)

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

	log.Debug("Create client for specified context")
	log.Debugf("Loading S3 connection settings from %q", *credsPath)

	yamlConfig, loadOk := loadConfig(credsPath)

	if !loadOk {
		log.Warnf("Config %q isn't loaded", *credsPath)
	}

	yamlConfig.SetDefaults()

	if yamlConfig.DisableSSL {
		s3Url = fmt.Sprintf("http://%s/", yamlConfig.EndpointUrl)
	} else {
		s3Url = fmt.Sprintf("https://%s/", yamlConfig.EndpointUrl)
	}

	customResolver := aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
		return aws.Endpoint{
			PartitionID:       "aws",
			URL:               s3Url,
			SigningRegion:     awsRegion,
			HostnameImmutable: forcePath,
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithEndpointResolver(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(yamlConfig.AwsAccessKey,
			yamlConfig.AwsSecretKey, "")))

	if err != nil {
		log.Fatalf("Failed to load configuration, %v", err)
	}

	return s3.NewFromConfig(cfg)
}

func getS3Config(credsPath *string, bucketPostfix *string) ut.Buckets {
	client := createS3SvcClient(credsPath)

	log.Info("List buckets from S3 storage")

	inputList := &s3.ListBucketsInput{}
	listResult, err := uf.ListBuckets(context.TODO(), client, inputList)

	if err != nil {
		log.Fatalf("Error retrieving buckets: %q", err.Error())
	}

	log.Info("Buckets listed successfully")

	buckets := make(ut.Buckets)
	matchPattern := fmt.Sprintf("%s$", *bucketPostfix)
	re := regexp.MustCompile(matchPattern)

	for _, bucket := range listResult.Buckets {
		var b ut.Bucket
		var bn string

		if len(*bucketPostfix) > 0 {
			if re.MatchString(*bucket.Name) {
				log.Debugf("Bucket %q was match pattern %q. Rename.", *bucket.Name, matchPattern)

				//Create name w/o postfix
				bn = re.ReplaceAllString(*bucket.Name, "")
				log.Debugf("New name: %q", bn)
			} else {
				log.Warnf("Bucket %q doesn't match pattern %q", *bucket.Name, matchPattern)

				bn = *bucket.Name
			}
		} else {
			bn = *bucket.Name
		}

		/*
			Get Bucket ACL
			Bucket ACL not supported yet in Ceph RGW S3 we use only owner now
		*/
		log.Debugf("Bucket: %q. Get bucket ACL...", *bucket.Name)

		inputAcl := &s3.GetBucketAclInput{
			Bucket: bucket.Name,
		}
		aclResult, err := uf.GetBucketAcl(context.TODO(), client, inputAcl)

		if err != nil {
			log.Errorf("Error retriving bucket ACL: %q", err.Error())

			b.AclType = "error"
		} else {
			log.Debugf("Bucket: %q, ACL: %+v", *bucket.Name, *aclResult)

			for _, grants := range aclResult.Grants {

				switch gp := grants.Permission; gp {
				case "FULL_CONTROL":
					b.Acl.Grants.FullControl = append(b.Acl.Grants.FullControl, *grants.Grantee.ID)
				case "READ":
					b.Acl.Grants.Read = append(b.Acl.Grants.Read, *grants.Grantee.ID)
				case "WRITE":
					b.Acl.Grants.Write = append(b.Acl.Grants.Write, *grants.Grantee.ID)
				default:
					log.Warnf("Permission type %q unsupported. Skip permission type", grants.Permission)
				}
			}

			b.Acl.Owner.DisplayName = *aclResult.Owner.DisplayName
			b.Acl.Owner.Id = *aclResult.Owner.ID
		}

		/*
			Get Bucket policies
			Rewrite ACL rules from bucket policies
		*/

		log.Debugf("Bucket %q: Get Bucket policies...", *bucket.Name)

		inputPol := &s3.GetBucketPolicyInput{
			Bucket: bucket.Name,
		}

		polResult, err := uf.GetBucketPolicy(context.TODO(), client, inputPol)

		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if ae.ErrorCode() == "NoSuchBucketPolicy" {
					log.Debugf("Bucket %q didn't have Bucket policy", *bucket.Name)
				} else {
					log.Errorf("API error. Code: %s, message: %s, fault: %s", ae.ErrorCode(), ae.ErrorMessage(), ae.ErrorFault().String())
				}
			} else {
				log.Errorf("Error retriving Bucket policies: %q", err.Error())
			}

			b.AclType = "error"
		} else {
			log.Debugf("Bucket %q: Bucket policies:\n%+v", *bucket.Name, *polResult.Policy)

			var bp ut.BucketPolicy

			err := json.Unmarshal([]byte(*polResult.Policy), &bp)

			if err != nil {
				log.Errorf("Error unmarshaling Bucket policies: %q", err.Error())

				b.AclType = "error"
			}

			log.Debugf("Bucket %q: Bucket policies struct: %+v", *bucket.Name, bp)

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
					log.Errorf("Bucket policy statement action type unsupported: %+v", sat)
				}

			}

			log.Debugf("Bucket %q: ACL updated from Bucket policies: %+v", *bucket.Name, b.Acl)

		}

		/*
			Get Bucket versioning status
		*/
		log.Debugf("Bucket %q: Get bucket versioning...", *bucket.Name)

		inputVer := &s3.GetBucketVersioningInput{
			Bucket: aws.String(*bucket.Name),
		}

		vResult, err := uf.GetBucketVersioning(context.TODO(), client, inputVer)

		if err != nil {
			log.Errorf("Error while retriving versioning configuration: %q", err.Error())

			b.VersioningType = "error"
		} else {
			if len(vResult.Status) > 0 {
				b.Versioning = strings.ToLower(string(vResult.Status))
			} else {
				b.Versioning = "suspended"
			}
		}

		log.Debugf("Bucket: %q. Versioning status: %q", *bucket.Name, b.Versioning)

		log.Debugf("Bucket: %q. Get bucket lifecycle...", *bucket.Name)

		input := &s3.GetBucketLifecycleConfigurationInput{
			Bucket: aws.String(*bucket.Name),
		}

		lfResult, err := uf.GetBucketLifecycleConfiguration(context.TODO(), client, input)

		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if ae.ErrorCode() == "NoSuchLifecycleConfiguration" {
					log.Debugf("Bucket %q didn't have Lifecycle configuration", *bucket.Name)
				} else {
					log.Errorf("API error. Code: %s, message: %s, fault: %s", ae.ErrorCode(), ae.ErrorMessage(), ae.ErrorFault().String())
				}
			} else {
				log.Errorf("Error retriving bucket lifecycle: %q", err.Error())
			}
		}

		if lfResult != nil {
			log.Debugf("Bucket %q, Lifecycle configuration: %+v", *bucket.Name, *lfResult)

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
						log.Errorf("Bucket %q, Lifecycle rule: %q. Filter type '%T' not supported!", *bucket.Name, *r.ID, r.Filter)
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

	log.Debugf("Buckets golang struct: %+v", buckets)
	log.Debug("Test YAML marshaling...")

	data, err := yaml.Marshal(&buckets)

	if err != nil {
		log.Fatalf("Error marshaling buckets to YAML: %q", err.Error())
	}

	log.Debugf("Buckets YAML:\n%s", string(data))

	return buckets
}

func createS3ConfigFile(confPath string, credsPath string, bucketPostfix string) int {
	buckets := getS3Config(&credsPath, &bucketPostfix)
	log.Infof("Write config to %q", confPath)

	err := writeConfig(&buckets, &confPath)

	if err != nil {
		log.Errorf("Error writing file %q: %q", confPath, err.Error())

		return 1
	}

	return 0
}

func loadS3ConfigFile(fs *string) (ut.Buckets, bool) {
	cfg := make(ut.Buckets)
	f, readOk := readFile(fs)

	if !readOk {
		log.Warnf("File %q isn't readed", *fs)
	}

	err := yaml.Unmarshal(f, &cfg)

	if err != nil {
		log.Errorf("Error unmarshaling YAML-config: %q", err.Error())

		os.Exit(2)
	}

	return cfg, readOk
}

func updateConfigFromApp(appPath string, confPath string) int {
	var appBuckets []string

	needUpdate := false

	log.Infof("Read file %q", appPath)

	fc, err := os.Open(appPath)

	if err != nil {
		log.Errorf("Error openning file: %q", err.Error())

		return 1
	}

	defer fc.Close()

	scanner := bufio.NewScanner(fc)

	for scanner.Scan() {
		s := scanner.Text()

		if checkBucketName(s) {
			log.Debugf("Bucket %q founded in %q", s, appPath)

		} else {
			continue
		}

		appBuckets = append(appBuckets, s)
	}

	log.Debugf("appBuckets: %+v", appBuckets)
	log.Infof("Load buckets configuration from %q", confPath)

	confBuckets, loadOk := loadS3ConfigFile(&confPath)

	if loadOk {

		if *debug {
			log.Debug("Buckets loaded:")

			for _, confBucket := range confBuckets {
				fmt.Printf("\t- %+v\n", confBucket)
			}

		}

	} else {
		log.Warn("Create new configuration")

		confBuckets = make(ut.Buckets)
	}

	for _, appBucket := range appBuckets {

		if _, ok := confBuckets[appBucket]; ok {
			log.Debugf("Bucket %q already in %q", appBucket, confPath)

			continue
		}

		var b ut.Bucket

		log.Infof("Bucket %q is new. Add in %q", appBucket, confPath)

		needUpdate = true
		// Versioning disabled by default
		b.Versioning = "suspended"

		confBuckets[appBucket] = b
	}

	if needUpdate {
		log.Debugf("New buckets config: %+v", confBuckets)
		log.Infof("Write new configuration to %q", confPath)

		err := writeConfig(&confBuckets, &confPath)

		if err != nil {
			log.Errorf("Error writing file %q: %q", confPath, err.Error())

			return 1
		}

	} else {
		log.Infof("Configuration in file %q already is up to date", confPath)
	}

	return 0
}

/*
	Bucket ACL not supported yet in Ceph RGW S3
*/
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

/*
	Bucket ACL not supported yet in Ceph RGW S3
*/
func aclEqual(lc *ut.Bucket, sc ut.Bucket, b *string) bool {
	log.Debugf("Compare ACLs for bucket %q", *b)

	if !reflect.DeepEqual(lc.Acl.Grants.FullControl, sc.Acl.Grants.FullControl) {
		log.Debugf("ACL FullControl %+v != %+v", lc.Acl.Grants.FullControl, sc.Acl.Grants.FullControl)

		return false
	}

	if !arrayIsEqual(lc.Acl.Grants.Read, sc.Acl.Grants.Read) {
		log.Debugf("ACL Read %+v != %+v", lc.Acl.Grants.Read, sc.Acl.Grants.Read)

		return false
	}

	if !arrayIsEqual(lc.Acl.Grants.Write, sc.Acl.Grants.Write) {
		log.Debugf("ACL Write %+v != %+v", lc.Acl.Grants.Write, sc.Acl.Grants.Write)

		return false
	}

	return true

}

func lfcIsEqual(lc *ut.Bucket, sc ut.Bucket, b *string) bool {
	log.Debugf("Compare Lifecycle Configuration for bucket %q", *b)

	if len(lc.LifecycleRules) == len(sc.LifecycleRules) {

		for i, v := range lc.LifecycleRules {

			if !reflect.DeepEqual(v, sc.LifecycleRules[i]) {
				log.Debugf("LC cmp %+v != %+v", v, sc.LifecycleRules[i])

				return false
			}
		}

		for i, v := range sc.LifecycleRules {

			if !reflect.DeepEqual(v, lc.LifecycleRules[i]) {
				log.Debugf("LC cmp %+v != %+v", v, lc.LifecycleRules[i])

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

	log.Info("Compare local and server's configurations")

	for k, v := range lc {

		if sc.HasKey(k) {
			log.Debugf("Bucket %q already exist on server", k)
			log.Debugf("Add server struct to result configuration: %+v", sc[k])

			newCfgBucket := sc[k]
			// Compare ACLs
			/*
				Bucket ACL not supported yet in Ceph RGW S3
			*/
			if !aclEqual(&v, sc[k], &k) {
				log.Infof("Update ACL for bucket %q", k)

				newCfgBucket.Acl.Grants.FullControl = v.Acl.Grants.FullControl
				newCfgBucket.Acl.Grants.Read = v.Acl.Grants.Read
				newCfgBucket.Acl.Grants.Write = v.Acl.Grants.Write
				newCfgBucket.AclType = "updated"
				needUpdate = true
			}

			// Compare versioning
			if sc[k].Versioning != v.Versioning {
				log.Infof("Update versioning configuration for bucket %q", k)
				log.Debugf("Versioning is %q now", v.Versioning)

				newCfgBucket.Versioning = v.Versioning
				newCfgBucket.VersioningType = "updated"
				needUpdate = true
			}

			// Compare Lifecycle Configurations
			if len(sc[k].LifecycleRules) > 0 || len(v.LifecycleRules) > 0 {

				if !lfcIsEqual(&v, sc[k], &k) {
					log.Infof("Update lifecycle configuration for bucket %q", k)

					newCfgBucket.LifecycleRules = v.LifecycleRules
					newCfgBucket.LifecycleType = "updated"
					needUpdate = true
				}

			}

			newCfg[k] = newCfgBucket

		} else {
			log.Debugf("Bucket %q doesn't exist on server", k)

			v.AclType = "new"
			v.BucketType = "new"
			v.LifecycleType = "new"

			log.Debugf("Add new bucket to server's configuration: %+v", v)

			newCfg[k] = v
			needUpdate = true
		}

	}

	return newCfg, needUpdate
}

func createBucketPolicy(bn *string, b *ut.Bucket) (string, error) {
	var (
		ps  ut.BucketPolicyStatement
		psa []ut.BucketPolicyStatement
		j   []byte
	)

	if len(b.Acl.Grants.FullControl) > 0 {
		var pta []string

		for _, u := range b.Acl.Grants.FullControl {

			switch s := u; {
			case s == b.Acl.Owner.Id:
				log.Debugf("Skip bucket owner: %s", s)
			case strings.Contains(s, ":"):
				pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s", u))
			default:
				pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s:%s", b.Acl.Owner.Id, u))

			}

		}

		ps = ut.BucketPolicyStatement{
			Sid: fmt.Sprintf("%s-full-%v", *bn, time.Now().UnixNano()),
			Action: []string{
				"s3:*",
			},
			Effect: "Allow",
			Resource: []string{
				fmt.Sprintf("arn:aws:s3:::%s", *bn),
			},
			Principal: ut.BucketPolicyPricipal{
				PrincipalType: pta,
			},
		}

		if len(ps.Principal.PrincipalType) > 0 {
			psa = append(psa, ps)
		} else {
			log.Debugf("Bucket %q: 'FULL_CONTROL' Bucket policy statement didn't have principals. Skip. Bucket policy template:\n%+v", *bn, ps)
		}

	}

	if len(b.Acl.Grants.Read) > 0 {
		var pta []string

		for _, u := range b.Acl.Grants.Read {

			switch s := u; {
			case s == b.Acl.Owner.Id:
				log.Debugf("Skip bucket owner: %s", s)
			case strings.Contains(s, ":"):
				pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s", u))
			default:
				pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s:%s", b.Acl.Owner.Id, u))

			}

		}

		ps = ut.BucketPolicyStatement{
			Sid:    fmt.Sprintf("%s-read-%v", *bn, time.Now().UnixNano()),
			Action: BucketPolicyReadAction,
			Effect: "Allow",
			Resource: []string{
				fmt.Sprintf("arn:aws:s3:::%s", *bn),
			},
			Principal: ut.BucketPolicyPricipal{
				PrincipalType: pta,
			},
		}

		if len(ps.Principal.PrincipalType) > 0 {
			psa = append(psa, ps)
		} else {
			log.Debugf("Bucket %q: 'READ' Bucket policy statement didn't have principals. Skip. Bucket policy template:\n%+v", *bn, ps)
		}

	}

	if len(b.Acl.Grants.Write) > 0 {
		var pta []string

		for _, u := range b.Acl.Grants.Write {

			switch s := u; {
			case s == b.Acl.Owner.Id:
				log.Debugf("Skip bucket owner: %s", s)
			case strings.Contains(s, ":"):
				pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s", u))
			default:
				pta = append(pta, fmt.Sprintf("arn:aws:iam:::user/%s:%s", b.Acl.Owner.Id, u))

			}

		}

		ps = ut.BucketPolicyStatement{
			Sid:    fmt.Sprintf("%s-write-%v", *bn, time.Now().UnixNano()),
			Action: BucketPolicyWriteAction,
			Effect: "Allow",
			Resource: []string{
				fmt.Sprintf("arn:aws:s3:::%s", *bn),
			},
			Principal: ut.BucketPolicyPricipal{
				PrincipalType: pta,
			},
		}

		if len(ps.Principal.PrincipalType) > 0 {
			psa = append(psa, ps)
		} else {
			log.Debugf("Bucket %q: 'WRITE' Bucket policy statement didn't have principals. Skip. Bucket policy template:\n%+v", *bn, ps)
		}

	}

	bp := ut.BucketPolicy{
		Version:   BucketPolicyVersion,
		Id:        fmt.Sprintf("Policy-%s-%v", *bn, time.Now().UnixNano()),
		Statement: psa,
	}

	j, err := json.MarshalIndent(bp, "", "  ")

	return string(j), err

}

/*
	Bucket ACL not supported yet in Ceph RGW S3
*/
/* func applyS3Acl(bn string, b ut.Bucket, client *s3.Client) bool {

	var retryCount int

	log.Infof("Bucket %q: Update ACL", bn)
	log.Debugf("Bucket %q: Get owner", bn)

	retryCount = retryNum
	input := &s3.GetBucketAclInput{
		Bucket: aws.String(bn),
	}

	ba, err := GetBucketAcl(context.TODO(), client, input)

	if err != nil {
		log.Errorf("Error retriving ACL: %q", err.Error())

		return false
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

	log.Debugf("Bucket %q: Set grants: %+v", bn, grants)

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

		log.Debugf("Bucket %q: Apply ACL: %+v", bn, *input)

		out, err := PutBucketAcl(context.TODO(), client, input)

		retryCount--

		if err != nil {
			log.Debugf("Error applying ACL: %q. Out: %+v\nRetry attempts left: %v", err.Error(), out, retryCount)

			time.Sleep(1 * time.Second)

		} else {
			break
		}

		if retryCount == 0 && err != nil {
			log.Errorf("Error applying ACL: %q", err.Error())

			return false
		}

	}

	return true

} */

func applyS3LifecycleConfiguration(bn string, b ut.Bucket, client *s3.Client) bool {
	var retryCount int

	log.Infof("Bucket %q: Update Lifecycle configuration", bn)

	lfcRules := []types.LifecycleRule{}
	for _, lc := range b.LifecycleRules {
		log.Debugf("LC rule: %+v", lc)

		if (lc.NonCurrentDays >= 0) && (b.Versioning == "suspended") {
			log.Warnf("Bucket %q: Lifecycle rule %q contains non-negative value for non-current version expiration, but bucket versioning is disabled!", bn, lc.Id)

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
		log.Debugf("Bucket %q: Set Lifecycle configuration: %+v", bn, lfcRules)

		// Recreate/Delete lifecycle rules
		// first: Delete old rules
		input := &s3.DeleteBucketLifecycleInput{
			Bucket: aws.String(bn),
		}

		out, err := uf.DeleteBucketLifecycle(context.TODO(), client, input)
		if err != nil {
			log.Errorf("Bucket %q: Error deleting old lifecycle configuration: %q\nOutput: %+v", bn, err.Error(), out)

			return false
		}

		if len(lfcRules) > 0 {
			// Create new versions of rules
			input := &s3.PutBucketLifecycleConfigurationInput{
				Bucket: aws.String(bn),
				LifecycleConfiguration: &types.BucketLifecycleConfiguration{
					Rules: lfcRules,
				},
			}

			log.Debugf("Apply lifecycle configuration: %+v", *input)

			out, err := uf.PutBucketLifecycleConfiguration(context.TODO(), client, input)

			retryCount--

			if err != nil {
				log.Debugf("Error applying Lifecycle Configuration: %q.\nOutput: %+v\nRetry attempts left: %v", err.Error(), out, retryCount)

				time.Sleep(1 * time.Second)

			} else {
				break
			}

			if retryCount == 0 && err != nil {
				log.Errorf("Error applying Lifecycle Configuration: %q", err.Error())

				return false

			}

		} else {
			break
		}

	}

	return true
}

func applyS3BucketPolicy(bn string, b ut.Bucket, client *s3.Client) bool {
	var retryCount int

	log.Infof("Bucket %q: Update Bucket policy", bn)

	// Create Bucket policy JSON
	log.Debugf("Bucket %q: Generate Bucket policy", bn)

	BucketPolicy, err := createBucketPolicy(&bn, &b)

	if err != nil {
		log.Errorf("Bucket %q: error marshaling Bucket policy to JSON: %q", bn, err)

		return false
	}

	log.Debugf("Bucket %q: Bucket policy:\n%s", bn, BucketPolicy)

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
			log.Debugf("Error applying Bucket policy: %q.\nOutput: %+v\nRetry attempts left: %v", err.Error(), out, retryCount)

			time.Sleep(1 * time.Second)

		} else {
			break
		}

		if retryCount == 0 && err != nil {
			log.Errorf("Error applying Lifecycle Configuration: %q", err.Error())

			return false

		}

	}

	return true
}

func applyS3Config(c *ut.Buckets, credsPath *string, bucketPostfix string) bool {
	log.Info("Apply new configuration on server")

	var retryCount int

	client := createS3SvcClient(credsPath)

	for bn, b := range *c {
		// Create bucket
		bn = bn + bucketPostfix

		if b.BucketType == "new" {
			log.Infof("Create bucket %q", bn)

			retryCount = retryNum

			for retryCount > 0 {
				input := &s3.CreateBucketInput{
					Bucket: &bn,
				}
				out, err := uf.CreateBucket(context.TODO(), client, input)

				retryCount--

				if err != nil {
					log.Debugf("Error creating bucket: %q.\nOutput: %+v\nRetry attempts left: %v", err.Error(), out, retryCount)

					time.Sleep(1 * time.Second)

				} else {
					log.Debugf("Bucket %q created", bn)

					break
				}

				if retryCount == 0 && err != nil {
					log.Errorf("Error creating bucket: %q", err.Error())

					return false
				}

			}

		}

		// Apply versioning if bucketType "new" or "updated"
		if b.VersioningType == "updated" {
			log.Infof("Bucket %q: Update versioning", bn)

			var status types.BucketVersioningStatus = types.BucketVersioningStatus(strcase.ToCamel(b.Versioning))

			log.Debugf("Versioning status: %q", status)

			retryCount = retryNum

			for retryCount > 0 {
				input := &s3.PutBucketVersioningInput{
					Bucket: aws.String(bn),
					VersioningConfiguration: &types.VersioningConfiguration{
						Status: status,
					},
				}

				log.Debugf("Apply versioning: %+v", *input)

				out, err := uf.PutBucketVersioning(context.TODO(), client, input)

				retryCount--

				if err != nil {
					log.Debugf("Error set versioning: %q.\nOutput: %+v\nRetry attempts left: %v", err.Error(), out, retryCount)

					time.Sleep(1 * time.Second)

				} else {
					break
				}

				if retryCount == 0 && err != nil {
					log.Errorf("Error set versioning: %q", err.Error())

					return false
				}

			}

		}

		// Apply Bucket ACLs and Bucket Policy
		switch aclType := b.AclType; aclType {
		case "new", "updated":
			/*
				Bucket ACL not supported yet in Ceph RGW S3
			*/
			/*
				if !applyS3Acl(bn, b, client) {
					return false
				}
			*/
			if !applyS3BucketPolicy(bn, b, client) {
				return false
			}

		case "error":
			log.Errorf("Bucket %q: ACL with type 'error' can't be applied! Skip.", bn)
		}

		// Apply Lifecycle Configuration
		switch LfcType := b.LifecycleType; LfcType {
		case "new":

			if !applyS3LifecycleConfiguration(bn, b, client) {
				return false
			}

		case "updated":

			if !applyS3LifecycleConfiguration(bn, b, client) {
				return false
			}

		case "error":
			log.Errorf("Bucket %q: Lifecycle configuration with type 'error' can't be applied! Skip.", bn)
		}

	}

	return true
}

func configureS3(confPath string, credsPath string, bucketPostfix string) int {
	log.Infof("Load buckets configuration from %q", confPath)

	localCfg, loadOk := loadS3ConfigFile(&confPath)

	if !loadOk {
		log.Errorf("Error loading file %q", localCfg)

		return 1
	}

	log.Debugf("Loaded local configuration: %+v", localCfg)
	log.Info("Load buckets configuration from server")

	srvCfg := getS3Config(&credsPath, &bucketPostfix)

	log.Debugf("Loaded server configuration: %+v", srvCfg)

	newSrvConfig, cfgUpdated := compareConfigs(localCfg, srvCfg)

	if cfgUpdated {
		// Test and sort configuration struct
		yaml_model, _ := yaml.Marshal(&newSrvConfig)
		err := yaml.Unmarshal(yaml_model, newSrvConfig)

		if err != nil {
			log.Errorf("Test new configuration was failed: %q", err.Error())
			log.Debugf("Broken configuration: %+v", newSrvConfig)

			return 1
		}

		log.Debugf("New configuration: %+v", newSrvConfig)

		if !applyS3Config(&newSrvConfig, &credsPath, bucketPostfix) {
			return 1
		}
	} else {
		log.Info("Server's configuration already up to date")

		return 200
	}

	return 0
}

func init() {
	app.Version(printVersion())
	kingpin.MustParse(app.Parse(os.Args[1:]))
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	//customFormatter.DisableLevelTruncation = true
	log.SetFormatter(customFormatter)

	if *debug {
		log.SetLevel(log.DebugLevel)
	}
}

func main() {
	var exitCode int

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case appFlags.FullCommand():
		log.Debugf("Command: %q", appFlags.FullCommand())
		log.Debugf("Flag --app-config:     %q", *appAppConfig)
		log.Debugf("Flag --ceph-config:    %q", *appS3Config)

		*appAppConfig, _ = filepath.Abs(*appAppConfig)
		*appS3Config, _ = filepath.Abs(*appS3Config)
		exitCode = updateConfigFromApp(*appAppConfig, *appS3Config)
	case createFlags.FullCommand():
		log.Debugf("Command: %q", createFlags.FullCommand())
		log.Debugf("Flag --ceph-config:    %q", *createS3Config)
		log.Debugf("Flag --credentials:    %q", *createCredentials)
		log.Debugf("Flag --bucket-postfix: %q", *createBucketPostfix)

		*createS3Config, _ = filepath.Abs(*createS3Config)
		*createCredentials, _ = filepath.Abs(*createCredentials)
		exitCode = createS3ConfigFile(*createS3Config, *createCredentials, *createBucketPostfix)
	case cfgFlags.FullCommand():
		log.Debugf("Command: %q", cfgFlags.FullCommand())
		log.Debugf("Flag --ceph-config:    %q", *cfgS3Config)
		log.Debugf("Flag --credentials:    %q", *cfgCredentials)
		log.Debugf("Flag --bucket-postfix: %q", *cfgBucketPostfix)

		*cfgS3Config, _ = filepath.Abs(*cfgS3Config)
		*cfgCredentials, _ = filepath.Abs(*cfgCredentials)
		exitCode = configureS3(*cfgS3Config, *cfgCredentials, *cfgBucketPostfix)

		if exitCode == 0 {
			log.Infof("Server configuration updated successfully")

			log.Info("Update local config from server")
			exitCode = createS3ConfigFile(*cfgS3Config, *cfgCredentials, *cfgBucketPostfix)
		} else if exitCode == 200 {
			exitCode = 0
		}
	}

	if exitCode > 0 {
		log.Fatalf("Exit code: %d", exitCode)
	}

	log.Debugf("Exit code: %d", exitCode)

	os.Exit(0)

}
