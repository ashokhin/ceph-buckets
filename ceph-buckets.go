package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ashokhin/ceph-buckets/types"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/iancoleman/strcase"
	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v3"
)

const (
	awsRegion string = "us-east-1"
	forcePath bool   = true
	retry_num int    = 10
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

func loadConfig(fs *string) (*types.Config, bool) {
	var cfg *types.Config

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

func createS3SvcClient(credsPath *string) (*types.Config, *s3.S3) {
	var sess *session.Session

	log.Debug("Create client for specified context")
	log.Debugf("Loading S3 connection settings from %q", *credsPath)

	yamlConfig, loadOk := loadConfig(credsPath)

	if !loadOk {
		log.Warnf("Config %q isn't loaded", *credsPath)
	}

	yamlConfig.SetDefaults()
	awsCreds := credentials.NewStaticCredentials(yamlConfig.AwsAccessKey, yamlConfig.AwsSecretKey, "")
	sess, err := session.NewSession()

	if err != nil {
		log.Errorf("Error creating session: %q", err.Error())
	}

	cfg := aws.NewConfig()

	cfg.WithCredentials(awsCreds)
	cfg.WithRegion(awsRegion)
	cfg.WithEndpoint(yamlConfig.EndpointUrl)
	cfg.WithDisableSSL(yamlConfig.DisableSSL)
	cfg.WithS3ForcePathStyle(forcePath)

	svc := s3.New(sess, cfg)

	return yamlConfig, svc
}

func getS3Config(credsPath *string, bucketPostfix *string) types.Buckets {
	_, svc := createS3SvcClient(credsPath)

	log.Infof("List buckets from %q", svc.Endpoint)

	listResult, err := svc.ListBuckets(nil)

	if err != nil {
		log.Fatalf("Error retrieving buckets: %q", err.Error())
	}

	log.Info("Buckets listed successfully")

	buckets := make(types.Buckets)
	matchPattern := fmt.Sprintf("%s$", *bucketPostfix)
	re := regexp.MustCompile(matchPattern)

	for _, bucket := range listResult.Buckets {
		var b types.Bucket
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

		log.Debugf("Bucket: %q. Get bucket ACL...", *bucket.Name)

		aclResult, err := svc.GetBucketAcl(&s3.GetBucketAclInput{
			Bucket: aws.String(*bucket.Name),
		})

		if err != nil {
			log.Errorf("Error retriving bucket ACL: %q", err.Error())

			b.AclType = "error"
		} else {
			log.Debugf("Bucket: %q, ACL: %+v", *bucket.Name, aclResult)

			for _, grants := range aclResult.Grants {

				if *grants.Permission == "FULL_CONTROL" {
					b.Acl.Grants.FullControl = append(b.Acl.Grants.FullControl, *grants.Grantee.ID)
				} else if *grants.Permission == "READ" {
					b.Acl.Grants.Read = append(b.Acl.Grants.Read, *grants.Grantee.ID)
				} else if *grants.Permission == "WRITE" {
					b.Acl.Grants.Write = append(b.Acl.Grants.Write, *grants.Grantee.ID)
				} else {
					log.Warnf("Permission type %q unsupported. Skip permission type", *grants.Permission)
				}

			}

			b.Acl.Owner.DisplayName = *aclResult.Owner.DisplayName
			b.Acl.Owner.Id = *aclResult.Owner.ID
		}

		log.Debugf("Bucket: %q. Get bucket versioning...", *bucket.Name)

		vResult, err := svc.GetBucketVersioning(&s3.GetBucketVersioningInput{
			Bucket: aws.String(*bucket.Name),
		})

		if err != nil {
			log.Errorf("Error while retriving versioning configuration: %q", err.Error())

			b.VersioningType = "error"
		} else {

			if len(vResult.GoString()) > 4 {
				b.Versioning = strings.ToLower(*vResult.Status)
			} else {
				b.Versioning = "suspended"
			}

		}

		log.Debugf("Bucket: %q. Get bucket lifecycle...", *bucket.Name)

		lfResult, err := svc.GetBucketLifecycleConfiguration(&s3.GetBucketLifecycleConfigurationInput{
			Bucket: aws.String(*bucket.Name),
		})

		log.Debugf("Got Lifecycle result: %+v", lfResult)

		if err != nil {

			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case "NoSuchLifecycleConfiguration":
					log.Debugf("Bucket: %q. Lifecycle configuration not found", *bucket.Name)

				default:
					log.Errorf("Error retriving bucket lifecycle: %q", aerr.Error())

					b.LifecycleType = "error"
				}
			} else {
				log.Errorf("Error (raw) retriving bucket lifecycle: %q", err.Error())
			}

		} else {

			for _, r := range lfResult.Rules {
				var lfr types.LifecycleRule

				lfr.ExpirationDays = *r.Expiration.Days
				lfr.Id = *r.ID

				if strings.Contains(r.GoString(), "NoncurrentVersionExpiration") {
					lfr.NonCurrentDays = *r.NoncurrentVersionExpiration.NoncurrentDays
				} else {
					lfr.NonCurrentDays = -1
				}

				if strings.Contains(r.GoString(), "Filter") {
					// New version of Ceph return "Prefix" inside struct "Filter"
					lfr.Prefix = *r.Filter.Prefix
				} else if strings.Contains(r.GoString(), "Prefix") {
					// New version of Ceph return "Prefix" inside struct "LifecycleRule"
					lfr.Prefix = *r.Prefix
				}

				lfr.Status = strings.ToLower(*r.Status)

				b.LifecycleRules = append(b.LifecycleRules, lfr)
			}

		}

		buckets[bn] = b

	}

	log.Debugf("Buckets golang struct: %+v", buckets)
	log.Debug("Test YAML marshaling...")

	data, err := yaml.Marshal(&buckets)

	if err != nil {
		log.Fatalf("Error while marshal buckets to YAML: %q", err.Error())
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

func loadS3ConfigFile(fs *string) (types.Buckets, bool) {
	cfg := make(types.Buckets)
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

		confBuckets = make(types.Buckets)
	}

	for _, appBucket := range appBuckets {

		if _, ok := confBuckets[appBucket]; ok {
			log.Debugf("Bucket %q already in %q", appBucket, confPath)

			continue
		}

		var b types.Bucket

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

func aclEqual(lc *types.Bucket, sc types.Bucket, b *string) bool {
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

func lfcIsEqual(lc *types.Bucket, sc types.Bucket, b *string) bool {
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

func compareConfigs(lc types.Buckets, sc types.Buckets) (types.Buckets, bool) {
	var needUpdate bool = false

	newCfg := make(types.Buckets)

	log.Info("Compare local and server's configurations")

	for k, v := range lc {

		if sc.HasKey(k) {
			log.Debugf("Bucket %q already exist on server", k)
			log.Debugf("Add server struct to result configuration: %+v", sc[k])

			newCfgBucket := sc[k]
			// Compare ACLs
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

func applyS3Config(c *types.Buckets, credsPath *string, bucketPostfix string) bool {
	log.Info("Apply new configuration on server")

	var retry_count int

	for bn, b := range *c {
		// Create bucket
		bn = bn + bucketPostfix
		if b.BucketType == "new" {
			log.Infof("Create bucket %q", bn)

			retry_count = retry_num

			for retry_count > 0 {
				_, svc := createS3SvcClient(credsPath)
				input := &s3.CreateBucketInput{
					Bucket: &bn,
				}
				_, err := svc.CreateBucket(input)

				retry_count--

				if err != nil {
					log.Debugf("Error creating bucket: %q. Retry attempts left: %v", err.Error(), retry_count)

					time.Sleep(1 * time.Second)

				} else {
					log.Debugf("Bucket %q created", bn)

					break
				}

				if retry_count == 0 && err != nil {
					log.Errorf("Error creating bucket: %q", err.Error())

					return false
				}

			}

		}

		// Apply versioning if bucketType "new" or "updated"
		if b.VersioningType == "updated" {
			log.Infof("Bucket %q: Update versioning", bn)

			status := strcase.ToCamel(b.Versioning)
			log.Debugf("Versioning status: %q", status)

			retry_count = retry_num

			for retry_count > 0 {
				_, svc := createS3SvcClient(credsPath)
				input := &s3.PutBucketVersioningInput{
					Bucket: aws.String(bn),
					VersioningConfiguration: &s3.VersioningConfiguration{
						Status: aws.String(status),
					},
				}

				log.Debugf("Apply versioning: %+v", input)

				_, err := svc.PutBucketVersioning(input)

				retry_count--

				if err != nil {
					log.Debugf("Error set versioning: %q. Retry attempts left: %v", err.Error(), retry_count)

					time.Sleep(1 * time.Second)

				} else {
					break
				}

				if retry_count == 0 && err != nil {
					log.Errorf("Error set versioning: %q", err.Error())

					return false
				}

			}

		}

		// Apply ACLs
		if b.AclType != "error" {
			log.Infof("Bucket %q: Update ACL", bn)
			log.Debugf("Bucket %q: Get owner", bn)

			retry_count = retry_num

			_, svc := createS3SvcClient(credsPath)
			input := &s3.GetBucketAclInput{
				Bucket: aws.String(bn),
			}

			ba, err := svc.GetBucketAcl(input)

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
				newGrantee := s3.Grantee{ID: aws.String(g), Type: aws.String("CanonicalUser")}
				newGrant := s3.Grant{Grantee: &newGrantee, Permission: aws.String("FULL_CONTROL")}
				grants = append(grants, &newGrant)
			}

			for _, g := range b.Acl.Grants.Read {
				newGrantee := s3.Grantee{ID: aws.String(g), Type: aws.String("CanonicalUser")}
				newGrant := s3.Grant{Grantee: &newGrantee, Permission: aws.String("READ")}
				grants = append(grants, &newGrant)
			}

			for _, g := range b.Acl.Grants.Write {
				newGrantee := s3.Grantee{ID: aws.String(g), Type: aws.String("CanonicalUser")}
				newGrant := s3.Grant{Grantee: &newGrantee, Permission: aws.String("WRITE")}
				grants = append(grants, &newGrant)
			}

			log.Debugf("Bucket %q: Set grants: %+v", bn, grants)

			retry_count = retry_num

			for retry_count > 0 {
				_, svc := createS3SvcClient(credsPath)
				input := &s3.PutBucketAclInput{
					Bucket: aws.String(bn),
					AccessControlPolicy: &s3.AccessControlPolicy{
						Grants: grants,
						Owner: &s3.Owner{
							DisplayName: aws.String(owner),
							ID:          aws.String(ownerId),
						},
					},
				}

				log.Debugf("Apply ACL: +%v", input)

				_, err = svc.PutBucketAcl(input)

				retry_count--

				if err != nil {
					log.Debugf("Error applying ACL: %q. Retry attempts left: %v", err.Error(), retry_count)

					time.Sleep(1 * time.Second)

				} else {
					break
				}

				if retry_count == 0 && err != nil {
					log.Errorf("Error applying ACL: %q", err.Error())

					return false
				}

			}

		}

		// Apply Lifrcycle Configuration
		if b.LifecycleType != "error" {
			log.Infof("Bucket %q: Update Lifecycle configuration", bn)

			lfcRules := []*s3.LifecycleRule{}
			for _, lc := range b.LifecycleRules {
				log.Debugf("LC rule: %+v", lc)

				if (lc.NonCurrentDays >= 0) && (b.Versioning == "suspended") {
					log.Warnf("Bucket %q: Lifecycle rule %q contains non-negative value for non-current version expiration, but bucket versioning is disabled!", bn, lc.Id)

					lc.NonCurrentDays = -1
				}

				// Specifies the expiration for the lifecycle of the object
				status := strcase.ToCamel(lc.Status)
				newLCRule := s3.LifecycleRule{}

				if lc.NonCurrentDays >= 0 {
					newLCRule = s3.LifecycleRule{
						Expiration: &s3.LifecycleExpiration{
							Days: aws.Int64(lc.ExpirationDays),
						},
						Filter: &s3.LifecycleRuleFilter{
							Prefix: aws.String(lc.Prefix),
						},
						ID: aws.String(lc.Id),
						NoncurrentVersionExpiration: &s3.NoncurrentVersionExpiration{
							NoncurrentDays: aws.Int64(lc.NonCurrentDays),
						},
						Status: aws.String(status),
					}
				} else {
					newLCRule = s3.LifecycleRule{
						Expiration: &s3.LifecycleExpiration{
							Days: aws.Int64(lc.ExpirationDays),
						},
						Filter: &s3.LifecycleRuleFilter{
							Prefix: aws.String(lc.Prefix),
						},
						ID:     aws.String(lc.Id),
						Status: aws.String(status),
					}
				}

				lfcRules = append(lfcRules, &newLCRule)
			}

			retry_count = retry_num

			for retry_count > 0 {
				log.Debugf("Bucket %q: Set Lifecycle configuration: %+v", bn, lfcRules)

				_, svc := createS3SvcClient(credsPath)
				// Recreate/Delete lifecycle rules
				// first: Delete old rules
				input := &s3.DeleteBucketLifecycleInput{
					Bucket: aws.String(bn),
				}

				_, err := svc.DeleteBucketLifecycle(input)
				if err != nil {
					log.Errorf("Error deleting old lifecycle configuration: %q", err.Error())

					return false
				}

				if len(lfcRules) > 0 {
					// Create new versions of rules
					input := &s3.PutBucketLifecycleConfigurationInput{
						Bucket: aws.String(bn),
						LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
							Rules: lfcRules,
						},
					}

					log.Debugf("Apply lifecycle configuration: %+v", input)

					_, err := svc.PutBucketLifecycleConfiguration(input)

					retry_count--

					if err != nil {
						log.Debugf("Error applying Lifecycle Configuration: %q. Retry attempts left: %v", err.Error(), retry_count)

						time.Sleep(1 * time.Second)

					} else {
						break
					}

					if retry_count == 0 && err != nil {
						log.Errorf("Error applying Lifecycle Configuration: %q", err.Error())

						return false

					}

				} else {
					break
				}

			}

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
