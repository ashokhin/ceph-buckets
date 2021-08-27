package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ashokhin/ceph-buckets/types"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v3"
)

const (
	awsRegion string = "us-east-1"
	forcePath bool   = true
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

	createFlags       = app.Command("create", "Create/Update Ceph configuration YAML-file from server.")
	createS3Config    = createFlags.Flag("ceph-config", "Ceph configuration YAML-file.").Default("./ceph_config.yml").String()
	createCredentials = createFlags.Flag("credentials", "Ceph credentials YAML-file.").Default("./ceph_credentials.yml").String()

	cfgFlags       = app.Command("config", "Create/Update Ceph configuration on server from YAML-file.")
	cfgS3Config    = cfgFlags.Flag("ceph-config", "Ceph configuration YAML-file.").Default("./ceph_config.yml").String()
	cfgCredentials = cfgFlags.Flag("credentials", "Ceph credentials YAML-file.").Default("./ceph_credentials.yml").String()
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

	log.Infof("Loading S3 configuration from %q", *credsPath)

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

func getS3Config(credsPath *string) map[string]types.Bucket {
	_, svc := createS3SvcClient(credsPath)
	// Create Bucket
	/* 	log.Warn("Create bucket! ", bucket)
	   	_, err := svc.CreateBucket(&s3.CreateBucketInput{
	   		Bucket: aws.String("bar"),
	   	})
	   	if err != nil {
	   		log.Fatalf("Unable to create bucket %q, %v", bucket, err)
	   	} */

	// Put Bucket Lifecycle configuration
	/* 	_, err := svc.PutBucketLifecycleConfiguration(&s3.PutBucketLifecycleConfigurationInput{
	   		Bucket: aws.String("foo"),
	   		LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
	   			Rules: []*s3.LifecycleRule{
	   				{
	   					Expiration: &s3.LifecycleExpiration{
	   						Days: aws.Int64(30),
	   					},
	   					Filter: &s3.LifecycleRuleFilter{
	   						Prefix: aws.String("done/"),
	   					},
	   					ID:     aws.String("DeleteOldDone"),
	   					Status: aws.String("Enabled"),
	   				},
	   				{
	   					Expiration: &s3.LifecycleExpiration{
	   						Days: aws.Int64(365),
	   					},
	   					Filter: &s3.LifecycleRuleFilter{
	   						Prefix: aws.String("errors/"),
	   					},
	   					ID:     aws.String("DeleteOldErrors"),
	   					Status: aws.String("Enabled"),
	   				},
	   			},
	   		},
	   	})

	   	if err != nil {
	   		if aerr, ok := err.(awserr.Error); ok {
	   			switch aerr.Code() {
	   			default:
	   				log.Errorln(aerr.Error())
	   			}
	   		} else {
	   			// Print the error, cast err to awserr.Error to get the Code and
	   			// Message from an error.
	   			log.Errorln(err.Error())
	   		}
	   	} */

	log.Infof("List buckets from %q", svc.Endpoint)

	listResult, err := svc.ListBuckets(nil)

	if err != nil {
		log.Fatalf("Error retrieving buckets: %q", err.Error())
	}

	log.Info("Buckets listed successfully")

	buckets := make(map[string]types.Bucket)

	for _, bucket := range listResult.Buckets {
		var b types.Bucket

		b.BucketType = "present"
		log.Debugf("Bucket: %q. Get bucket ACL...", *bucket.Name)
		aclResult, err := svc.GetBucketAcl(&s3.GetBucketAclInput{
			Bucket: aws.String(*bucket.Name),
		})

		if err != nil {
			log.Errorf("Error retriving bucket ACL: %q", err.Error())
		} else {

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

			b.Versioning = "error"
		} else {
			if len(vResult.GoString()) > 4 {
				b.Versioning = strings.ToLower(*vResult.Status)
			} else {
				b.Versioning = "disabled"
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
				}
			} else {
				log.Errorf("Error (raw) retriving bucket lifecycle: %q", err.Error())
			}
		} else {
			for _, r := range lfResult.Rules {
				log.Debugf("LF FUCKING RULE: %+v", r)

				var lfr types.LifecycleRule

				lfr.ExpirationDays = *r.Expiration.Days
				lfr.Id = *r.ID

				if strings.Contains(r.GoString(), "NoncurrentVersionExpiration") {
					lfr.NonCurrentDays = *r.NoncurrentVersionExpiration.NoncurrentDays
				} else {
					lfr.NonCurrentDays = -1
				}

				if strings.Contains(r.GoString(), "Prefix") {
					lfr.Prefix = *r.Filter.Prefix
				}

				lfr.Status = strings.ToLower(*r.Status)

				b.LifecycleRules = append(b.LifecycleRules, lfr)
			}
		}

		buckets[*bucket.Name] = b

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

func createS3ConfigFile(confPath string, credsPath string) int {
	var exitCode int

	buckets := getS3Config(&credsPath)
	log.Infof("Write config to %q", confPath)
	err := writeConfig(&buckets, &confPath)

	if err != nil {
		log.Errorf("Error writing file %q: %q", confPath, err.Error())

		exitCode = 1
		return exitCode
	}

	return exitCode
}

func loadS3ConfigFile(fs *string) (map[string]types.Bucket, bool) {
	cfg := make(map[string]types.Bucket)
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
		log.Debugf("Bucket %q founded in %q", s, appPath)
		appBuckets = append(appBuckets, s)
	}

	log.Debugf("appBuckets: %+v", appBuckets)
	log.Infof("Load buckets configuration from %q", confPath)

	confBuckets, loadOk := loadS3ConfigFile(&confPath)

	if loadOk {
		log.Debug("Buckets loaded:")

		if *debug {

			for _, confBucket := range confBuckets {
				fmt.Printf("\t- %+v\n", confBucket)
			}

		}

	} else {
		log.Warn("Create new configuration")

		confBuckets = make(map[string]types.Bucket)
	}

	for _, appBucket := range appBuckets {

		if _, ok := confBuckets[appBucket]; ok {
			log.Debugf("Bucket %q already in %q", appBucket, confPath)

			continue
		}

		var b types.Bucket

		log.Infof("Bucket %q is new. Add in %q", appBucket, confPath)

		needUpdate = true
		b.BucketType = "new"
		// Versioning disabled by default
		b.Versioning = "disabled"
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

func compareConfigs(lc types.Buckets, sc types.Buckets) types.Buckets {

	return make(types.Buckets)
}

func applyS3Config(confPath string, credsPath string) int {
	log.Infof("Load buckets configuration from %q", confPath)

	localCfg, loadOk := loadS3ConfigFile(&confPath)

	if !loadOk {
		log.Errorf("Error loading file %q")
		return 1
	}

	log.Debugf("Loaded local config: %+v", localCfg)

	log.Info("Load buckets configuration from server")

	srvCfg := getS3Config(&credsPath)

	log.Debugf("Loaded server config: %+v", srvCfg)

	newSrvConfig := compareConfigs(localCfg, srvCfg)

	log.Debugf("New config: %+v", newSrvConfig)

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
		log.Debugf("Flag --app-config:  %q", *appAppConfig)
		log.Debugf("Flag --ceph-config: %q", *appS3Config)

		exitCode = updateConfigFromApp(*appAppConfig, *appS3Config)
	case createFlags.FullCommand():
		log.Debugf("Command: %q", createFlags.FullCommand())
		log.Debugf("Flag --ceph-config: %q", *createS3Config)
		log.Debugf("Flag --credentials: %q", *createCredentials)

		exitCode = createS3ConfigFile(*createS3Config, *createCredentials)
	case cfgFlags.FullCommand():
		log.Debugf("Command: %q", cfgFlags.FullCommand())
		log.Debugf("Flag -ceph-config:  %q", *cfgS3Config)
		log.Debugf("Flag --credentials: %q", *cfgCredentials)

		/*
			TODO
			Write functions for compare and configuration Amazon S3-compatible Ceph storage
		*/
		exitCode = applyS3Config(*cfgS3Config, *cfgCredentials)
	}

	if exitCode > 0 {
		log.Fatalf("Exit code: %d", exitCode)
	}

	log.Debugf("Exit code: %d", exitCode)

	os.Exit(0)

}
