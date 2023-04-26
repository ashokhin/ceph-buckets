package collector

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"golang.org/x/sync/errgroup"
)

type Collector struct {
	EndpointUrl         string `yaml:"endpoint_url"`
	AwsAccessKey        string `yaml:"access_key"`
	AwsSecretKey        string `yaml:"secret_key"`
	DisableSSL          bool   `yaml:"disable_ssl"`
	AwsRegion           string `yaml:"aws_region"`
	BucketsPostfix      string
	ForcePath           bool
	AppConfigPath       string
	CephConfigPath      string
	CsvFilePath         string
	YamlFilePath        string
	CephCredentialsPath string
	CsvFieldSeparator   string
	CsvFieldsNum        int
	LoggerDebug         bool
	Logger              log.Logger
	CephBuckets         buckets
	CephClient          *s3.Client
	ParallelThreads     int
	RetryNum            int
	appBuckets          []string
	ctx                 context.Context
}

func (c *Collector) setDefaults() {
	c.DisableSSL = false
	c.AwsRegion = "us-east-1"
}

func (c *Collector) loadCredentials() error {
	if err := loadYamlFile(c.CephCredentialsPath, &c, c.Logger); err != nil {

		return err
	}

	return nil
}

func (c *Collector) createCephClient() error {
	var err error
	var cfg aws.Config

	level.Debug(c.Logger).Log("msg", "set defaults")

	c.setDefaults()

	level.Debug(c.Logger).Log("msg", "load Ceph credentials from file", "file", c.CephCredentialsPath)

	if err := c.loadCredentials(); err != nil {
		level.Warn(c.Logger).Log("msg", "error load Ceph credentials", "error", err.Error())
	}

	err = nil

	level.Debug(c.Logger).Log("msg", "create Ceph client")

	switch {
	// if endpoint present than connect to that endpoint
	case c.EndpointUrl != "":
		var cephUrl string

		if c.DisableSSL {
			cephUrl = fmt.Sprintf("http://%s/", c.EndpointUrl)
		} else {
			cephUrl = fmt.Sprintf("https://%s/", c.EndpointUrl)
		}

		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				PartitionID:       "aws",
				URL:               cephUrl,
				SigningRegion:     c.AwsRegion,
				HostnameImmutable: c.ForcePath,
			}, nil
		})

		cfg, err = config.LoadDefaultConfig(c.ctx,
			config.WithEndpointResolverWithOptions(customResolver),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AwsAccessKey, c.AwsSecretKey, "")),
		)
	// if credentials present than connect with that credentials
	case (c.AwsAccessKey != "") && (c.AwsSecretKey != ""):
		cfg, err = config.LoadDefaultConfig(c.ctx,
			config.WithRegion(c.AwsRegion),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AwsAccessKey, c.AwsSecretKey, "")),
		)
	// otherwise try to load credentials from '~/.aws/credentials'
	default:
		cfg, err = config.LoadDefaultConfig(c.ctx, config.WithRegion(c.AwsRegion))
	}

	if err != nil {
		level.Error(c.Logger).Log("msg", "failed load configuration", "error", err.Error())

		return err
	}

	c.CephClient = s3.NewFromConfig(cfg)

	return nil
}

func (c *Collector) loadCephConfigFile(f string) error {
	level.Debug(c.Logger).Log("msg", "load Ceph configuration from file", "file", f)

	if err := loadYamlFile(f, &c.CephBuckets, c.Logger); err != nil {
		c.CephBuckets = make(buckets)
		level.Debug(c.Logger).Log("msg", "Ceph configuration is blank")

		return err
	}

	// filter loaded configuration
	cfgTemp := make(buckets)

	for bucketName, bucket := range c.CephBuckets {
		if err := checkBucketName(bucketName); err != nil {
			switch err.(type) {
			case *errBucketName:
				level.Warn(c.Logger).Log("msg", "bucket name error", "bucket", bucketName)
				level.Debug(c.Logger).Log("msg", "name not suitable for bucket naming rules", "error", err.Error(), "bucket", bucketName)
			}
			continue
		} else {
			bucket.name = bucketName
			cfgTemp[bucketName] = bucket
		}
	}

	c.CephBuckets = cfgTemp

	return nil
}

func (c *Collector) updateConfigurationFromApp() bool {
	var needUpdate bool
	var b Bucket

	for _, appBucket := range c.appBuckets {

		if _, ok := c.CephBuckets[appBucket]; ok {
			level.Debug(c.Logger).Log("msg", "bucket already in Ceph configuration file. skip", "bucket", appBucket, "file", c.CephConfigPath)

			continue
		}

		level.Info(c.Logger).Log("msg", "bucket is new. Add to Ceph configuration", "bucket", appBucket)

		needUpdate = true
		// Versioning disabled by default
		b.Versioning = "suspended"

		c.CephBuckets[appBucket] = b
	}

	return needUpdate
}

func (c *Collector) writeCephConfig() error {
	level.Debug(c.Logger).Log("msg", "write Ceph config into YAML file", "file", c.CephConfigPath)

	if err := writeYamlFile(c.CephConfigPath, c.CephBuckets, c.Logger); err != nil {
		level.Error(c.Logger).Log("msg", "error write Ceph configuration", "error", err.Error())

		return err
	}

	return nil
}

func (c *Collector) loadAppConfig() error {
	var err error

	fc, err := os.Open(c.AppConfigPath)

	if err != nil {
		level.Error(c.Logger).Log("msg", "error open file", "file", c.AppConfigPath, "error", err.Error())

		return err
	}

	scanner := bufio.NewScanner(fc)

	defer fc.Close()

	var pos int = 0
	for scanner.Scan() {
		s := scanner.Text()
		pos++

		if err := checkBucketName(s); err != nil {
			switch err.(type) {
			case *errBucketName:
				level.Warn(c.Logger).Log("msg", "bucket name error", "bucket", s)
				level.Debug(c.Logger).Log("msg", "bucket not suitable for bucket naming rules", "error", err.Error(), "bucket", s, "line", pos)
			case *errCommentString:
				level.Debug(c.Logger).Log("msg", "string skipped as a comment string", "value", s, "line", pos)
			case *errBlankString:
				level.Debug(c.Logger).Log("msg", "string skipped as a blank string", "line", pos)
			}
			continue
		} else {
			level.Debug(c.Logger).Log("msg", "bucket found in application's configuration file", "bucket", s, "file", c.AppConfigPath)

			c.appBuckets = append(c.appBuckets, s)
		}
	}

	return nil
}

func (c *Collector) loadCephConfigFromServer() error {
	var err error
	var wg sync.WaitGroup
	var collectorsNum int

	c.ctx = context.Background()

	level.Debug(c.Logger).Log("msg", "create Ceph client")

	if err := c.createCephClient(); err != nil {
		level.Error(c.Logger).Log("msg", "error create Ceph client", "error", err.Error())

		return err
	}

	level.Debug(c.Logger).Log("msg", "list buckets from Ceph storage")

	cephBucketsList, err := listBuckets(c.ctx, c.CephClient, &s3.ListBucketsInput{})

	if err != nil {
		level.Error(c.Logger).Log("msg", "error get buckets", "error", err.Error())

		return err
	}

	bucketsNum := len(cephBucketsList.Buckets)
	// init Buckets map
	c.CephBuckets = make(buckets)
	bucketsCh := make(chan types.Bucket, bucketsNum)
	resultsCh := make(chan Bucket, bucketsNum)

	for _, bucket := range cephBucketsList.Buckets {
		level.Debug(c.Logger).Log("msg", "get bucket details", "bucket", *bucket.Name)

		bucketsCh <- bucket
	}

	close(bucketsCh)

	if c.ParallelThreads < bucketsNum {
		level.Debug(c.Logger).Log("msg", "--parallel less than buckets count", "parallel", c.ParallelThreads, "buckets count", bucketsNum)
		collectorsNum = c.ParallelThreads
	} else {
		level.Debug(c.Logger).Log("msg", "--parallel more than buckets count", "parallel", c.ParallelThreads, "buckets count", bucketsNum)
		collectorsNum = bucketsNum
	}

	level.Debug(c.Logger).Log("msg", "run concurrency collectors", "count", collectorsNum)

	for i := 1; i <= collectorsNum; i++ {
		wg.Add(1)
		// get buckets info concurrently and write results to channel resultsCh
		go c.bucketCollector(&wg, i, bucketsCh, resultsCh)
	}

	wg.Wait()

	close(resultsCh)

	for b := range resultsCh {
		c.CephBuckets[b.name] = b
	}

	return err
}

func (c *Collector) bucketCollector(wg *sync.WaitGroup, id int, cephBuckets <-chan types.Bucket, results chan<- Bucket) {
	defer wg.Done()

	startTime := time.Now()
	collectorName := fmt.Sprintf("bucketCollector-%d", id)

	level.Debug(c.Logger).Log("msg", "bucket collector started", "id", collectorName)
	// read cephBuckets as 'types.Bucket' type from channel
	for cephBucket := range cephBuckets {
		level.Debug(c.Logger).Log("msg", "get bucket details", "id", collectorName, "bucket", cephBucket.Name)
		// get bucket map as 'Bucket' type
		b := getBucketDetailsToMap(cephBucket, c)
		level.Debug(c.Logger).Log("msg", "return bucket results", "id", collectorName, "bucket", b.name)

		results <- b
	}

	level.Debug(c.Logger).Log("msg", "bucket collector done all jobs", "id", collectorName, "duration", time.Since(startTime))
}

func (c *Collector) applyCephConfig() error {
	level.Debug(c.Logger).Log("msg", "create Ceph client")

	if err := c.createCephClient(); err != nil {
		level.Error(c.Logger).Log("msg", "error create Ceph client", "error", err.Error())

		return err
	}

	errGroup, errGrpContext := errgroup.WithContext(c.ctx)

	for bn, b := range c.CephBuckets {
		// Create bucket name with postfix
		cephBucket := b
		cephBucket.name = bn + c.BucketsPostfix
		cephBucket.ctx = errGrpContext

		errGroup.Go(func() error {
			return cephBucket.applyBucketConfig(c)
		})

	}

	return errGroup.Wait()
}

func (c *Collector) writeBucketsToCsv() error {
	var err error

	// Create slice for configuration sorting
	keys := make([]string, 0, len(c.CephBuckets))

	for k := range c.CephBuckets {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	file, err := os.OpenFile(c.CsvFilePath, os.O_RDWR|os.O_CREATE, 0644)

	if err != nil {
		level.Error(c.Logger).Log("msg", "error open CSV file", "file", c.CsvFilePath, "error", err.Error())

		return err
	}

	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Comma = []rune(c.CsvFieldSeparator)[0]

	for index, bucketName := range keys {
		if index == 0 {
			// create and write CSV-header first
			csvHeader := []string{"bucket", "read", "write"}

			level.Debug(c.Logger).Log("msg", "write CSV header", "value", fmt.Sprintf("%s", csvHeader))

			if err := writer.Write(csvHeader); err != nil {
				level.Error(c.Logger).Log("msg", "error write CSV header to file", "error", err.Error())

				return err
			}
		}

		bucketConfig := c.CephBuckets[bucketName]
		bucketString := []string{bucketName, strings.Join(bucketConfig.Acl.Grants.Read, " "), strings.Join(bucketConfig.Acl.Grants.Write, " ")}

		level.Debug(c.Logger).Log("msg", "write CSV string", "record", fmt.Sprintf("%s", bucketString))

		if err := writer.Write(bucketString); err != nil {
			level.Error(c.Logger).Log("msg", "error write CSV record to file", "record", bucketString, "file", c.CsvFilePath, "error", err.Error())

			return err
		}
	}

	return err
}
