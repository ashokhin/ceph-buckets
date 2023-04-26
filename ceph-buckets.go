package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ashokhin/ceph-buckets/collector"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

const (
	// In Ceph need to set "HostnameImmutable" option to true for resolving path to bucket right
	forcePath bool = true
	retryNum  int  = 10
)

var (
	collectorConfig collector.Collector

	appName                    = "ceph-buckets"
	appBranch                  = "None"
	appVersion                 = "dev"
	appRevision                = "0"
	appOrigin                  = "./"
	appBuildUser               = "nobody"
	appBuildDate               = "None"
	app                        = kingpin.New("ceph-buckets", "A command-line application for manage Ceph configuration of Amazon S3-compatible storage based on Ceph.")
	debug                      = app.Flag("debug", "Enable debug mode.").Bool()
	parallelThreads            = app.Flag("parallel", "Number of parallel threads.").Default("100").Int()
	appFlags                   = app.Command("app", "Create/Update Ceph configuration YAML-file from application's TXT-file.")
	appAppConfig               = appFlags.Flag("app-config", "Application's TXT-file, contains buckets list.").Default("./app_buckets_config.txt").String()
	appCephConfig              = appFlags.Flag("ceph-config", "Ceph configuration YAML-file.").Default("./ceph_config.yml").String()
	createFlags                = app.Command("create", "Create/Update Ceph configuration YAML-file from server.")
	createCephConfig           = createFlags.Flag("ceph-config", "Ceph configuration YAML-file.").Default("./ceph_config.yml").String()
	createCredentials          = createFlags.Flag("credentials", "Ceph credentials YAML-file.").Default("./ceph_credentials.yml").String()
	createBucketPostfix        = createFlags.Flag("bucket-postfix", "Bucket postfix to be deleted from the bucket name.").Default("").String()
	cfgFlags                   = app.Command("config", "Create/Update Ceph configuration on server from YAML-file.")
	cfgCephConfig              = cfgFlags.Flag("ceph-config", "Ceph configuration YAML-file.").Default("./ceph_config.yml").String()
	cfgCredentials             = cfgFlags.Flag("credentials", "Ceph credentials YAML-file.").Default("./ceph_credentials.yml").String()
	cfgBucketPostfix           = cfgFlags.Flag("bucket-postfix", "Bucket postfix to be added to the bucket name.").Default("").String()
	csv2yamlFlags              = app.Command("parse-csv", "Parse CSV source file and write result to YAML file.")
	csv2yamlCsvFile            = csv2yamlFlags.Flag("csv-file", "Source CSV file, contains buckets ACL.").Default("./buckets_acl.csv").String()
	csv2yamlYamlFile           = csv2yamlFlags.Flag("yaml-file", "Destination YAML file.").Default("./ceph_config_from_csv.yml").String()
	csv2yamlFieldsPerRecord    = csv2yamlFlags.Flag("fields-per-record", "Number of fields per record").Default("3").Int()
	csv2yamlFieldsSeparator    = csv2yamlFlags.Flag("fields-sep", "Fields separator for CSV fields").Default(";").String()
	yaml2csvFlags              = app.Command("parse-yaml", "Parse YAML source file and write result to CSV file.")
	yaml2csvYamlFile           = yaml2csvFlags.Flag("yaml-file", "Source YAML file, contains buckets ACL.").Default("./ceph_config.yml").String()
	yaml2csvCsvFile            = yaml2csvFlags.Flag("csv-file", "Destination CSV file.").Default("./buckets_acl_from_yaml.csv").String()
	yaml2csvCsvFieldsSeparator = yaml2csvFlags.Flag("fields-sep", "Fields separator for CSV fields").Default(";").String()
)

func printVersion() string {
	return fmt.Sprintf(`%q build info:
	version:              %q
	repo:                 %q
	branch:               %q
	revision:             %q
	build_user:           %q
	build_date:           %q`, appName, appVersion, appOrigin, appBranch, appRevision, appBuildUser, appBuildDate)
}

func init() {
	app.Version(printVersion())
	kingpin.MustParse(app.Parse(os.Args[1:]))

	collectorConfig = collector.Collector{
		ForcePath:       forcePath,
		ParallelThreads: *parallelThreads,
		LoggerDebug:     *debug,
		RetryNum:        retryNum,
	}

	collectorConfig.Logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))

	if collectorConfig.LoggerDebug {
		collectorConfig.Logger = level.NewFilter(collectorConfig.Logger, level.AllowDebug())
	} else {
		collectorConfig.Logger = level.NewFilter(collectorConfig.Logger, level.AllowInfo())
	}

	timestampFormat := log.TimestampFormat(
		func() time.Time { return time.Now().UTC() },
		"2006-01-02T15:04:05.000000Z07:00",
	)
	collectorConfig.Logger = log.With(collectorConfig.Logger, "timestamp", timestampFormat, "caller", log.DefaultCaller)
}

func main() {
	var err error
	var cfgUpdated bool

	timeStart := time.Now()
	flag.Parse()
	logger := collectorConfig.Logger

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case appFlags.FullCommand():
		level.Debug(logger).Log("command", appFlags.FullCommand())
		level.Debug(logger).Log("flag", "--app-config", "value", *appAppConfig)
		level.Debug(logger).Log("flag", "--ceph-config", "value", *appCephConfig)

		collectorConfig.AppConfigPath, _ = filepath.Abs(*appAppConfig)
		collectorConfig.CephConfigPath, _ = filepath.Abs(*appCephConfig)
		err = collectorConfig.UpdateConfigFromApp()

	case createFlags.FullCommand():
		level.Debug(logger).Log("command", createFlags.FullCommand())
		level.Debug(logger).Log("flag", "--ceph-config", "value", *createCephConfig)
		level.Debug(logger).Log("flag", "--credentials", "value", *createCredentials)
		level.Debug(logger).Log("flag", "--bucket-postfix", "value", *createBucketPostfix)

		collectorConfig.CephConfigPath, _ = filepath.Abs(*createCephConfig)
		collectorConfig.CephCredentialsPath, _ = filepath.Abs(*createCredentials)
		collectorConfig.BucketsPostfix = *createBucketPostfix
		err = collectorConfig.CreateCephConfigFile()
	case cfgFlags.FullCommand():
		level.Debug(logger).Log("command", cfgFlags.FullCommand())
		level.Debug(logger).Log("flag", "--ceph-config", "value", *cfgCephConfig)
		level.Debug(logger).Log("flag", "--credentials", "value", *cfgCredentials)
		level.Debug(logger).Log("flag", "--bucket-postfix", "value", *cfgBucketPostfix)

		collectorConfig.CephConfigPath, _ = filepath.Abs(*cfgCephConfig)
		collectorConfig.CephCredentialsPath, _ = filepath.Abs(*cfgCredentials)
		collectorConfig.BucketsPostfix = *cfgBucketPostfix
		cfgUpdated, err = collectorConfig.ConfigureCephServer()

		if cfgUpdated {
			level.Info(logger).Log("msg", "server's configuration updated successfully")
			level.Info(logger).Log("msg", "update local config from server")

			err = collectorConfig.CreateCephConfigFile()
		}
	case csv2yamlFlags.FullCommand():
		level.Debug(logger).Log("command", csv2yamlFlags.FullCommand())
		level.Debug(logger).Log("flag", "--csv-file", "value", *csv2yamlCsvFile)
		level.Debug(logger).Log("flag", "--yaml-file", "value", *csv2yamlYamlFile)
		level.Debug(logger).Log("flag", "--fields-sep", "value", *csv2yamlFieldsSeparator)
		level.Debug(logger).Log("flag", "--fields-per-record", "value", *csv2yamlFieldsPerRecord)

		collectorConfig.CsvFilePath, _ = filepath.Abs(*csv2yamlCsvFile)
		collectorConfig.YamlFilePath, _ = filepath.Abs(*csv2yamlYamlFile)
		collectorConfig.CsvFieldSeparator = *csv2yamlFieldsSeparator
		collectorConfig.CsvFieldsNum = *csv2yamlFieldsPerRecord
		err = collectorConfig.ParseCsvToYaml()
	case yaml2csvFlags.FullCommand():
		level.Debug(logger).Log("command", yaml2csvFlags.FullCommand())
		level.Debug(logger).Log("flag", "--yaml-file", "value", *yaml2csvYamlFile)
		level.Debug(logger).Log("flag", "--csv-file", "value", *yaml2csvCsvFile)
		level.Debug(logger).Log("flag", "--fields-sep", "value", *yaml2csvCsvFieldsSeparator)

		collectorConfig.YamlFilePath, _ = filepath.Abs(*yaml2csvYamlFile)
		collectorConfig.CsvFilePath, _ = filepath.Abs(*yaml2csvCsvFile)
		collectorConfig.CsvFieldSeparator = *yaml2csvCsvFieldsSeparator
		err = collectorConfig.ParseYamlToCsv()
	}

	if err != nil {
		level.Error(logger).Log("msg", "exit main", "error", err.Error(), "exit_code", 1)
		level.Warn(logger).Log("msg", "operation failed", "elapsed_time", time.Since(timeStart))

		os.Exit(1)
	}

	level.Debug(logger).Log("msg", "exit main", "exit_code", 0)
	level.Info(logger).Log("msg", "operation success", "elapsed_time", time.Since(timeStart))

	os.Exit(0)

}
