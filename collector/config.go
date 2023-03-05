package collector

import (
	"context"
	"fmt"
	"os"

	"github.com/go-kit/log/level"
	"gopkg.in/yaml.v3"
)

func UpdateConfigFromApp(c *Collector) error {
	var err error
	var appBuckets []string
	var confUpdated bool

	logger := c.Logger

	level.Info(logger).Log("msg", "load buckets list from application's configuration file", "file", c.AppConfigPath)

	// load list of buckets from '--app-config' path
	appBuckets, err = c.loadAppConfig()

	if err != nil {
		level.Warn(logger).Log("msg", "configuration not loaded", "error", err.Error())
	}

	if c.LoggerDebug {
		for _, bucketName := range appBuckets {
			level.Debug(logger).Log("msg", "bucket loaded from application's configuration file", "value", bucketName)
		}
	}

	level.Info(logger).Log("msg", "load buckets from Ceph configuration file", "file", c.CephConfigPath)

	// load buckets map from '--ceph-config' path
	if err = c.loadCephConfigFile(c.CephConfigPath); err != nil {
		level.Warn(logger).Log("msg", "configuration not loaded", "error", err.Error())
		level.Info(logger).Log("msg", "use blank Ceph configuration map")
	}

	if c.LoggerDebug {
		for bucketName := range c.CephBuckets {
			level.Debug(logger).Log("msg", "bucket loaded from Ceph configuration file", "bucket", bucketName)
		}
	}

	// Merge bucket configurations
	level.Info(logger).Log("msg", "merge configurations from application and Ceph configuration files")
	confUpdated = c.mergeConfigurations(appBuckets)

	if confUpdated {
		level.Info(logger).Log("msg", "Ceph config was updated. Write new config into Ceph configuration file", "file", c.CephConfigPath)

		if err := c.writeCephConfig(); err != nil {
			level.Error(logger).Log("msg", "Ceph configuration not wrote", "file", c.CephConfigPath, "error", err.Error())
			return err
		}
	} else {
		level.Info(logger).Log("msg", "new buckets not found")
	}

	return nil
}

func CreateCephConfigFile(c *Collector) error {
	var err error

	level.Info(c.Logger).Log("msg", "load Ceph config from server")

	if err := c.loadCephConfigFromServer(); err != nil {
		level.Error(c.Logger).Log("msg", "error load Ceph config from server", "error", err.Error())

		return err
	}

	level.Info(c.Logger).Log("msg", "write Ceph config from server to file", "file", c.CephConfigPath)

	if err := c.writeCephConfig(); err != nil {
		level.Error(c.Logger).Log("msg", "Ceph configuration not wrote", "file", c.CephConfigPath, "error", err.Error())
		return err
	}

	return err
}

func ConfigureCephServer(c *Collector) (bool, error) {
	var err error

	c.ctx = context.Background()

	level.Info(c.Logger).Log("msg", "load buckets configuration from file", "file", c.CephConfigPath)

	// load buckets map from '--ceph-config' path
	if err = c.loadCephConfigFile(c.CephConfigPath); err != nil {
		level.Warn(c.Logger).Log("msg", "configuration not loaded", "error", err.Error())
		level.Info(c.Logger).Log("msg", "use blank Ceph configuration map")
	}

	configFromFile := c.CephBuckets

	if c.LoggerDebug {
		for bucketName := range configFromFile {
			level.Debug(c.Logger).Log("msg", "bucket loaded from Ceph configuration file", "bucket", bucketName)
		}
	}

	level.Info(c.Logger).Log("msg", "load Ceph config from server")

	if err := c.loadCephConfigFromServer(); err != nil {
		level.Error(c.Logger).Log("msg", "error load Ceph config from server", "error", err.Error())

		return false, err
	}

	configFromServer := c.CephBuckets

	if c.LoggerDebug {
		for bucketName := range configFromServer {
			level.Debug(c.Logger).Log("msg", "bucket loaded from Ceph server", "bucket", bucketName)
		}
	}

	level.Info(c.Logger).Log("msg", "compare Ceph configurations loaded from file and from server")

	newSrvConfig, cfgUpdated := compareBuckets(configFromFile, configFromServer, c.Logger)

	if cfgUpdated {
		// Test and sort configuration struct
		yamlModel, _ := yaml.Marshal(&newSrvConfig)
		if err := yaml.Unmarshal(yamlModel, &newSrvConfig); err != nil {
			level.Error(c.Logger).Log("msg", "test new configuration was failed", "error", err.Error())
			level.Debug(c.Logger).Log("msg", "broken configuration", "value", fmt.Sprintf("%+v", newSrvConfig))

			return false, err
		}

		level.Debug(c.Logger).Log("msg", "show new configuration", "value", fmt.Sprintf("%+v", newSrvConfig))

		c.CephBuckets = newSrvConfig

		level.Info(c.Logger).Log("msg", "apply new configuration on server")

		if err = c.applyCephConfig(); err != nil {
			level.Error(c.Logger).Log("msg", "apply new configuration on server was failed", "error", err.Error())
			level.Debug(c.Logger).Log("msg", "show new configuration", "value", fmt.Sprintf("%+v", c))
			return false, err
		}

	} else {
		level.Info(c.Logger).Log("msg", "server's configuration already up to date")

		return false, nil
	}

	return true, nil
}

func ParseCsvToYaml(c *Collector) error {
	var err error

	level.Info(c.Logger).Log("msg", "parse CSV file and write results to YAML file", "csv-file", c.CsvFilePath, "yaml-file", c.YamlFilePath)
	csvRecords, err := csvParser(c)

	if err != nil {
		level.Error(c.Logger).Log("msg", "CSV parse failed", "error", err.Error())

		return err
	}

	// load buckets map from '--yaml-file' path
	if err = c.loadCephConfigFile(c.YamlFilePath); err != nil {
		level.Warn(c.Logger).Log("msg", "configuration from YAML file not loaded", "error", err.Error())
		level.Info(c.Logger).Log("msg", "use blank Ceph configuration map")
	}

	compareCsvToBuckets(csvRecords, c)

	data, err := yaml.Marshal(c.CephBuckets)

	if err != nil {
		level.Error(c.Logger).Log("msg", "failed to parse yaml", "error", err.Error())

		return err
	}

	if err = os.WriteFile(c.YamlFilePath, data, 0644); err != nil {

		return err
	}

	return err
}

func ParseYamlToCsv(c *Collector) error {
	var err error

	level.Info(c.Logger).Log("msg", "parse YAML file and write results to CSV file", "yaml-file", c.YamlFilePath, "csv-file", c.CsvFilePath)
	// load buckets map from '--yaml-file' path
	if err = c.loadCephConfigFile(c.YamlFilePath); err != nil {
		level.Warn(c.Logger).Log("msg", "configuration from YAML file not loaded", "error", err.Error())
		level.Info(c.Logger).Log("msg", "nothing to write")

		return err
	}

	if err = writeBucketsToCsv(c); err != nil {
		level.Error(c.Logger).Log("msg", "error write YAML config to CSV file", "error", err.Error())

		return err
	}

	return nil
}
