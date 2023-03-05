package collector

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"gopkg.in/yaml.v3"
)

func fileExists(filepath string) error {
	var err error

	fileinfo, err := os.Stat(filepath)

	if os.IsNotExist(err) {
		return err
	}

	// Return error if the fileinfo says the file path is a directory.
	if fileinfo.IsDir() {
		return newIsDirError(fmt.Sprintf("'%v' is a directory", filepath))
	}

	return nil
}

// loadYamlFile read YAML file to byte slice than
// yaml.Unmarshal decodes the first document found within the in byte slice and assigns decoded values into the out value.
func loadYamlFile(filePath string, out interface{}, logger log.Logger) error {
	var err error
	var f []byte

	level.Debug(logger).Log("msg", "read YAML file", "file", filePath)

	if err := fileExists(filePath); err != nil {
		var isDirErr *errIsDir

		if os.IsNotExist(err) {
			level.Warn(logger).Log("msg", "YAML file does not exists", "error", err.Error())

			return err
		}

		if errors.As(err, &isDirErr) {
			level.Error(logger).Log("msg", "YAML path is not a file", "path", filePath, "error", err.Error())

			os.Exit(1)
		}
	}

	f, err = os.ReadFile(filePath)

	if err != nil {
		level.Warn(logger).Log("msg", "read file error", "error", err.Error())

		return err
	}

	if err := yaml.Unmarshal(f, out); err != nil {
		level.Error(logger).Log("msg", "error unmarshal YAML configuration", "error", err.Error())

		os.Exit(1)
	}

	return nil
}

func writeYamlFile(filePath string, in interface{}, logger log.Logger) error {
	data, err := yaml.Marshal(in)

	if err != nil {
		level.Error(logger).Log("msg", "error marshal struct to YAML", "error", err.Error())
		level.Debug(logger).Log("msg", "show struct", "struct", fmt.Sprintf("%v", in))

		return err
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		level.Error(logger).Log("msg", "error write YAML into Ceph configuration file", "error", err.Error())

		return err
	}
	return nil
}

func writeBucketsToCsv(c *Collector) error {
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
