package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	"encoding/csv"

	ut "github.com/ashokhin/ceph-buckets/types"
	"github.com/go-kit/log/level"
	yaml "gopkg.in/yaml.v2"
)

func recordToArr(r string) []string {
	return strings.Fields(r)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func parseCsvToYaml(csvFile string, yamlFile string, csvSep string, csvFieldsNum int) error {
	var subusers []string

	buckets, _ := loadS3ConfigFile(&yamlFile)

	file, err := os.Open(csvFile)

	if err != nil {
		level.Error(logger).Log("msg", "failed to open CSV file", "file", csvFile, "error:", err)
	}

	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = []rune(csvSep)[0]
	reader.FieldsPerRecord = csvFieldsNum
	reader.Comment = '#'

	csvRecords, err := reader.ReadAll()

	if err != nil {
		level.Error(logger).Log("msg", "failed to parse CSV. Check CSV field separator and use `--csv-sep` flag for setup it", "error:", err)

		return err
	}

	for index, record := range csvRecords {
		if index == 0 {
			continue
		}

		var b ut.Bucket

		bn := record[0]

		if bucket, ok := buckets[bn]; ok {
			level.Debug(logger).Log("msg", "bucket already exists. Update", "bucket", bn)

			b = bucket

		} else {
			level.Debug(logger).Log("msg", "bucket is new.", "bucket", bn)
			// Versioning disabled by default
			b.Versioning = "suspended"
		}

		if len(record[1]) > 0 {
			b.Acl.Grants.Read = append([]string{}, recordToArr(record[1])...)
			for _, subuser := range recordToArr(record[1]) {
				if !contains(subusers, subuser) {
					subusers = append(subusers, subuser)
				}
			}

		}

		if len(record[2]) > 0 {
			b.Acl.Grants.Write = append([]string{}, recordToArr(record[2])...)
			for _, subuser := range recordToArr(record[2]) {
				if !contains(subusers, subuser) {
					subusers = append(subusers, subuser)
				}
			}
		}

		buckets[bn] = b

	}

	data, err := yaml.Marshal(&buckets)

	if err != nil {
		fmt.Printf("Failed to parse yaml. Error: '%s'", err.Error())
		return err
	}

	if err = os.WriteFile(yamlFile, data, 0644); err != nil {
		return err
	}

	return nil
}

func parseYamlToCsv(yamlFile string, csvFile string, csvSep string) error {

	cfg := make(ut.Buckets)

	f, err := ioutil.ReadFile(yamlFile)

	if err != nil {
		level.Error(logger).Log("msg", "error reading file", "file", yamlFile, "err", err.Error())

		return err
	}

	if err = yaml.Unmarshal(f, &cfg); err != nil {
		level.Error(logger).Log("msg", "error unmarshaling YAML", "file", yamlFile, "err", err.Error())

		return err
	}

	keys := make([]string, 0, len(cfg))

	for k := range cfg {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	file, err := os.OpenFile(csvFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		level.Error(logger).Log("error", err)

		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Comma = []rune(csvSep)[0]

	for index, bucket := range keys {
		if index == 0 {
			//fmt.Fprintln(w, `"bucket";"read";"write"`)
			csvHeader := []string{"bucket", "read", "write"}
			if err := writer.Write(csvHeader); err != nil {
				level.Error(logger).Log("msg", "error writing header to file", "error", err)

				return err
			}
		}
		bucket_cfg := cfg[bucket]
		bucketString := []string{bucket, strings.Join(bucket_cfg.Acl.Grants.Read, " "), strings.Join(bucket_cfg.Acl.Grants.Write, " ")}
		level.Debug(logger).Log("msg", "write string", "record", fmt.Sprintf("%s", bucketString))

		if err := writer.Write(bucketString); err != nil {
			level.Error(logger).Log("msg", "error writing record to file", "record", bucketString, "error", err)

			return err
		}
	}

	return nil
}
