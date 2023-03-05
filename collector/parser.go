package collector

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/go-kit/log/level"
)

func csvParser(c *Collector) ([][]string, error) {
	file, err := os.Open(c.CsvFilePath)

	if err != nil {
		level.Error(c.Logger).Log("msg", "failed to open CSV file", "file", c.CsvFilePath, "error", err.Error())

		return nil, err
	}

	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = []rune(c.CsvFieldSeparator)[0]
	reader.FieldsPerRecord = c.CsvFieldsNum
	reader.Comment = '#'

	csvRecords, err := reader.ReadAll()

	if err != nil {
		level.Error(c.Logger).Log("msg", "failed to parse CSV. Check CSV field separator and use `--csv-sep` flag for setup it OR check number of CSV fields and use `--fields-per-record` flag for setup it", "error", err.Error())

		return nil, err
	}

	return csvRecords, nil

}

func compareCsvToBuckets(csvRecords [][]string, c *Collector) {

	for index, record := range csvRecords {
		if index == 0 {
			if record[0] == "bucket" && record[1] == "read" && record[2] == "write" {
				level.Info(c.Logger).Log("msg", "the first CSV record looks like CSV header and will be skipped", "record", fmt.Sprintf("%v", record))

				continue
			}
		}

		var b Bucket

		bucketName := record[0]

		if bucket, ok := c.CephBuckets[bucketName]; ok {
			level.Debug(c.Logger).Log("msg", "bucket already exists. Update", "bucket", bucketName)

			b = bucket

		} else {
			level.Debug(c.Logger).Log("msg", "bucket is new", "bucket", bucketName)
			// Versioning disabled by default
			b.Versioning = "suspended"
		}

		b.name = bucketName

		if len(record[1]) > 0 {
			b.Acl.Grants.Read = append([]string{}, recordToArr(record[1])...)
			level.Debug(c.Logger).Log("msg", "add users to read grants", "bucket", bucketName, "users", fmt.Sprintf("%+v", b.Acl.Grants.Read))
		}

		if len(record[2]) > 0 {
			b.Acl.Grants.Write = append([]string{}, recordToArr(record[2])...)
			level.Debug(c.Logger).Log("msg", "add users to write grants", "bucket", bucketName, "users", fmt.Sprintf("%+v", b.Acl.Grants.Write))
		}

		c.CephBuckets[bucketName] = b
	}
}
