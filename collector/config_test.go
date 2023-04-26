package collector

import (
	"os"
	"testing"
)

func TestUpdateConfigFromApp(t *testing.T) {
	updateConfigFromAppTests := map[string]struct {
		collector   Collector
		appData     []byte
		cephData    []byte
		expectError bool
	}{
		"test01": {
			Collector{
				Logger:        collector.Logger,
				LoggerDebug:   collector.LoggerDebug,
				AppConfigPath: ""},
			nil,
			nil,
			true,
		},
		"test02": {
			Collector{
				Logger:         collector.Logger,
				LoggerDebug:    collector.LoggerDebug,
				AppConfigPath:  "./collector_test_app_config.txt",
				CephConfigPath: "./collector_test_ceph_config.yml"},
			[]byte("bar"),
			nil,
			false,
		},
		"test03": {
			Collector{
				Logger:         collector.Logger,
				LoggerDebug:    true,
				AppConfigPath:  "./collector_test_app_config.txt",
				CephConfigPath: "./collector_test_ceph_config.yml"},
			[]byte("bar"),
			[]byte("bad-yaml"),
			false,
		},
		"test04": {
			Collector{
				Logger:         collector.Logger,
				LoggerDebug:    true,
				AppConfigPath:  "./collector_test_app_config.txt",
				CephConfigPath: "./collector_test_ceph_config.yml"},
			[]byte("bar"),
			[]byte(`baz:
foo:`),
			false,
		},
		"test05": {
			Collector{
				Logger:         collector.Logger,
				LoggerDebug:    true,
				AppConfigPath:  "./collector_test_app_config.txt",
				CephConfigPath: "./collector_test_ceph_config.yml"},
			[]byte("bar"),
			[]byte("bar:"),
			false,
		},
	}

	for testName, testData := range updateConfigFromAppTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)

			if testData.collector.AppConfigPath != "" {
				if err := os.WriteFile(testData.collector.AppConfigPath, testData.appData, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}
			if testData.collector.CephConfigPath != "" {
				if err := os.WriteFile(testData.collector.CephConfigPath, testData.cephData, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}

			err := testData.collector.UpdateConfigFromApp()

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")
			}
		})
	}
}

func TestParseCsvToYaml(t *testing.T) {
	parseCsvToYamlTests := map[string]struct {
		collector   Collector
		csvData     []byte
		expectError bool
	}{
		"test01": {
			Collector{Logger: collector.Logger},
			nil,
			true,
		},
		"test02": {
			Collector{
				Logger:            collector.Logger,
				CsvFilePath:       "./collector_test_buckets_acl.csv",
				CsvFieldSeparator: ";"},
			[]byte(`"bucket";"read";"write"
"bar";"alice bob";"bob"
"baz";"";""
"foo";"bob";"s3_admin"`),
			true,
		},
		"test03": {
			Collector{
				Logger:            collector.Logger,
				YamlFilePath:      "./collector_test_ceph_config.yml",
				CsvFilePath:       "./collector_test_buckets_acl.csv",
				CsvFieldSeparator: ";"},
			[]byte(`"bucket";"read";"write"
"bar";"alice bob";"bob"
"baz";"";""
"foo";"bob";"s3_admin"`),
			false,
		},
	}

	for testName, testData := range parseCsvToYamlTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)

			if testData.collector.CsvFilePath != "" {
				if err := os.WriteFile(testData.collector.CsvFilePath, testData.csvData, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}

			err := testData.collector.ParseCsvToYaml()

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")
			}
		})
	}
}

func TestParseYamlToCsv(t *testing.T) {
	parseYamlToCsvTests := map[string]struct {
		collector   Collector
		yamlData    []byte
		expectError bool
	}{
		"test01": {
			Collector{Logger: collector.Logger},
			nil,
			true,
		},
		"test02": {
			Collector{
				Logger:            collector.Logger,
				YamlFilePath:      "./collector_test_ceph_config.yml",
				CsvFieldSeparator: ";"},
			[]byte(`bar:
  acl:
    grants:
      full_control:
      - s3_admin
      read:
      - alice
      - bob
      write:
      - bob`),
			true,
		},
		"test03": {
			Collector{
				Logger:            collector.Logger,
				YamlFilePath:      "./collector_test_ceph_config.yml",
				CsvFilePath:       "./collector_test_buckets_acl.csv",
				CsvFieldSeparator: ";"},
			[]byte(`bar:
  acl:
    grants:
      full_control:
      - s3_admin
      read:
      - alice
      - bob
      write:
      - bob`),
			false,
		},
	}

	for testName, testData := range parseYamlToCsvTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)

			if testData.collector.YamlFilePath != "" {
				if err := os.WriteFile(testData.collector.YamlFilePath, testData.yamlData, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}

			err := testData.collector.ParseYamlToCsv()

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")
			}
		})
	}
}
