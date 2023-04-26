package collector

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestFileExists(t *testing.T) {
	fileExistsTests := map[string]struct {
		arg1     string
		data     []byte
		expected error
	}{
		"test01": {
			"./test01_file.txt",
			[]byte("test01"),
			nil,
		},
		"test02": {
			"./test02_file.txt",
			[]byte(""),
			&fs.PathError{Op: "stat", Path: "./test02_file.txt", Err: syscall.ENOENT},
		},
		"test03": {
			"./",
			[]byte(""),
			&errIsDir{path: "./"},
		},
	}

	for testName, testData := range fileExistsTests {
		t.Run(testName, func(t *testing.T) {
			if testData.expected == nil {
				tmpDir := t.TempDir()
				testData.arg1, _ = filepath.Abs(filepath.Join(tmpDir, testData.arg1))
				if err := os.WriteFile(testData.arg1, testData.data, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}

			err := fileExists(testData.arg1)
			if testData.expected != nil {
				if !reflect.DeepEqual(err, testData.expected) {
					t.Errorf("Output '%#v' not equal to expected '%#v'", err, testData.expected)
				}
			}
		})
	}
}

func TestLoadYamlFile(t *testing.T) {
	loadYamlFileTests := map[string]struct {
		arg2         interface{}
		collector    Collector
		testData     []byte
		expectError  bool
		expectedData interface{}
	}{
		"test01": {
			nil,
			Collector{
				Logger:       collector.Logger,
				LoggerDebug:  collector.LoggerDebug,
				YamlFilePath: "./test_buckets.yaml"},
			nil,
			true,
			nil,
		},
		"test02": {
			nil,
			Collector{
				Logger:       collector.Logger,
				LoggerDebug:  collector.LoggerDebug,
				YamlFilePath: "./test_buckets.yaml"},
			nil,
			true,
			nil,
		},
		"test03": {
			nil,
			Collector{
				Logger:       collector.Logger,
				LoggerDebug:  collector.LoggerDebug,
				YamlFilePath: "./test_buckets.yaml"},
			nil,
			true,
			nil,
		},
		"test04": {
			buckets{},
			Collector{
				Logger:       collector.Logger,
				LoggerDebug:  collector.LoggerDebug,
				YamlFilePath: "./test_buckets.yaml"},
			[]byte(`baz:
foo:`),
			false,
			buckets{
				"baz": Bucket{
					Acl: BucketAcl{
						Grants: AclGrants{
							FullControl: []string(nil),
							Read:        []string(nil),
							Write:       []string(nil)},
						Owner: AclOwner{
							DisplayName: "",
							Id:          ""},
					},
					AclType:        "",
					BucketType:     "",
					LifecycleRules: []LifecycleRule(nil),
					LifecycleType:  "",
					Versioning:     "",
					VersioningType: "",
					name:           "",
					ctx:            context.Context(nil)},
				"foo": Bucket{
					Acl: BucketAcl{
						Grants: AclGrants{
							FullControl: []string(nil),
							Read:        []string(nil),
							Write:       []string(nil)},
						Owner: AclOwner{
							DisplayName: "", Id: ""},
					},
					AclType:        "",
					BucketType:     "",
					LifecycleRules: []LifecycleRule(nil),
					LifecycleType:  "",
					Versioning:     "",
					VersioningType: "",
					name:           "",
					ctx:            context.Context(nil)},
			},
		},
	}

	for testName, testData := range loadYamlFileTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)

			if testName == "test02" {
				os.Mkdir(testData.collector.YamlFilePath, 0755)
			}

			if testData.collector.YamlFilePath != "" && testData.testData != nil {
				if err := os.WriteFile(testData.collector.YamlFilePath, testData.testData, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}

			err := loadYamlFile(testData.collector.YamlFilePath, testData.arg2, testData.collector.Logger)

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%#v'", err)

				return
			}

			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")

				return
			}

			if !reflect.DeepEqual(testData.arg2, testData.expectedData) {
				t.Errorf("Output '%#v' not equal to expected '%#v'", testData.arg2, testData.expectedData)
			}
		})
	}
}
