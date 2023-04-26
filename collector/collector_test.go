package collector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func prepareTestData(t *testing.T, c *Collector) {
	tmpDir := t.TempDir()

	if c.CephCredentialsPath != "" {
		c.CephCredentialsPath, _ = filepath.Abs(filepath.Join(tmpDir, c.CephCredentialsPath))
	}

	if c.CephConfigPath != "" {
		c.CephConfigPath, _ = filepath.Abs(filepath.Join(tmpDir, c.CephConfigPath))
	}

	if c.AppConfigPath != "" {
		c.AppConfigPath, _ = filepath.Abs(filepath.Join(tmpDir, c.AppConfigPath))
	}

	if c.CsvFilePath != "" {
		c.CsvFilePath, _ = filepath.Abs(filepath.Join(tmpDir, c.CsvFilePath))
	}

	if c.YamlFilePath != "" {
		c.YamlFilePath, _ = filepath.Abs(filepath.Join(tmpDir, c.YamlFilePath))
	}
}

func TestSetDefaults(t *testing.T) {
	setDefaultsTests := map[string]struct {
		collector   Collector
		expected    Collector
		expectError bool
	}{
		"test01": {
			Collector{Logger: collector.Logger},
			Collector{DisableSSL: true, AwsRegion: "us-east-2"},
			true,
		},
		"test02": {
			Collector{Logger: collector.Logger},
			Collector{DisableSSL: false, AwsRegion: "us-east-1"},
			false,
		},
	}

	for testName, testData := range setDefaultsTests {
		t.Run(testName, func(t *testing.T) {
			testData.collector.setDefaults()

			if (testData.collector.DisableSSL != testData.expected.DisableSSL) && !testData.expectError {
				t.Errorf("Output '%t' not equal to expected '%t'", testData.collector.DisableSSL, testData.expected.DisableSSL)
			}
			if (testData.collector.AwsRegion != testData.expected.AwsRegion) && !testData.expectError {
				t.Errorf("Output '%s' not equal to expected '%s'", testData.collector.AwsRegion, testData.expected.AwsRegion)
			}
		})
	}
}

func TestLoadCredentials(t *testing.T) {

	loadCredentialsTests := map[string]struct {
		collector   Collector
		credData    []byte
		expectError bool
		expected    Collector
	}{
		"test01": {
			Collector{
				Logger:              collector.Logger,
				CephCredentialsPath: ""},
			[]byte(""),
			true,
			Collector{Logger: collector.Logger},
		},
		"test02": {
			Collector{
				Logger:              collector.Logger,
				CephCredentialsPath: "./collector_test_credentials_config.yml"},
			[]byte(`endpoint_url: "127.0.0.1:8080"
access_key: "445S7Y2GPP3R2PV2XH62"
secret_key: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89"
disable_ssl: True`),
			false,
			Collector{
				EndpointUrl:  "127.0.0.1:8080",
				AwsAccessKey: "445S7Y2GPP3R2PV2XH62",
				AwsSecretKey: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89",
				DisableSSL:   true,
				Logger:       collector.Logger,
			},
		},
	}

	for testName, testData := range loadCredentialsTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)
			testData.expected.CephCredentialsPath = testData.collector.CephCredentialsPath

			if testData.collector.CephCredentialsPath != "" {
				if err := os.WriteFile(testData.collector.CephCredentialsPath, testData.credData, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}
			err := testData.collector.loadCredentials()

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")
			}

			if !reflect.DeepEqual(testData.collector, testData.expected) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", testData.collector, testData.expected)
			}
		})
	}
}

func TestCreateCephClient(t *testing.T) {
	createCephClientTests := map[string]struct {
		collector   Collector
		credData    []byte
		expectError bool
		expected    Collector
	}{
		"test01": {
			Collector{
				Logger:              collector.Logger,
				CephCredentialsPath: ""},
			[]byte(""),
			false,
			Collector{
				Logger:    collector.Logger,
				AwsRegion: "us-east-1"},
		},
		"test02": {
			Collector{
				Logger:              collector.Logger,
				CephCredentialsPath: "./collector_test_credentials_config.yml"},
			[]byte(`endpoint_url: "127.0.0.1:8080"
access_key: "445S7Y2GPP3R2PV2XH62"
secret_key: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89"
disable_ssl: True`),
			false,
			Collector{
				Logger:       collector.Logger,
				EndpointUrl:  "127.0.0.1:8080",
				AwsAccessKey: "445S7Y2GPP3R2PV2XH62",
				AwsSecretKey: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89",
				AwsRegion:    "us-east-1",
				DisableSSL:   true},
		},
		"test03": {
			Collector{
				Logger:              collector.Logger,
				CephCredentialsPath: "./collector_test_credentials_config.yml"},
			[]byte(`endpoint_url: "127.0.0.1:8080"
access_key: "445S7Y2GPP3R2PV2XH62"
secret_key: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89"
disable_ssl: False`),
			false,
			Collector{
				Logger:       collector.Logger,
				EndpointUrl:  "127.0.0.1:8080",
				AwsAccessKey: "445S7Y2GPP3R2PV2XH62",
				AwsSecretKey: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89",
				AwsRegion:    "us-east-1",
				DisableSSL:   false},
		},
		"test04": {
			Collector{
				Logger:              collector.Logger,
				CephCredentialsPath: "./collector_test_credentials_config.yml"},
			[]byte(`endpoint_url: ""
access_key: "445S7Y2GPP3R2PV2XH62"
secret_key: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89"
disable_ssl: False`),
			false,
			Collector{
				Logger:       collector.Logger,
				EndpointUrl:  "",
				AwsAccessKey: "445S7Y2GPP3R2PV2XH62",
				AwsSecretKey: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89",
				AwsRegion:    "us-east-1",
				DisableSSL:   false},
		},
		"test05": {
			Collector{
				Logger:              collector.Logger,
				CephCredentialsPath: "./collector_test_credentials_config.yml"},
			[]byte(`endpoint_url: ""
access_key: ""
secret_key: ""`),
			false,
			Collector{
				Logger:    collector.Logger,
				AwsRegion: "us-east-1"},
		},
		// TODO: find a way to get error when create API-client
	}

	for testName, testData := range createCephClientTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)
			testData.expected.CephCredentialsPath = testData.collector.CephCredentialsPath

			if testData.collector.CephCredentialsPath != "" {
				if err := os.WriteFile(testData.collector.CephCredentialsPath, testData.credData, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}

			err := testData.collector.createCephClient()
			testData.expected.CephClient = testData.collector.CephClient

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")
			}
			if !reflect.DeepEqual(testData.collector, testData.expected) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", testData.collector, testData.expected)
			}
		})
	}
}

func TestLoadCephConfigFile(t *testing.T) {
	loadCephConfigFileTests := map[string]struct {
		collector   Collector
		confData    []byte
		expectError bool
		expected    buckets
	}{
		"test01": {
			Collector{
				Logger:         collector.Logger,
				CephConfigPath: ""},
			[]byte(""),
			true,
			buckets{},
		},
		"test02": {
			Collector{
				Logger:         collector.Logger,
				CephConfigPath: "./collector_test_ceph_config.yml"},
			[]byte(`bar:
  acl:
    grants:
      full_control:
      - s3_admin
      read:
      - alice
      - bob
      write:
      - bob
    owner:
      display_name: S3 Admin
      id: s3_admin
  lifecycle_rules:
  - cur_ver_expiration_days: 30
    id: DeleteOldDone
    non_cur_ver_expiration_days: -1
    prefix: done/
    status: enabled
  - cur_ver_expiration_days: 365
    id: DeleteOldErrors
    non_cur_ver_expiration_days: -1
    prefix: errors/
    status: enabled
  versioning: enabled
Test02_Error_In_Name_Case:
  acl:
    grants:
      full_control: []
      read: []
      write: []
    owner:
      display_name: ""
      id: ""
  lifecycle_rules: []
  versioning: suspended
# comment here
foo:
  acl:
    grants:
      full_control:
      - alice
      - s3_admin
      read:
      - bob
      write:
      - s3_admin
    owner:
      display_name: S3 Admin
      id: s3_admin
  lifecycle_rules:
  - cur_ver_expiration_days: 31
    id: DeleteOldDone
    non_cur_ver_expiration_days: -1
    prefix: done/
    status: enabled
  - cur_ver_expiration_days: 365
    id: DeleteOldErrors
    non_cur_ver_expiration_days: -1
    prefix: errors/
    status: disabled
  versioning: suspended`),
			false,
			buckets{
				"bar": Bucket{
					Acl: BucketAcl{
						Grants: AclGrants{
							FullControl: []string{"s3_admin"},
							Read:        []string{"alice", "bob"},
							Write:       []string{"bob"},
						},
						Owner: AclOwner{
							DisplayName: "S3 Admin",
							Id:          "s3_admin",
						},
					},
					LifecycleRules: []LifecycleRule{
						{ExpirationDays: 30,
							Id:             "DeleteOldDone",
							NonCurrentDays: -1,
							Prefix:         "done/",
							Status:         "enabled"},
						{ExpirationDays: 365,
							Id:             "DeleteOldErrors",
							NonCurrentDays: -1,
							Prefix:         "errors/",
							Status:         "enabled"},
					},
					Versioning: "enabled",
					name:       "bar",
				},
				"foo": Bucket{
					Acl: BucketAcl{
						Grants: AclGrants{
							FullControl: []string{"alice", "s3_admin"},
							Read:        []string{"bob"},
							Write:       []string{"s3_admin"},
						},
						Owner: AclOwner{
							DisplayName: "S3 Admin",
							Id:          "s3_admin",
						},
					},
					LifecycleRules: []LifecycleRule{
						{ExpirationDays: 31,
							Id:             "DeleteOldDone",
							NonCurrentDays: -1,
							Prefix:         "done/",
							Status:         "enabled"},
						{ExpirationDays: 365,
							Id:             "DeleteOldErrors",
							NonCurrentDays: -1,
							Prefix:         "errors/",
							Status:         "disabled"},
					},
					Versioning: "suspended",
					name:       "foo",
				},
			},
		},
	}

	for testName, testData := range loadCephConfigFileTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)

			if testData.collector.CephConfigPath != "" {
				if err := os.WriteFile(testData.collector.CephConfigPath, testData.confData, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}

			err := testData.collector.loadCephConfigFile(testData.collector.CephConfigPath)

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")
			}

			if !reflect.DeepEqual(testData.collector.CephBuckets, testData.expected) {
				t.Errorf("Output '%+v' not equal to expected '%+v'", testData.collector.CephBuckets, testData.expected)
			}
		})
	}
}

func TestUpdateConfigurationFromApp(t *testing.T) {
	updateConfigurationFromAppTests := map[string]struct {
		collector   Collector
		cephBuckets buckets
		expected    bool
	}{
		"test01": {
			Collector{
				Logger:     collector.Logger,
				appBuckets: []string{"bar", "baz"}},
			buckets{
				"bar": Bucket{},
				"baz": Bucket{},
			},
			false,
		},
		"test02": {
			Collector{
				Logger:     collector.Logger,
				appBuckets: []string{"bar", "baz", "test02"}},
			buckets{
				"bar": Bucket{},
				"baz": Bucket{},
			},

			true,
		},
		"test03": {
			Collector{Logger: collector.Logger},
			buckets{
				"bar": Bucket{},
				"baz": Bucket{},
			},
			false,
		},
		"test04": {
			Collector{Logger: collector.Logger},
			buckets{},
			false,
		},
	}

	for testName, testData := range updateConfigurationFromAppTests {
		t.Run(testName, func(t *testing.T) {
			testData.collector.CephBuckets = testData.cephBuckets
			if got := testData.collector.updateConfigurationFromApp(); got != testData.expected {
				t.Errorf("Output '%t' not equal to expected '%t'", got, testData.expected)
			}
		})
	}
}

func TestWriteCephConfig(t *testing.T) {
	writeCephConfigTests := map[string]struct {
		collector   Collector
		expectError bool
	}{
		"test01": {
			Collector{
				CephConfigPath: "",
				Logger:         collector.Logger},
			true,
		},
		"test02": {
			Collector{
				CephConfigPath: "./collector_test_ceph_config.yml",
				Logger:         collector.Logger},
			false,
		},
		"test03": {
			Collector{
				CephBuckets: buckets{
					"bar": Bucket{name: "bar"},
					"foo": Bucket{name: "foo"},
				},
				CephConfigPath: "./collector_test_ceph_config.yml",
				Logger:         collector.Logger},
			false,
		},
	}

	for testName, testData := range writeCephConfigTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)

			err := testData.collector.writeCephConfig()

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")
			}
		})
	}
}

func TestLoadAppConfig(t *testing.T) {
	loadAppConfigTests := map[string]struct {
		collector   Collector
		appData     []byte
		expectError bool
		expected    []string
	}{
		"test01": {
			Collector{Logger: collector.Logger},
			[]byte(``),
			true,
			nil,
		},
		"test02": {
			Collector{
				Logger:        collector.Logger,
				AppConfigPath: "./collector_test_app_config.txt"},
			[]byte(`# comment string
// another comment string
# next 4 strings is blank/with spaces/with tabs/with both (tabs and spaces)

  
		
  	  
bar
baz
test02BadBucketName`),
			false,
			[]string{"bar", "baz"},
		},
		"test03": {
			Collector{
				Logger:        collector.Logger,
				AppConfigPath: "./collector_test_app_config.txt"},
			[]byte(`bar
baz
foo`),
			false,
			[]string{"bar", "baz", "foo"},
		},
	}

	for testName, testData := range loadAppConfigTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)

			if testData.collector.AppConfigPath != "" {
				if err := os.WriteFile(testData.collector.AppConfigPath, testData.appData, 0644); err != nil {
					t.Errorf("Error write test data file: '%s'", err.Error())
				}
			}

			err := testData.collector.loadAppConfig()

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")
			}

			if !reflect.DeepEqual(testData.collector.appBuckets, testData.expected) {
				t.Errorf("Output '%v' not equal to expected '%v'", testData.collector.appBuckets, testData.expected)
			}
		})
	}
}

func TestWriteBucketsToCsv(t *testing.T) {
	writeBucketsToCsvTests := map[string]struct {
		collector   Collector
		expectError bool
	}{
		"test01": {
			Collector{Logger: collector.Logger},
			true,
		},
		"test02": {
			Collector{
				Logger: collector.Logger,
				CephBuckets: buckets{
					"bar": Bucket{},
					"baz": Bucket{}},
				CsvFieldSeparator: "\r",
				CsvFilePath:       "./collector_test_buckets_acl.csv"},
			true,
		},
		"test03": {
			Collector{
				Logger: collector.Logger,
				CephBuckets: buckets{
					"bar": Bucket{
						Acl: BucketAcl{Grants: AclGrants{
							Read:  []string{`string;with-uncommon-characters§c\İ\n0xC0¶∑§d`},
							Write: []string{"normal-string"},
						}},
					},
					"baz": Bucket{}},
				CsvFieldSeparator: ";",
				CsvFilePath:       "./collector_test_buckets_acl.csv"},
			false,
		},
	}

	for testName, testData := range writeBucketsToCsvTests {
		t.Run(testName, func(t *testing.T) {
			prepareTestData(t, &testData.collector)

			err := testData.collector.writeBucketsToCsv()

			if err != nil && !testData.expectError {
				t.Errorf("Output got unexpected error '%s'", err.Error())
			}
			if err == nil && testData.expectError {
				t.Errorf("Output expect error but got nothing")
			}
		})
	}
}
