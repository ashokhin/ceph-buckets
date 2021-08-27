package types

type Config struct {
	EndpointUrl  string `yaml:"endpoint_url"`
	AwsAccessKey string `yaml:"access_key"`
	AwsSecretKey string `yaml:"secret_key"`
	DisableSSL   bool   `yaml:"disable_ssl"`
}

type AclGrants struct {
	FullControl []string `yaml:"full_control"`
	Read        []string `yaml:"read"`
	Write       []string `yaml:"write"`
}

type AclOwner struct {
	DisplayName string `yaml:"display_name"`
	Id          string `yaml:"id"`
}

type BucketAcl struct {
	Grants AclGrants `yaml:"grants"`
	Owner  AclOwner  `yaml:"owner"`
}

type LifecycleRule struct {
	ExpirationDays int64  `yaml:"cur_ver_expiration_days"`
	Id             string `yaml:"id"`
	NonCurrentDays int64  `yaml:"non_cur_ver_expiration_days"`
	Prefix         string `yaml:"prefix"`
	Status         string `yaml:"status"`
}

type Bucket struct {
	Acl            BucketAcl       `yaml:"acl"`
	AclType        string          `yaml:"acl_type"`
	BucketType     string          `yaml:"bucket_type"`
	LifecycleRules []LifecycleRule `yaml:"lifecycle_rules"`
	Versioning     string          `yaml:"versioning"`
}

type Buckets map[string]Bucket

func (conf *Config) SetDefaults() {
	if conf.EndpointUrl == "" {
		conf.EndpointUrl = "127.0.0.1:8880"
	}
}

func (b Buckets) HasKey(k string) bool {
	_, ok := b[k]
	return ok
}
