module github.com/ashokhin/ceph-buckets

go 1.20

require (
	github.com/alecthomas/kingpin/v2 v2.3.1
	github.com/ashokhin/ceph-buckets/collector v0.0.0-00010101000000-000000000000
	github.com/go-kit/log v0.2.1
)

require (
	github.com/alecthomas/units v0.0.0-20151022065526-2efee857e7cf // indirect
	github.com/aws/aws-sdk-go-v2 v1.17.4 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.18.13 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.18 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.30.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.18.3 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/iancoleman/strcase v0.2.0 // indirect
	github.com/xhit/go-str2duration v1.2.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/ashokhin/ceph-buckets/collector => ./collector
