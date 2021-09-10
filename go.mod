module github.com/ashokhin/ceph-buckets

go 1.16

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20210208195552-ff826a37aa15 // indirect
	github.com/ashokhin/ceph-buckets/funcs v0.0.0-20210910055508-809bbd7e4670
	github.com/ashokhin/ceph-buckets/types v0.0.0-20210910055128-731cc1e6f17c
	github.com/aws/aws-sdk-go-v2 v1.9.0
	github.com/aws/aws-sdk-go-v2/config v1.8.0
	github.com/aws/aws-sdk-go-v2/credentials v1.4.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.15.0
	github.com/aws/smithy-go v1.8.0
	github.com/iancoleman/strcase v0.2.0
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/sys v0.0.0-20210423082822-04245dca01da // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
