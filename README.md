# ceph-buckets - Amazon S3-compatible storage manager

A utility for managing Ceph buckets that provides storage driven by a RESTful API compatible with Amazon Simple Storage Service (Amazon S3).

You can read more about the capabilities of S3-compatible storage in the Ceph documentation [(link to documentation)](https://docs.ceph.com/en/latest/radosgw/s3/#).

## Preliminary work on Ceph:

### Create the main user:

For the main user, run the following command on Ceph:

```
radosgw-admin user create --uid="s3_admin" --display-name="S3 Admin" --key-type="s3"
```

Here **s3_admin** is the user under which the connection to the storage will be performed and buckets will be created. 

"**S3 Admin**" is the display name. This setting does not affect anything.

### Create additional users:

To create additional users, you must create them as inherited (sub-user) from the main user.

Example for users **bob** and **alice**:
```
radosgw-admin subuser create --uid="s3_admin" --subuser="alice" --display-name="alice" --key-type="s3"
radosgw-admin subuser create --uid="s3_admin" --subuser="bob" --display-name="bob" --key-type="s3"
```

:exclamation: ATTENTION! Inheriting users from the main user is necessary so that additional users can see the buckets created by the main user.

### Here and below:

- `ceph-buckets`
     : binary file for creating and updating buckets in Amazon S3-compatible Ceph storage;
- `ceph_config.yml`
     : configuration file containing data about buckets and their configuration (see example [ceph_config_example.yml](./ceph_config_example.yml));
- `ceph_credentials.yml`
     : file containing the data required to connect to the Ceph storage. (see example [ceph_credentials_example.yml](./ceph_credentials_example.yml))
- `app_buckets_config.txt`
     : file containing a list of buckets required for the application to work (see example [app_buckets_config_example.txt](./app_buckets_config_example.txt))

- `buckets_acl.csv`
     : a file containing a list of buckets and ACLs for those buckets in the format `"bucket";"read";"write";` (see example [buckets_example.csv](./buckets_acl_example.csv))
    
     :exclamation: ATTENTION! When naming buckets, follow the S3-API requirements:
     - bucket names must be no shorter than 3 and no longer than 63 characters;
     - bucket names can only contain lowercase letters, numbers and dashes (`-`);
     - Bucket names must start and end with a lowercase letter.

## Supported operations:

- Create/modify Amazon S3 bucket <sup id="a1">[1](#f1)</sup>:
     - Create/Change Permissions (**ACL** [(link to documentation)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#permissions)). Supported <sup id="a2">[2](#f2)</sup> types:
         - "FULL_CONTROL"
         - "READ"
         - "WRITE"

       :exclamation: ATTENTION! Currently (3/24/2022) **Bucket ACL** is not supported in Ceph RGW S3 [(documentation link)](https://docs.ceph.com/en/nautilus/radosgw/bucketpolicy/). 
       Quote:

       > We do not yet support setting policies on users, groups, or roles.

       In this regard, access rights are still managed through the **Bucket policy** methods.
      
     - Create/modify file lifecycle settings . Supported type <sup id="a3">[3](#f3)</sup>:
         - "Expiration actions"

- Creation/modification of a configuration file for further application on Amazon s3 storage.

## Assembly:

1. Install the golang package and its dependencies:

     ```
     #RHEL/CentOS/Fedora
     yum install -y golang

     #Debian/Ubuntu
     apt install -y golang
     ```

2. Enter the GIT project folder and run the command

     ```
     make
     ```

## Usage:

### Supported options:

| type | parameter | description |
| - | - | - |
| flag | `--help` | Display help on using the utility |
| flag | `--help-long` | Display extended help on using the utility, commands, their parameters and default values |
| flag | `--debug` | Enable debug mode |
| flag | `--version` | Display version and build information |
| command | `help [<command>]` | Display contextual help for the specified command |
| command | `app[<flags>]` | Create/update `ceph_config.yml` based on list of application buckets (`app_buckets_config.txt`) |
| command | `create [<flags>]` | Create `ceph_config.yml` based on data from server |
| command | `config [<flags>]` | Create/update buckets on the server based on data from `ceph_config.yml` |
| command | `parse-csv [<flags>]` | Create/update `ceph_config.yml` based on bucket list and ACL from CSV file (`buckets_acl.csv`) |
| command | `parse-yaml [<flags>]` | Create/update `buckets_acl.csv` based on server configuration from YAML file (`ceph_config.yml`)

#### Using the `--help-long` flag and the `help app` command as an example:

```
# ceph-buckets --help-long
usage: ceph-buckets [<flags>] <command> [<args> ...]

A command-line application for manage Ceph configuration of Amazon S3-compatible storage based on Ceph.

Flags:
   --help Show context-sensitive help (also try --help-long and --help-man).
   --debug Enable debug mode.
   --version Show application version.

Commands:
   help [<command>...]
     Show help.


   app [<flags>]
     Create/Update Ceph configuration YAML-file from application's TXT-file.

     --app-config="./app_buckets_config.txt"
       Application's TXT-file, contains buckets list.
     --ceph-config="./ceph_config.yml"
       Ceph configuration YAML-file.

   create [<flags>]
     Create/Update Ceph configuration YAML-file from server.

     --ceph-config="./ceph_config.yml"
                          Ceph configuration YAML-file.
     --credentials="./ceph_credentials.yml"
                          Ceph credentials YAML-file.
     --bucket-postfix="" Bucket postfix to be deleted from the bucket name.

   config [<flags>]
     Create/Update Ceph configuration on server from YAML-file.

     --ceph-config="./ceph_config.yml"
                          Ceph configuration YAML-file.
     --credentials="./ceph_credentials.yml"
                          Ceph credentials YAML-file.
     --bucket-postfix="" Bucket postfix to be added to the bucket name.

   parse-csv [<flags>]
     Parse CSV source file and write result to YAML file.

     --csv-file="./buckets_acl.csv"
                            Source CSV file, contains buckets ACL.
     --yaml-file="./ceph_config_from_csv.yml"
                            Destination YAML file.
     --fields-per-record=3 Number of fields per record
     --fields-sep=";" Fields separator for CSV fields

   parse-yaml [<flags>]
     Parse YAML source file and write result to CSV file.

     --yaml-file="./ceph_config.yml"
                       Source YAML file, contains buckets ACL.
     --csv-file="./buckets_from_yaml.csv"
                       Destination CSV file.
     --fields-sep=";" Fields separator for CSV fields


# ceph-buckets help app
usage: ceph-buckets app [<flags>]

Create/Update Ceph configuration YAML-file from application's TXT-file.

Flags:
   --help Show context-sensitive help (also try --help-long and --help-man).
   --debug Enable debug mode.
   --version Show application version.
   --app-config="./app_buckets_config.txt"
              Application's TXT-file, contains buckets list.
   --ceph-config="./ceph_config.yml"
              Ceph configuration YAML-file.
```

### Before use:
Populate the `ceph_credentials.yaml` file with the following:
* `endpoint_url:` IP/FQDN and port of the Ceph host, for example `endpoint_url: "127.0.0.1:8080"`
* `access_key:` The key of the user under which the connection will be made, for example `access_key: "445S7Y2GPP3R2PVPXH62"`
* `secret_key:` The secret part of the user key under which the connection will be made, for example `secret_key: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89"`
* `disable_ssl:` Whether to disable SSL (i.e. use HTTP protocol instead of HTTPS), e.g. `disable_ssl: True`

A complete configuration example can be found in the file [ceph_credentials_example.yml](./ceph_credentials_example.yml)

### Create/update config file from data from Ceph server:

```
ceph-buckets create --ceph-config ./ceph_config.yml --credentials ./ceph_credentials.yml --bucket-postfix="-rls"
```

### Create/update a configuration file from the list of application buckets:

```
ceph-buckets app --app-config ./app_buckets_config.txt --ceph-config ./ceph_config.yml
```

### Create/update buckets on the Ceph server from data from the configuration file:

```
ceph-buckets config --ceph-config ./ceph_config.yml --credentials ./ceph_credentials.yml --bucket-postfix="-rls"
```

### Create/update a YAML configuration file from a CSV file:
```
ceph-buckets parse-csv --csv-file ./buckets_acl.csv --yaml-file ./ceph_config_from_csv.yml
```

### Create a CSV file from a YAML configuration file:
```
ceph-buckets parse-yaml --yaml-file ./ceph_config.yml --csv-file ./buckets_acl_from_yaml.csv
```

----
### Notes:
<a id="f1">1</a>: Only operations for creating and modifying buckets are supported. Removing buckets is not supported for security reasons. [↩](#a1)

<a id="f2">2</a>: Types "READ_ACP" and "WRITE_ACP" are not supported to simplify the resulting configuration file. [↩](#a2)

<a id="f3">3</a>: The "Transition actions" type is not supported due to the lack of additional Storage Classes in Ceph. [↩](#a3)
