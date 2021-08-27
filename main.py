#! /usr/bin/env python3

import argparse
import logging
import os
import sys
import json
import time
import yaml

import botocore
import boto3

script_dir = os.path.dirname(__file__)


def timing(f):
    # This function used as decorator for print another functions elapsed time
    def perf(*args, **kwargs):
        time1 = time.time()
        function_result = f(*args, **kwargs)
        time2 = time.time()
        logging.debug("{:s} function took {:.3f} ms".format(f.__name__, (time2 - time1) * 1000.0))
        return function_result

    return perf


@timing
def parse_args():
    parser = argparse.ArgumentParser(description="Create/Update Ceph buckets")

    subparsers = parser.add_subparsers()

    parser_app = subparsers.add_parser('app', help="Apply application config to repo config")
    parser_app.add_argument('-a', '--app-config', help="Current application buckets config file", dest='app_config',
                            default=None, required=True)
    parser_app.add_argument('-r', '--ceph-config', help="Repo YAML file for Ceph buckets config", dest='ceph_config',
                            default=None)
    parser_app.set_defaults(func=apply_app_config)

    parser_ceph = subparsers.add_parser('ceph', help="Apply repo config to Ceph S3-compatible storage")
    parser_ceph.add_argument('-r', '--ceph-config', help="Target YAML file for Ceph buckets config", dest='ceph_config',
                             default=None)
    parser_ceph.add_argument('-c', '--credentials', help="Ceph credentials JSON file", dest='ceph_credentials',
                             default=None)
    parser_ceph.set_defaults(func=apply_ceph_config)

    parser_create = subparsers.add_parser('create', help="Create repo config from Ceph S3-compatible storage")
    parser_create.add_argument('-r', '--ceph-config', help="Repo YAML file for Ceph buckets config",
                               dest='ceph_config', default=None, required=True)
    parser_create.add_argument('-c', '--credentials', help="Ceph credentials JSON file", dest='ceph_credentials',
                               default=None)
    parser_create.set_defaults(func=create_repo_config)
    return parser


@timing
def load_ceph_repo_config(args):
    # If path argument present than try to load config from file
    if args.ceph_config:
        if os.path.exists(os.path.abspath(args.ceph_config)):
            ceph_config_path = os.path.abspath(args.ceph_config)
        else:
            logging.critical("Config file '{:s}' not found!".format(args.ceph_config))
            return 1
    # if path argument skipped than try to load from default path
    else:
        ceph_config_path = os.path.abspath(os.path.join(script_dir, "ceph_config.yml"))

    logging.info("Load Ceph buckets from file '{:s}'".format(ceph_config_path))
    with open(ceph_config_path, 'r') as f:
        repo_config = yaml.full_load(f)
    return repo_config, ceph_config_path


@timing
def load_ceph_bucket_template():
    template_path = os.path.abspath(os.path.join(script_dir, "ceph_bucket_template.json"))
    logging.info("Load Ceph bucket template for new buckets from file '{:s}'".format(template_path))
    with open(template_path, 'r') as f:
        bucket_template = json.loads(f.read())
    return bucket_template


@timing
def verify_bucket_name(bucket_name):
    import re
    regex = re.compile("^[a-z][a-z0-9\-]{2,61}[a-z]$")
    if regex.match(bucket_name):
        logging.debug("Bucket name '{:s}' matched naming rules".format(bucket_name))
        return True
    else:
        logging.warning("""
        Bucket name '{:s}' not match naming rules and will be skipped.
        The following rules apply for naming S3 buckets:
          * Bucket names must be between 3 and 63 characters long.
          * Bucket names can consist only of lowercase letters, numbers, and hyphens (-).
          * Bucket names must begin and end with a lowercase letter.
        """.format(bucket_name))
        return False


@timing
def update_repo_config(ceph_config, app_buckets_list=None, bucket_template=None):
    # Create copy of Ceph-config for comparison early
    _old_ceph_config = ceph_config.copy()
    if app_buckets_list:
        logging.info("Compare application's buckets with ceph buckets")
        for app_bucket in app_buckets_list:
            if app_bucket in ceph_config.keys() or not verify_bucket_name(app_bucket):
                continue
            logging.debug("Add new bucket '{:s}' to ceph buckets".format(app_bucket))
            ceph_config.update({app_bucket: bucket_template.copy()})
    if _old_ceph_config != ceph_config:
        return ceph_config
    else:
        return None


@timing
def check_ceph_config(ceph_config, repo_config, bucket_template):
    ceph_config_changed = False
    for repo_bucket_name, repo_bucket_dict in repo_config.items():
        if repo_bucket_name not in ceph_config.keys():
            ceph_config.update({repo_bucket_name: bucket_template.copy()})
            ceph_config_changed = True
        if repo_bucket_dict["versioning"] != ceph_config[repo_bucket_name]["versioning"]:
            if repo_bucket_dict["versioning"] == "Enabled":
                ceph_config[repo_bucket_name]["versioning"] = "Enabling"
            elif repo_bucket_dict["versioning"] == "Disabled" or repo_bucket_dict["versioning"] == "Suspended":
                ceph_config[repo_bucket_name]["versioning"] = "Disabling"
            ceph_config_changed = True
        if repo_bucket_dict["acl"] != ceph_config[repo_bucket_name]["acl"]:
            bucket_owner = ceph_config[repo_bucket_name]["acl"]["owner"]
            ceph_config[repo_bucket_name]["acl"] = repo_bucket_dict["acl"]
            ceph_config[repo_bucket_name]["acl"].update({"owner": bucket_owner})
            ceph_config[repo_bucket_name]["acl_type"] = "new"
            ceph_config_changed = True
        else:
            ceph_config[repo_bucket_name]["acl_type"] = "present"
    if ceph_config_changed:
        return ceph_config
    else:
        return None


@timing
def load_ceph_server_config(args):
    # If path argument present than try to load credentials from file
    if args.ceph_credentials:
        if os.path.exists(os.path.abspath(args.ceph_credentials)):
            credentials_path = os.path.abspath(args.ceph_credentials)
        else:
            logging.critical("Credentials file '{:s}' not found!".format(args.ceph_credentials))
            sys.exit(1)
    # if path argument skipped than try to load credentials from default path
    else:
        credentials_path = os.path.abspath(os.path.join(script_dir, "ceph_credentials.json"))

    # Load Ceph S3-compatible storage credentials from JSON-file
    with open(credentials_path, 'r') as f:
        ceph_credentials = json.loads(f.read())

    # Connect to Ceph S3-compatible storage
    logging.debug("Connect to Ceph S3-compatible storage")
    s3api = boto3.client('s3',
                         endpoint_url=ceph_credentials['endpoint_url'],
                         aws_access_key_id=ceph_credentials['access_key'],
                         aws_secret_access_key=ceph_credentials['secret_key'],
                         use_ssl=False,
                         verify=False)
    # Get Ceph S3-compatible buckets configuration from server
    logging.info("Get Ceph S3-compatible buckets configuration from "
                 "server '{:s}'".format(ceph_credentials['endpoint_url']))
    response = s3api.list_buckets()
    ceph_config_dict = dict()
    # Create Ceph buckets dict from response
    for ceph_bucket in response["Buckets"]:
        bucket_name = ceph_bucket["Name"]
        # Get versioning state for each bucket
        versioning = s3api.get_bucket_versioning(Bucket=ceph_bucket["Name"])
        if "Status" in versioning.keys():
            versioning_status = versioning["Status"]
        else:
            versioning_status = 'Disabled'
        # Get bucket ACLs
        acl = s3api.get_bucket_acl(Bucket=bucket_name)
        acl_dict = dict()
        full_control_list = []
        read_list = []
        write_list = []
        for grant in acl["Grants"]:
            if grant["Permission"] == "FULL_CONTROL":
                full_control_list.append(grant["Grantee"]["ID"])
            elif grant["Permission"] == "READ":
                read_list.append(grant["Grantee"]["ID"])
            elif grant["Permission"] == "WRITE":
                write_list.append(grant["Grantee"]["ID"])
            else:
                logging.info("Permission '{:s}' unsupported and will be skipped".format(grant["Permission"]))
        acl_dict.update({
            "owner": {
                "display_name": acl["Owner"]["DisplayName"],
                "id": acl["Owner"]["ID"]
            },
            "grants": {
                "full_control": full_control_list,
                "read": read_list,
                "write": write_list,
            },
        })
        bucket_dict = {
            bucket_name: {
                "bucket_type": "present",
                "versioning": versioning_status,
                "acl": acl_dict,
                "acl_type": "present",
            }
        }
        ceph_config_dict.update(bucket_dict)

    return ceph_config_dict, ceph_credentials, s3api


@timing
def apply_app_config(args):
    # Try to load config from file
    if os.path.exists(os.path.abspath(args.app_config)):
        app_config_path = os.path.abspath(args.app_config)
    else:
        logging.critical("Config file '{:s}' not found!".format(args.app_config))
        return 1

    # Load Ceph buckets YAML config file
    repo_config, ceph_config_path = load_ceph_repo_config(args)

    # Load Ceph bucket template for new buckets
    bucket_template = load_ceph_bucket_template()

    # Load application buckets list
    logging.info("Load application buckets list from file '{:s}'".format(app_config_path))
    with open(app_config_path, 'r') as f:
        app_buckets_list = f.readlines()
        # Strip whitespaces like '\n'
        app_buckets_list = [x.strip() for x in app_buckets_list]
    logging.info("Compare application's buckets list with repository buckets list")
    updated_repo_config = update_repo_config(repo_config.copy(), app_buckets_list, bucket_template)
    # If config was changed than update Ceph buckets YAML config file
    if updated_repo_config:
        logging.info("Update Ceph buckets file '{:s}'".format(ceph_config_path))
        # Write new buckets config to repo file
        with open(ceph_config_path, 'w') as f:
            yaml.safe_dump(updated_repo_config, f)
    # If config wasn't changed than just exit
    else:
        logging.info("New buckets not found. Ceph buckets file '{:s}' not changed".format(ceph_config_path))
    return 0


@timing
def create_repo_config(args):
    # Load Ceph buckets from server
    ceph_config_dict, ceph_credentials, ceph_session = load_ceph_server_config(args)
    ceph_config_path = os.path.abspath(args.ceph_config)
    # Write Ceph buckets to repo
    with open(ceph_config_path, 'w') as f:
        yaml.safe_dump(ceph_config_dict, f)
    return 0


@timing
def apply_ceph_config(args):
    # Load Ceph buckets from server
    ceph_config_dict, ceph_credentials, ceph_session = load_ceph_server_config(args)

    # Load Ceph buckets YAML config file
    repo_config, ceph_config_path = load_ceph_repo_config(args)

    # Load Ceph bucket template for new buckets
    bucket_template = load_ceph_bucket_template()

    # Compare S3 buckets configuration between Ceph server and YAML
    logging.info("Compare S3 buckets configuration between Ceph server '{:s}' and YAML-file '{:s}'".format(
        ceph_credentials['endpoint_url'], ceph_config_path))
    ceph_config_updated = check_ceph_config(ceph_config_dict.copy(), repo_config, bucket_template)

    # If new/changed buckets not found in YAML than exit
    if not ceph_config_updated:
        logging.info("No new/changed buckets/ACLs found in repo config.")
        return 0

    need_update = False
    # If new/changed buckets found in YAML than create/update buckets in Ceph
    for bucket_name, bucket_conf in ceph_config_updated.items():
        if bucket_conf["bucket_type"] == "new":
            need_update = True
            logging.info("Create bucket '{:s}' on Ceph".format(bucket_name))
            ceph_session.create_bucket(Bucket=bucket_name)
        if bucket_conf["versioning"] == "Enabling":
            logging.info("Enable versioning for bucket '{:s}' in Ceph".format(bucket_name))
            ceph_session.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={
                    'MFADelete': 'Disabled',
                    'Status': 'Enabled'
                },
            )
        if bucket_conf["versioning"] == "Disabling":
            logging.info("Disable versioning for bucket '{:s}' in Ceph".format(bucket_name))
            ceph_session.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={
                    'Status': 'Suspended'
                },
            )
    
    if need_update:
        # Update Ceph config after create bucket
        logging.info("Update Ceph config after create bucket")
        apply_ceph_config(args)
    
    for bucket_name, bucket_conf in ceph_config_updated.items():
        if bucket_conf["acl_type"] == "new" and not need_update:
            acl_dict = {
                "Owner": {
                    "DisplayName": bucket_conf["acl"]["owner"]["display_name"],
                    "ID": bucket_conf["acl"]["owner"]["id"]
                },
                "Grants": []
            }
            logging.info("Update ACLs for bucket '{:s}' in Ceph".format(bucket_name))
            for acl_type in bucket_conf["acl"]["grants"].keys():
                if acl_type == "full_control":
                    grant_permission = "FULL_CONTROL"
                elif acl_type == "read":
                    grant_permission = "READ"
                elif acl_type == "write":
                    grant_permission = "WRITE"
                else:
                    logging.warning("Permission '{:s}' unsupported and will be skipped".format(acl_type))
                    continue
                
                for acl_user in bucket_conf["acl"]["grants"][acl_type]:
                    logging.info("Set '{:s}' permissions for user '{:s}' on bucket '{:s}'".format(acl_type, acl_user, bucket_name))
                    grant_dict = {
                        'Grantee': {
                            'ID': acl_user,
                            'Type': 'CanonicalUser',
                        },
                        'Permission': grant_permission
                    }
                    acl_dict["Grants"].append(grant_dict)
                    logging.debug("ACL:\n{:s}".format(json.dumps(acl_dict, indent=4)))
                    try:
                        ceph_session.put_bucket_acl(
                            AccessControlPolicy=acl_dict,
                            Bucket=bucket_name
                        )
                    except botocore.exceptions.ClientError:
                        logging.exception("One or more users doesn't exists! Please, check ACL, create users and try again:\n{:s}".format(json.dumps(acl_dict, indent=4)))
                        need_update = True
    if not need_update:
        logging.info("Update repository config '{:s}'".format(ceph_config_path))
        create_repo_config(args)
    return 0


@timing
def main():
    logging.basicConfig(format=u'[%(asctime)s][%(levelname)-7s] [%(funcName)s.%(lineno)d]: %(message)s',
                        level=logging.INFO, stream=sys.stderr)
    
    parser = parse_args()
    args = parser.parse_args()

    # Call default function for each sub-parser and return exit code
    try:
        return args.func(args)
    except AttributeError as ex:
        logging.debug(dir(args))
        logging.exception(ex, parser.print_help())
        return 1


if __name__ == '__main__':
    sys.exit(main())
