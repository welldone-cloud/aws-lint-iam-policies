#!/usr/bin/env python3

import argparse
import boto3
import botocore.config
import botocore.exceptions
import cachetools
import concurrent.futures
import datetime
import json
import os
import pkg_resources
import re
import string
import sys
import traceback

from enum import Enum
from policytypes import *


AWS_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12,}$")

AWS_REGION_NAME_PATTERN = re.compile(r"^([a-z]+-){2,}\d+$")

AWS_ROLE_NAME_PATTERN = re.compile(r"^[\w+=,.@-]{1,64}$")

BOTO_CLIENT_CONFIG = botocore.config.Config(retries={"total_max_attempts": 5, "mode": "standard"})

ERROR_MESSAGE_INVALID_PARAM_COMBINATION = "Invalid combination of parameters"

REGION = Enum("REGION", [("ALL", "all"), ("US_EAST_1", "us-east-1"), ("US_WEST_2", "us-west-2")])

SCOPE = Enum("SCOPE", ["ACCOUNT", "ORGANIZATION", "NONE"])

VALID_FILE_NAME_CHARACTERS = string.ascii_letters + string.digits + "_+=,.@-"

POLICY_TYPES_AND_REGIONS = {
    acm_private_ca_policies: REGION.ALL,
    api_gateway_rest_api_policies: REGION.ALL,
    app_mesh_mesh_policies: REGION.ALL,
    appsync_graphql_api_policies: REGION.ALL,
    backup_vault_policies: REGION.ALL,
    cloudtrail_channel_policies: REGION.ALL,
    cloudwatch_logs_delivery_destination_policies: REGION.ALL,
    cloudwatch_logs_destination_policies: REGION.ALL,
    cloudwatch_logs_resource_policies: REGION.ALL,
    codeartifact_domain_policies: REGION.ALL,
    codeartifact_repository_policies: REGION.ALL,
    codebuild_build_project_policies: REGION.ALL,
    codebuild_report_group_policies: REGION.ALL,
    datazone_domain_policies: REGION.ALL,
    dynamodb_stream_policies: REGION.ALL,
    dynamodb_table_policies: REGION.ALL,
    ec2_capacity_reservation_policies: REGION.ALL,
    ec2_dedicated_host_policies: REGION.ALL,
    ec2_image_builder_component_policies: REGION.ALL,
    ec2_placement_group_policies: REGION.ALL,
    ecr_private_registry_policies: REGION.ALL,
    ecr_private_repository_policies: REGION.ALL,
    ecr_public_repository_policies: REGION.US_EAST_1,
    efs_file_system_policies: REGION.ALL,
    elemental_mediastore_container_policies: REGION.ALL,
    eventbridge_event_bus_policies: REGION.ALL,
    eventbridge_schema_registry_policies: REGION.ALL,
    glacier_vault_lock_policies: REGION.ALL,
    glacier_vault_resource_policies: REGION.ALL,
    glue_data_catalog_policies: REGION.ALL,
    iam_group_inline_policies: REGION.US_EAST_1,
    iam_identity_center_permission_set_inline_policies: REGION.ALL,
    iam_managed_policies: REGION.US_EAST_1,
    iam_role_inline_policies: REGION.US_EAST_1,
    iam_role_trust_policies: REGION.US_EAST_1,
    iam_user_inline_policies: REGION.US_EAST_1,
    iot_core_policies: REGION.ALL,
    kinesis_data_stream_consumer_policies: REGION.ALL,
    kinesis_data_stream_policies: REGION.ALL,
    kms_key_policies: REGION.ALL,
    lambda_function_policies: REGION.ALL,
    lambda_layer_policies: REGION.ALL,
    lex_bot_alias_policies: REGION.ALL,
    lex_bot_policies: REGION.ALL,
    migration_hub_refactor_spaces_environment_policies: REGION.ALL,
    opensearch_domain_policies: REGION.ALL,
    organizations_delegation_policies: REGION.US_EAST_1,
    organizations_service_control_policies: REGION.US_EAST_1,
    ram_customer_managed_permissions: REGION.ALL,
    rds_aurora_cluster_policies: REGION.ALL,
    redshift_serverless_snapshot_policies: REGION.ALL,
    rekognition_custom_labels_project_policies: REGION.ALL,
    s3_access_point_policies: REGION.ALL,
    s3_bucket_policies: REGION.ALL,
    s3_directory_bucket_policies: REGION.ALL,
    s3_multi_region_access_point_policies: REGION.US_WEST_2,
    s3_object_lambda_access_point_policies: REGION.ALL,
    secrets_manager_secret_policies: REGION.ALL,
    security_hub_product_subscription_policies: REGION.ALL,
    ses_authorization_policies: REGION.ALL,
    sns_topic_policies: REGION.ALL,
    sqs_queue_policies: REGION.ALL,
    ssm_incident_manager_contact_policies: REGION.ALL,
    ssm_incident_manager_response_plan_policies: REGION.ALL,
    ssm_opscenter_opsitemgroup_resource_policies: REGION.ALL,
    ssm_parameter_store_parameter_policies: REGION.ALL,
    vpc_endpoint_policies: REGION.ALL,
}


@cachetools.cached(cache=cachetools.LRUCache(maxsize=64))
def get_access_analyzer_client(boto_session, region):
    return boto_session.client("accessanalyzer", config=BOTO_CLIENT_CONFIG, region_name=region)


@cachetools.cached(cache=dict())
def get_organizations_parents(organizations_client, child_id):
    all_parents = []
    parent = organizations_client.list_parents(ChildId=child_id)["Parents"][0]
    all_parents.append(parent["Id"])
    if parent["Type"] != "ROOT":
        all_parents.extend(get_organizations_parents(organizations_client, parent["Id"]))
    return all_parents


def get_scope():
    for pair in [(sys.argv[i], sys.argv[i + 1]) for i in range(0, len(sys.argv) - 1)]:
        if pair == ("--scope", SCOPE.ACCOUNT.name):
            return SCOPE.ACCOUNT
        elif pair == ("--scope", SCOPE.ORGANIZATION.name):
            return SCOPE.ORGANIZATION
    return SCOPE.NONE


def get_policy_type_names():
    return sorted([policy_type.__name__.split(".")[1] for policy_type in POLICY_TYPES_AND_REGIONS])


def parse_member_accounts_role(val):
    if val and get_scope() != SCOPE.ORGANIZATION:
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAM_COMBINATION)
    elif not val and get_scope() == SCOPE.ORGANIZATION:
        raise argparse.ArgumentTypeError("Parameter required when using scope {}".format(SCOPE.ORGANIZATION.name))
    if val and not AWS_ROLE_NAME_PATTERN.match(val):
        raise argparse.ArgumentTypeError("Invalid IAM role name")
    return val


def parse_policy_types(val):
    if get_scope() not in (SCOPE.ORGANIZATION, SCOPE.ACCOUNT):
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAM_COMBINATION)
    for policy_type_name in val.split(","):
        if policy_type_name not in get_policy_type_names():
            raise argparse.ArgumentTypeError("Unrecognized policy type name: {}".format(policy_type_name))
    return val.split(",")


def parse_regions(val):
    if get_scope() not in (SCOPE.ORGANIZATION, SCOPE.ACCOUNT):
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAM_COMBINATION)
    for region in val.split(","):
        if not AWS_REGION_NAME_PATTERN.match(region):
            raise argparse.ArgumentTypeError("Invalid region name format: {}".format(region))
    return val.split(",")


def parse_accounts(val):
    if get_scope() != SCOPE.ORGANIZATION:
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAM_COMBINATION)
    for account in val.split(","):
        if not AWS_ACCOUNT_ID_PATTERN.match(account):
            raise argparse.ArgumentTypeError("Invalid account ID format: {}".format(account))
    return val.split(",")


def parse_ous(val):
    if get_scope() != SCOPE.ORGANIZATION:
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAM_COMBINATION)
    for ou in val.split(","):
        if not ou.startswith("ou-"):
            raise argparse.ArgumentTypeError("Invalid OU ID format: {}".format(ou))
    return val.split(",")


def log_error(msg):
    result_collection["_metadata"]["errors"].append(msg.strip())
    print(msg)


def analyze_policy(
    account_id,
    region,
    boto_session,
    resource_type,
    resource_name,
    resource_arn,
    policy_document,
    policy_type,
    policy_resource_type=None,
    ignore_finding_issue_codes=[],
):
    # Create a policy dump file. Some AWS resources can have multiple policies attached or can use the same name,
    # while using different IDs in their ARN. An index is thus put at the end of the file name to handle collisions.
    index = 0
    while True:
        dump_file_name = "".join(
            char if char in VALID_FILE_NAME_CHARACTERS else "_"
            for char in "{}_{}_{}_{}_{}.json".format(account_id, region, resource_type, resource_name, index)
        )
        dump_file_name = re.sub("_+", "_", dump_file_name)
        dump_file_path = os.path.join(policy_dump_directory, dump_file_name)
        if not os.path.isfile(dump_file_path):
            break
        index += 1
    with open(dump_file_path, "w") as dump_file:
        json.dump(json.loads(policy_document), dump_file, indent=2)

    # Send policy through Access Analyzer validation
    access_analyzer_client = get_access_analyzer_client(boto_session, region)
    findings_paginator = access_analyzer_client.get_paginator("validate_policy")
    call_parameters = {
        "locale": "EN",
        "policyType": policy_type,
        "policyDocument": policy_document,
    }
    if policy_resource_type:
        call_parameters["validatePolicyResourceType"] = policy_resource_type

    # Add any Access Analyzer findings to the result collection
    for findings_page in findings_paginator.paginate(**call_parameters):
        for finding in findings_page["findings"]:
            # Skip if this finding issue code should not be reported
            if finding["issueCode"] in ignore_finding_issue_codes:
                continue

            result_summary = {
                "account_id": account_id,
                "region": region,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "resource_arn": resource_arn,
                "finding_type": finding["findingType"],
                "finding_issue_code": finding["issueCode"],
                "finding_description": finding["findingDetails"],
                "finding_link": finding["learnMoreLink"],
                "policy_dump_file_name": dump_file_name,
            }

            # Add to results_grouped_by_account_id
            try:
                result_collection["results_grouped_by_account_id"][account_id].append(result_summary)
            except KeyError:
                result_collection["results_grouped_by_account_id"][account_id] = [result_summary]

            # Add to results_grouped_by_finding_category
            finding_type = finding["findingType"]
            finding_issue_code = finding["issueCode"]
            try:
                result_collection["results_grouped_by_finding_category"][finding_type][finding_issue_code].append(
                    result_summary
                )
            except KeyError:
                if finding_type not in result_collection["results_grouped_by_finding_category"]:
                    result_collection["results_grouped_by_finding_category"][finding_type] = {}
                result_collection["results_grouped_by_finding_category"][finding_type][finding_issue_code] = [
                    result_summary
                ]


def analyze_account(account_id, boto_session):
    # Get all regions enabled in the account
    ec2_client = boto_session.client("ec2", config=BOTO_CLIENT_CONFIG, region_name=REGION.US_EAST_1.value)
    try:
        describe_regions_response = ec2_client.describe_regions(AllRegions=False)
    except botocore.exceptions.ClientError:
        log_error("Error for account ID {}: cannot fetch enabled regions".format(account_id))
        return
    enabled_regions = sorted([region["RegionName"] for region in describe_regions_response["Regions"]])

    # Iterate all supported policy types and enabled regions and trigger analysis for applicable combinations that
    # are also allowed by include and exclude arguments
    print("Analyzing account ID {}".format(account_id))
    futures = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for policy_type in POLICY_TYPES_AND_REGIONS:
            policy_type_name = policy_type.__name__.split(".")[1]
            if policy_type_name in args.exclude_policy_types:
                continue
            if args.include_policy_types and policy_type_name not in args.include_policy_types:
                continue

            for region in enabled_regions:
                if POLICY_TYPES_AND_REGIONS[policy_type].value not in (REGION.ALL.value, region):
                    continue
                if region in args.exclude_regions:
                    continue
                if args.include_regions and region not in args.include_regions:
                    continue
                future_params = {
                    "account_id": account_id,
                    "region": region,
                    "boto_session": boto_session,
                    "boto_config": BOTO_CLIENT_CONFIG,
                    "policy_analysis_function": analyze_policy,
                }
                future = executor.submit(policy_type.analyze, **future_params)
                future_params["policy_type_name"] = policy_type_name
                futures[future] = future_params

        # Show status and process any errors that occurred
        futures_completed = 0
        for future in concurrent.futures.as_completed(futures.keys()):
            futures_completed += 1
            print("{}%".format(int(futures_completed * 100 / len(futures))), end="\r")

            try:
                future.result()
            except botocore.exceptions.EndpointConnectionError:
                # Ignore errors when an AWS service is not available in a certain region
                pass
            except botocore.exceptions.ClientError as ex:
                # Log expected errors such as a lack of permissions, regions/services denied by SCPs, etc.
                log_error(
                    "Error for account ID {}, region {}, policy type {}: {} ({})".format(
                        account_id,
                        futures[future]["region"],
                        futures[future]["policy_type_name"],
                        ex.response["Error"]["Code"],
                        ex.response["Error"]["Message"],
                    )
                )
            except Exception as ex:
                # Log all remaining and unexpected errors and print stack trace details
                msg = "Uncaught exception for account ID {}, region {}, policy type {}: {}. "
                msg += "Please report this as an issue along with the stack trace information."
                log_error(
                    msg.format(
                        account_id,
                        futures[future]["region"],
                        futures[future]["policy_type_name"],
                        ex.__class__.__name__,
                    )
                )
                print(traceback.format_exc())


def analyze_organization(boto_session):
    # Iterate all accounts of the Organization
    accounts_paginator = organizations_client.get_paginator("list_accounts")
    for accounts_page in accounts_paginator.paginate():
        for account in accounts_page["Accounts"]:
            account_id = account["Id"]

            # Skip accounts that should not be targeted because of include or exclude arguments
            if account_id in args.exclude_accounts:
                continue
            if args.include_accounts and account_id not in args.include_accounts:
                continue
            if args.exclude_ous and any(
                ou in args.exclude_ous for ou in get_organizations_parents(organizations_client, account_id)
            ):
                continue
            if args.include_ous and all(
                ou not in args.include_ous for ou in get_organizations_parents(organizations_client, account_id)
            ):
                continue

            # Skip accounts that are not active
            if account["Status"] != "ACTIVE":
                log_error("Error for account ID {}: account status is not active".format(account_id))
                continue

            # Assume a role in the target account for analysis, except for when we are currently analyzing the
            # management account itself
            if account_id == organization_management_account_id:
                analyze_account(account_id, boto_session)
            else:
                try:
                    assume_role_response = sts_client.assume_role(
                        RoleArn="arn:aws:iam::{}:role/{}".format(account_id, args.member_accounts_role),
                        RoleSessionName="aws-lint-iam-policies",
                    )
                except botocore.exceptions.ClientError:
                    log_error(
                        "Error for account ID {}: cannot assume specified member accounts role".format(account_id)
                    )
                    continue
                account_session = boto3.Session(
                    aws_access_key_id=assume_role_response["Credentials"]["AccessKeyId"],
                    aws_secret_access_key=assume_role_response["Credentials"]["SecretAccessKey"],
                    aws_session_token=assume_role_response["Credentials"]["SessionToken"],
                )
                analyze_account(account_id, account_session)


if __name__ == "__main__":
    # Check runtime environment
    if sys.version_info[0] < 3:
        print("Python version 3 required")
        sys.exit(1)
    with open("requirements.txt", "r") as requirements_file:
        try:
            for package in requirements_file.read().splitlines():
                pkg_resources.require(package)
        except (pkg_resources.ResolutionError, pkg_resources.ExtractionError):
            print("Unfulfilled requirement: {}".format(package))
            sys.exit(1)

    # Parse arguments
    parser = argparse.ArgumentParser()
    mutually_exclusive_args = parser.add_mutually_exclusive_group(required=True)
    mutually_exclusive_args.add_argument(
        "--list-policy-types",
        action="store_true",
        help="list all supported policy types and exit",
    )
    mutually_exclusive_args.add_argument(
        "--scope",
        choices=[SCOPE.ACCOUNT.name, SCOPE.ORGANIZATION.name],
        help="target either an individual account or all accounts of an AWS Organization",
    )
    parser.add_argument(
        "--member-accounts-role",
        default="",
        type=parse_member_accounts_role,
        help="IAM role name present in member accounts that can be assumed from the Organizations management account",
    )
    parser.add_argument(
        "--exclude-policy-types",
        default=[],
        type=parse_policy_types,
        help="do not target the specified comma-separated list of policy types",
    )
    parser.add_argument(
        "--include-policy-types",
        default=[],
        type=parse_policy_types,
        help="only target the specified comma-separated list of policy types",
    )
    parser.add_argument(
        "--exclude-regions",
        default=[],
        type=parse_regions,
        help="do not target the specified comma-separated list of region names",
    )
    parser.add_argument(
        "--include-regions",
        default=[],
        type=parse_regions,
        help="only target the specified comma-separated list of region names",
    )
    parser.add_argument(
        "--exclude-accounts",
        default=[],
        type=parse_accounts,
        help="do not target the specified comma-separated list of account IDs",
    )
    parser.add_argument(
        "--include-accounts",
        default=[],
        type=parse_accounts,
        help="only target the specified comma-separated list of account IDs",
    )
    parser.add_argument(
        "--exclude-ous",
        default=[],
        type=parse_ous,
        help="do not target the specified comma-separated list of Organizations OU IDs",
    )
    parser.add_argument(
        "--include-ous",
        default=[],
        type=parse_ous,
        help="only target the specified comma-separated list of Organizations OU IDs",
    )
    parser.add_argument(
        "--profile",
        help="named AWS profile to use",
    )
    args = parser.parse_args()
    args.scope = get_scope()

    # List policy types and exit, if configured
    if args.list_policy_types:
        for policy_type_name in get_policy_type_names():
            print(policy_type_name)
        sys.exit(0)

    # Test for valid credentials
    try:
        boto_session = boto3.Session(profile_name=args.profile)
    except botocore.exceptions.ProfileNotFound as ex:
        print("Error: {}".format(ex))
        sys.exit(1)
    sts_client = boto_session.client(
        "sts",
        config=BOTO_CLIENT_CONFIG,
        region_name=REGION.US_EAST_1.value,
        endpoint_url="https://sts.{}.amazonaws.com".format(REGION.US_EAST_1.value),
    )
    try:
        get_caller_identity_response = sts_client.get_caller_identity()
        account_id = get_caller_identity_response["Account"]
    except:
        print("No or invalid AWS credentials configured")
        sys.exit(1)

    # Prepare result collection JSON structure
    run_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    result_collection = {
        "_metadata": {
            "invocation": " ".join(sys.argv),
            "principal": get_caller_identity_response["Arn"],
            "run_timestamp": run_timestamp,
            "scope": args.scope.name,
            "errors": [],
        },
        "results_grouped_by_account_id": {},
        "results_grouped_by_finding_category": {},
    }

    # Prepare results directory
    results_directory = os.path.join(os.path.relpath(os.path.dirname(__file__) or "."), "results")
    try:
        os.mkdir(results_directory)
    except FileExistsError:
        pass
    policy_dump_directory = os.path.join(results_directory, "policy_dump_{}".format(run_timestamp))
    os.mkdir(policy_dump_directory)

    # Handle ACCOUNT scope
    if args.scope == SCOPE.ACCOUNT:
        result_collection["_metadata"]["account_id"] = account_id
        analyze_account(account_id, boto_session)

    # Handle ORGANIZATION scope
    elif args.scope == SCOPE.ORGANIZATION:
        organizations_client = boto_session.client(
            "organizations", config=BOTO_CLIENT_CONFIG, region_name=REGION.US_EAST_1.value
        )
        try:
            # Collect information about the Organization
            describe_organization_response = organizations_client.describe_organization()
            organization_id = describe_organization_response["Organization"]["Id"]
            organization_management_account_id = describe_organization_response["Organization"]["MasterAccountId"]
            result_collection["_metadata"]["organization_id"] = organization_id
            result_collection["_metadata"]["organization_management_account_id"] = organization_management_account_id

            # Confirm we are running with credentials of the management account
            if organization_management_account_id != account_id:
                print(
                    "Need to run with credentials of the Organizations management account when using scope {}".format(
                        SCOPE.ORGANIZATION.name
                    )
                )
                sys.exit(1)

            print(
                "Analyzing organization ID {} under management account ID {}".format(
                    organization_id,
                    organization_management_account_id,
                )
            )
            analyze_organization(boto_session)

        except organizations_client.exceptions.AccessDeniedException:
            print("Insufficient permissions to communicate with the AWS Organizations service")
            sys.exit(1)
        except organizations_client.exceptions.AWSOrganizationsNotInUseException:
            print("AWS Organizations is not configured for this account")
            sys.exit(1)

    # Write result file
    result_file = os.path.join(results_directory, "policy_linting_results_{}.json".format(run_timestamp))
    with open(result_file, "w") as out_file:
        json.dump(result_collection, out_file, indent=2)

    print("Result file written to {}".format(result_file))
    print("Policy dump written to {}".format(policy_dump_directory))
