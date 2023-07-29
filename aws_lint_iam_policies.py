import argparse
import boto3
import botocore.config
import botocore.exceptions
import cachetools
import datetime
import json
import re
import sys

from enum import Enum
from policytypes import (
    backup_vault_policies,
    ecr_private_registry_policies,
    ecr_private_repository_policies,
    ecr_public_repository_policies,
    efs_file_system_policies,
    eventbridge_event_bus_policies,
    eventbridge_schema_registry_policies,
    glue_data_catalog_policies,
    iam_group_inline_policies,
    iam_managed_policies,
    iam_role_inline_policies,
    iam_role_trust_policies,
    iam_user_inline_policies,
    kms_key_policies,
    lambda_function_policies,
    lambda_layer_policies,
    organizations_service_control_policies,
    s3_access_point_policies,
    s3_bucket_policies,
    s3_multi_region_access_point_policies,
    s3_object_lambda_access_point_policies,
    secrets_manager_secret_policies,
    sns_topic_policies,
    sqs_queue_policies,
    vpc_endpoint_policies,
)


AWS_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12,}$")

AWS_REGION_NAME_PATTERN = re.compile(r"^([a-z]+-){2,}\d+$")

AWS_ROLE_NAME_PATTERN = re.compile(r"^[\w+=,.@-]{1,64}$")

ALL_REGIONS = "ALL"

DEFAULT_REGION = "us-east-1"

BOTO_CONFIG = botocore.config.Config(retries={"total_max_attempts": 5, "mode": "standard"})

POLICY_TYPES_AND_REGIONS = {
    backup_vault_policies: ALL_REGIONS,
    ecr_private_registry_policies: ALL_REGIONS,
    ecr_private_repository_policies: ALL_REGIONS,
    ecr_public_repository_policies: DEFAULT_REGION,
    efs_file_system_policies: ALL_REGIONS,
    eventbridge_event_bus_policies: ALL_REGIONS,
    eventbridge_schema_registry_policies: ALL_REGIONS,
    glue_data_catalog_policies: ALL_REGIONS,
    iam_group_inline_policies: DEFAULT_REGION,
    iam_managed_policies: DEFAULT_REGION,
    iam_role_inline_policies: DEFAULT_REGION,
    iam_role_trust_policies: DEFAULT_REGION,
    iam_user_inline_policies: DEFAULT_REGION,
    kms_key_policies: ALL_REGIONS,
    lambda_function_policies: ALL_REGIONS,
    lambda_layer_policies: ALL_REGIONS,
    organizations_service_control_policies: DEFAULT_REGION,
    s3_access_point_policies: ALL_REGIONS,
    s3_bucket_policies: ALL_REGIONS,
    s3_multi_region_access_point_policies: "us-west-2",
    s3_object_lambda_access_point_policies: ALL_REGIONS,
    secrets_manager_secret_policies: ALL_REGIONS,
    sns_topic_policies: ALL_REGIONS,
    sqs_queue_policies: ALL_REGIONS,
    vpc_endpoint_policies: ALL_REGIONS,
}

SCOPE = Enum("SCOPE", ["ACCOUNT", "ORGANIZATION"])


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


def parse_member_accounts_role(val):
    if get_scope() == SCOPE.ACCOUNT:
        raise argparse.ArgumentTypeError("Invalid option for scope {}".format(SCOPE.ACCOUNT.name))
    if not AWS_ROLE_NAME_PATTERN.match(val):
        raise argparse.ArgumentTypeError("Invalid IAM role name")
    return val


def parse_exclude_accounts(val):
    if get_scope() == SCOPE.ACCOUNT:
        raise argparse.ArgumentTypeError("Invalid option for scope {}".format(SCOPE.ACCOUNT.name))
    for account in val.split(","):
        if account and not AWS_ACCOUNT_ID_PATTERN.match(account):
            raise argparse.ArgumentTypeError("Invalid account ID format")
    return val


def parse_exclude_regions(val):
    for region in val.split(","):
        if region and not AWS_REGION_NAME_PATTERN.match(region):
            raise argparse.ArgumentTypeError("Invalid region name format")
    return val


def parse_exclude_ous(val):
    if get_scope() == SCOPE.ACCOUNT:
        raise argparse.ArgumentTypeError("Invalid option for scope {}".format(SCOPE.ACCOUNT.name))
    for ou in val.split(","):
        if ou and not ou.startswith("ou-"):
            raise argparse.ArgumentTypeError("Invalid OU ID format")
    return val


def parse_exclude_policy_types(val):
    for exclude_type in val.split(","):
        if exclude_type and exclude_type not in [
            policy_type.__name__.split(".")[1] for policy_type in POLICY_TYPES_AND_REGIONS
        ]:
            raise argparse.ArgumentTypeError("Unrecognized policy type name")
    return val


def log_error(msg):
    result_collection["_metadata"]["errors"].append(msg.strip())
    print(msg)


def add_result_to_result_collection(result):
    # Add to results_grouped_by_account_id
    account_id = result["account_id"]
    if account_id not in result_collection["results_grouped_by_account_id"]:
        result_collection["results_grouped_by_account_id"][account_id] = []
    result_collection["results_grouped_by_account_id"][account_id].append(result)

    # Add to results_grouped_by_finding_category
    finding_type = result["finding_type"]
    finding_issue_code = result["finding_issue_code"]
    if finding_type not in result_collection["results_grouped_by_finding_category"]:
        result_collection["results_grouped_by_finding_category"][finding_type] = {}
    if finding_issue_code not in result_collection["results_grouped_by_finding_category"][finding_type]:
        result_collection["results_grouped_by_finding_category"][finding_type][finding_issue_code] = []
    result_collection["results_grouped_by_finding_category"][finding_type][finding_issue_code].append(result)


def validate_policy(
    account_id,
    region,
    boto_session,
    resource_type,
    resource_name,
    resource_arn,
    policy_document,
    policy_type,
    policy_resource_type=None,
):
    # Send policy through Access Analyzer validation
    access_analyzer_client = boto_session.client("accessanalyzer", config=BOTO_CONFIG, region_name=region)
    response_paginator = access_analyzer_client.get_paginator("validate_policy")
    call_parameters = {
        "locale": "EN",
        "policyType": policy_type,
        "policyDocument": policy_document,
    }
    if policy_resource_type:
        call_parameters["validatePolicyResourceType"] = policy_resource_type

    # Add any Access Analyzer findings to the result collection
    for response in response_paginator.paginate(**call_parameters):
        for finding in response["findings"]:
            add_result_to_result_collection(
                {
                    "account_id": account_id,
                    "region": region,
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "resource_arn": resource_arn,
                    "policy_type": policy_type,
                    "finding_type": finding["findingType"],
                    "finding_issue_code": finding["issueCode"],
                    "finding_description": finding["findingDetails"],
                    "finding_link": finding["learnMoreLink"],
                }
            )


def analyze_account(account_id, boto_session):
    # Get all regions enabled in the account and not excluded by configuration
    ec2_client = boto_session.client("ec2", config=BOTO_CONFIG, region_name=DEFAULT_REGION)
    try:
        ec2_response = ec2_client.describe_regions(AllRegions=False)
    except botocore.exceptions.ClientError:
        log_error("Error for account ID {}: cannot fetch enabled regions".format(account_id))
        return
    target_regions = sorted(
        [region["RegionName"] for region in ec2_response["Regions"] if region["RegionName"] not in exclude_regions]
    )

    # Iterate regions and trigger analysis of applicable policy types
    print("Analyzing account ID {}".format(account_id))
    for region in target_regions:
        print("{}{}".format(" " * 2, region))
        for policy_type in POLICY_TYPES_AND_REGIONS:
            policy_type_name = policy_type.__name__.split(".")[1]
            policy_type_applies_to_region = POLICY_TYPES_AND_REGIONS[policy_type]
            if policy_type_name not in exclude_policy_types and policy_type_applies_to_region in (ALL_REGIONS, region):
                try:
                    policy_type.analyze(
                        account_id=account_id,
                        region=region,
                        boto_session=boto_session,
                        boto_config=BOTO_CONFIG,
                        validation_function=validate_policy,
                    )
                except botocore.exceptions.ClientError as ex:
                    log_error(
                        "{}Error for account ID {}, region {}, policy type {}: {}".format(
                            " " * 4, account_id, region, policy_type_name, ex.response["Error"]["Code"]
                        )
                    )


def analyze_organization():
    print(
        "Analyzing organization ID {} under management account ID {}".format(
            organization_id, organization_management_account_id
        )
    )

    # Iterate all accounts of the Organization
    accounts_paginator = organizations_client.get_paginator("list_accounts")
    for list_accounts_response in accounts_paginator.paginate():
        for account in list_accounts_response["Accounts"]:
            account_id = account["Id"]

            # Skip account when configured to do so or when it is not active
            if account_id in exclude_accounts:
                continue
            elif exclude_ous and any(
                ou in exclude_ous for ou in get_organizations_parents(organizations_client, account_id)
            ):
                continue
            elif account["Status"] != "ACTIVE":
                log_error("Error for account ID {}: account status is not active".format(account_id))
                continue

            # Assume a role in the target account, if required
            if account_id == organization_management_account_id:
                account_session = boto_session
            else:
                try:
                    sts_response = sts_client.assume_role(
                        RoleArn="arn:aws:iam::{}:role/{}".format(account_id, member_accounts_role),
                        RoleSessionName="aws-lint-iam-policies",
                    )
                except botocore.exceptions.ClientError:
                    log_error(
                        "Error for account ID {}: cannot assume specified member accounts role".format(account_id)
                    )
                    continue
                account_session = boto3.session.Session(
                    aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
                    aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
                    aws_session_token=sts_response["Credentials"]["SessionToken"],
                )

            analyze_account(account_id, account_session)


if __name__ == "__main__":
    # Check runtime environment
    if sys.version_info[0] < 3:
        print("Python version 3 required")
        sys.exit(1)

    # Define arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scope",
        required=True,
        choices=[SCOPE.ACCOUNT.name, SCOPE.ORGANIZATION.name],
        nargs=1,
        help="target either an individual account or all accounts of an AWS Organization",
    )
    parser.add_argument(
        "--member-accounts-role",
        required=True if get_scope() == SCOPE.ORGANIZATION else False,
        nargs=1,
        type=parse_member_accounts_role,
        help="IAM role name present in member accounts that can be assumed from the Organizations management account",
    )
    parser.add_argument(
        "--exclude-accounts",
        required=False,
        nargs=1,
        type=parse_exclude_accounts,
        help="comma-separated list of account IDs that should be skipped",
    )
    parser.add_argument(
        "--exclude-regions",
        required=False,
        nargs=1,
        type=parse_exclude_regions,
        help="comma-separated list of region names that should be skipped",
    )
    parser.add_argument(
        "--exclude-ous",
        required=False,
        nargs=1,
        type=parse_exclude_ous,
        help="comma-separated list of Organizations OU IDs that should be skipped",
    )
    parser.add_argument(
        "--exclude-policy-types",
        required=False,
        nargs=1,
        type=parse_exclude_policy_types,
        help="comma-separated list of policy type names that should be skipped",
    )
    parser.add_argument("--profile", required=False, nargs=1, help="named AWS profile to use")

    # Parse arguments
    args = parser.parse_args()
    scope = SCOPE[args.scope[0]]
    if args.member_accounts_role:
        member_accounts_role = args.member_accounts_role[0]
    if args.exclude_accounts:
        exclude_accounts = [val for val in args.exclude_accounts[0].split(",") if val]
    else:
        exclude_accounts = []
    if args.exclude_regions:
        exclude_regions = [val for val in args.exclude_regions[0].split(",") if val]
    else:
        exclude_regions = []
    if args.exclude_ous:
        exclude_ous = [val for val in args.exclude_ous[0].split(",") if val]
    else:
        exclude_ous = []
    if args.exclude_policy_types:
        exclude_policy_types = [val for val in args.exclude_policy_types[0].split(",") if val]
    else:
        exclude_policy_types = []
    profile = args.profile[0] if args.profile else None
    boto_session = boto3.session.Session(profile_name=profile)

    # Test for valid credentials
    sts_client = boto_session.client("sts", config=BOTO_CONFIG, region_name=DEFAULT_REGION)
    try:
        sts_response = sts_client.get_caller_identity()
        account_id = sts_response["Account"]
        account_arn = sts_response["Arn"]
    except:
        print("No or invalid AWS credentials configured")
        sys.exit(1)

    # Prepare result collection structure
    run_timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    result_collection = {
        "_metadata": {
            "invocation": " ".join(sys.argv),
            "principal": account_arn,
            "run_timestamp": run_timestamp,
            "scope": scope.name,
            "errors": [],
        },
        "results_grouped_by_account_id": {},
        "results_grouped_by_finding_category": {},
    }

    # Analyze ORGANIZATION scope
    if scope == SCOPE.ORGANIZATION:
        organizations_client = boto_session.client("organizations", config=BOTO_CONFIG, region_name=DEFAULT_REGION)
        try:
            # Collect information about the Organization
            describe_org_response = organizations_client.describe_organization()
            organization_id = describe_org_response["Organization"]["Id"]
            organization_management_account_id = describe_org_response["Organization"]["MasterAccountId"]
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

            analyze_organization()

        except organizations_client.exceptions.AccessDeniedException:
            print("Insufficient permissions to communicate with the AWS Organizations service")
            sys.exit(1)
        except organizations_client.exceptions.AWSOrganizationsNotInUseException:
            print("AWS Organizations is not configured for this account")
            sys.exit(1)

    # Analyze ACCOUNT scope
    elif scope == SCOPE.ACCOUNT:
        result_collection["_metadata"]["account_id"] = account_id
        analyze_account(account_id, boto_session)

    # Write result file
    output_file_name = "policy_linting_results_{}.json".format(run_timestamp)
    with open(output_file_name, "w") as out_file:
        json.dump(result_collection, out_file, indent=2)
    print("Output file written to {}".format(output_file_name))
