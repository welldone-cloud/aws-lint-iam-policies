#!/usr/bin/env python3

import argparse
import boto3
import botocore.config
import botocore.exceptions
import importlib.metadata
import os
import packaging.requirements
import packaging.version
import pathlib
import re
import sys

from modules.account_analyzer import AccountAnalyzer
from modules.organization_analyzer import OrganizationAnalyzer
from modules.policy_analyzer import PolicyAnalyzer
from modules.result_collector import ResultCollector


AWS_DEFAULT_REGION = "us-east-1"

BOTO_CONFIG = botocore.config.Config(
    connect_timeout=5,
    read_timeout=5,
    retries={"total_max_attempts": 5, "mode": "standard"},
    user_agent_appid="aws-lint-iam-polices",
)

ERROR_MESSAGE_INVALID_PARAMETER = "Invalid parameter for provided scope"

PATTERN_AWS_ACCOUNT_ID = re.compile(r"^\d{12,}$")

PATTERN_AWS_ORGANIZATIONAL_UNIT = re.compile(r"^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$")

PATTERN_AWS_REGION = re.compile(r"^([a-z]+-){2,}\d+$")

PATTERN_AWS_ROLE_NAME = re.compile(r"^[\w+=,.@-]{1,64}$")

PATTERN_FINDING_ISSUE_CODE = re.compile(r"^[A-Z0-9_]+$")

PATTERN_RESULT_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

REQUIREMENTS_FILE = "requirements.txt"

SCOPE_ACCOUNT = "ACCOUNT"

SCOPE_ORGANIZATION = "ORGANIZATION"


def get_scope():
    for pair in [(sys.argv[i], sys.argv[i + 1]) for i in range(0, len(sys.argv) - 1)]:
        if pair == ("--scope", SCOPE_ACCOUNT):
            return SCOPE_ACCOUNT
        elif pair == ("--scope", SCOPE_ORGANIZATION):
            return SCOPE_ORGANIZATION
    return None


def parse_member_accounts_role(val):
    if val and get_scope() != SCOPE_ORGANIZATION:
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAMETER)
    elif not val and get_scope() == SCOPE_ORGANIZATION:
        raise argparse.ArgumentTypeError("Parameter required when using scope {}".format(SCOPE_ORGANIZATION))
    if val and not PATTERN_AWS_ROLE_NAME.match(val):
        raise argparse.ArgumentTypeError("Invalid IAM role name")
    return val


def parse_policy_types(val):
    if get_scope() not in (SCOPE_ACCOUNT, SCOPE_ORGANIZATION):
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAMETER)
    supported_policy_types = PolicyAnalyzer.get_supported_policy_types()
    for policy_type in val.split(","):
        if policy_type not in supported_policy_types:
            raise argparse.ArgumentTypeError("Unrecognized policy type name: {}".format(policy_type))
    return val.split(",")


def parse_regions(val):
    if get_scope() not in (SCOPE_ACCOUNT, SCOPE_ORGANIZATION):
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAMETER)
    for region in val.split(","):
        if not PATTERN_AWS_REGION.match(region):
            raise argparse.ArgumentTypeError("Invalid region format: {}".format(region))
    return val.split(",")


def parse_organizations_accounts(val):
    if get_scope() != SCOPE_ORGANIZATION:
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAMETER)
    for account in val.split(","):
        if not PATTERN_AWS_ACCOUNT_ID.match(account):
            raise argparse.ArgumentTypeError("Invalid account ID format: {}".format(account))
    return val.split(",")


def parse_trusted_accounts(val):
    for account in val.split(","):
        if account == "SAMEORG":
            if get_scope() != SCOPE_ORGANIZATION:
                raise argparse.ArgumentTypeError(
                    "SAMEORG only supported when using scope {}".format(SCOPE_ORGANIZATION)
                )
        elif not PATTERN_AWS_ACCOUNT_ID.match(account):
            raise argparse.ArgumentTypeError("Invalid account ID format: {}".format(account))
    return val.split(",")


def parse_ous(val):
    if get_scope() != SCOPE_ORGANIZATION:
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAMETER)
    for ou in val.split(","):
        if not PATTERN_AWS_ORGANIZATIONAL_UNIT.match(ou):
            raise argparse.ArgumentTypeError("Invalid OU ID format: {}".format(ou))
    return val.split(",")


def parse_issue_codes(val):
    if get_scope() not in (SCOPE_ACCOUNT, SCOPE_ORGANIZATION):
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAMETER)
    for issue_code in val.split(","):
        if not PATTERN_FINDING_ISSUE_CODE.match(issue_code):
            raise argparse.ArgumentTypeError("Invalid issue code format: {}".format(issue_code))
    return val.split(",")


def parse_result_name(val):
    if get_scope() not in (SCOPE_ACCOUNT, SCOPE_ORGANIZATION):
        raise argparse.ArgumentTypeError(ERROR_MESSAGE_INVALID_PARAMETER)
    if not PATTERN_RESULT_NAME.match(val):
        raise argparse.ArgumentTypeError("Result name must satisfy pattern: {}".format(PATTERN_RESULT_NAME.pattern))
    return val


if __name__ == "__main__":
    # Check runtime environment
    if sys.version_info < (3, 10):
        print("Python version 3.10 or higher required")
        sys.exit(1)
    with open(os.path.join(pathlib.Path(__file__).parent, REQUIREMENTS_FILE), "r") as requirements_file:
        for requirements_line in requirements_file.read().splitlines():
            requirement = packaging.requirements.Requirement(requirements_line)
            expected_version_specifier = requirement.specifier
            installed_version = packaging.version.parse(importlib.metadata.version(requirement.name))
            if installed_version not in expected_version_specifier:
                print("Unfulfilled requirement: {}".format(requirements_line))
                sys.exit(1)

    # Parse arguments
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit.")
    mutually_exclusive_args = parser.add_mutually_exclusive_group(required=True)
    mutually_exclusive_args.add_argument(
        "--list-policy-types",
        action="store_true",
        help="List all supported policy types and exit.",
    )
    mutually_exclusive_args.add_argument(
        "--scope",
        choices=[SCOPE_ACCOUNT, SCOPE_ORGANIZATION],
        help="Target either an individual account or all accounts of an Organization.",
    )
    parser.add_argument(
        "--member-accounts-role",
        default="",
        type=parse_member_accounts_role,
        help="Assume the specified IAM role name in member accounts of the Organization.",
    )
    parser.add_argument(
        "--profile",
        help="Use the specified AWS named profile.",
    )
    parser.add_argument(
        "--result-name",
        type=parse_result_name,
        help="Use the specified result name instead of the run timestamp.",
    )
    parser.add_argument(
        "--trusted-accounts",
        default=[],
        type=parse_trusted_accounts,
        help="Treat the specified comma-separated list of account IDs as trusted and do not generate trusted outside principal findings for them. Use 'SAMEORG' to refer to all accounts that belong to the Organization.",
    )
    parser.add_argument(
        "--exclude-policy-types",
        default=[],
        type=parse_policy_types,
        help="Do not target the specified comma-separated list of policy types.",
    )
    parser.add_argument(
        "--include-policy-types",
        default=[],
        type=parse_policy_types,
        help="Only target the specified comma-separated list of policy types.",
    )
    parser.add_argument(
        "--exclude-regions",
        default=[],
        type=parse_regions,
        help="Do not target the specified comma-separated list of regions.",
    )
    parser.add_argument(
        "--include-regions",
        default=[],
        type=parse_regions,
        help="Only target the specified comma-separated list of regions.",
    )
    parser.add_argument(
        "--exclude-accounts",
        default=[],
        type=parse_organizations_accounts,
        help="Do not target the specified comma-separated list of account IDs.",
    )
    parser.add_argument(
        "--include-accounts",
        default=[],
        type=parse_organizations_accounts,
        help="Only target the specified comma-separated list of account IDs.",
    )
    parser.add_argument(
        "--exclude-ous",
        default=[],
        type=parse_ous,
        help="Do not target the specified comma-separated list of OU IDs of the Organization.",
    )
    parser.add_argument(
        "--include-ous",
        default=[],
        type=parse_ous,
        help="Only target the specified comma-separated list of OU IDs of the Organization.",
    )
    parser.add_argument(
        "--exclude-finding-issue-codes",
        default=[],
        type=parse_issue_codes,
        help="Do not report the specified comma-separated list of finding issue codes.",
    )
    parser.add_argument(
        "--include-finding-issue-codes",
        default=[],
        type=parse_issue_codes,
        help="Only report the specified comma-separated list of finding issue codes.",
    )
    args = parser.parse_args()
    args.scope = get_scope()

    # List policy types and exit, if configured
    if args.list_policy_types:
        for policy_type in PolicyAnalyzer.get_supported_policy_types():
            print(policy_type)
        sys.exit(0)

    # Validate provided credentials and get account details
    try:
        boto_session = boto3.Session(profile_name=args.profile, region_name=AWS_DEFAULT_REGION)
    except botocore.exceptions.ProfileNotFound as ex:
        print("Error: {}".format(ex))
        sys.exit(1)
    sts_client = boto_session.client(
        "sts",
        config=BOTO_CONFIG,
        endpoint_url="https://sts.{}.amazonaws.com".format(boto_session.region_name),
    )
    try:
        get_caller_identity_response = sts_client.get_caller_identity()
    except:
        print("No or invalid AWS credentials configured")
        sys.exit(1)
    account_id = get_caller_identity_response["Account"]
    principal = get_caller_identity_response["Arn"]

    # Validate regions provided as arguments
    provided_regions = set(args.exclude_regions + args.include_regions)
    if provided_regions:
        ec2_client = boto_session.client("ec2", config=BOTO_CONFIG)
        try:
            describe_regions_response = ec2_client.describe_regions(AllRegions=True)
        except botocore.exceptions.ClientError:
            print("Cannot read available AWS regions")
            sys.exit(1)
        available_regions = {region["RegionName"] for region in describe_regions_response["Regions"]}
        for region in provided_regions:
            if region not in available_regions:
                print("Unrecognized region: {}".format(region))
                sys.exit(1)

    # Handle ACCOUNT scope
    if args.scope == SCOPE_ACCOUNT:
        result_collector = ResultCollector(
            account_id,
            principal,
            args.scope,
            args.exclude_finding_issue_codes,
            args.include_finding_issue_codes,
            args.result_name,
        )
        account_analyzer = AccountAnalyzer(
            account_id,
            boto_session,
            BOTO_CONFIG,
            result_collector,
            args.trusted_accounts,
            args.exclude_policy_types,
            args.include_policy_types,
            args.exclude_regions,
            args.include_regions,
        )
        account_analyzer.analyze_account()
        result_collector.write_result_files()

    # Handle ORGANIZATION scope
    elif args.scope == SCOPE_ORGANIZATION:
        organizations_client = boto_session.client("organizations", config=BOTO_CONFIG)
        try:
            # Confirm we are running with credentials of the management account
            try:
                describe_organization_response = organizations_client.describe_organization()
            except organizations_client.exceptions.AWSOrganizationsNotInUseException:
                print("AWS Organizations is not configured for this account")
                sys.exit(1)
            if account_id != describe_organization_response["Organization"]["MasterAccountId"]:
                print(
                    "Need to run with credentials of the Organizations management account when using scope {}".format(
                        SCOPE_ORGANIZATION
                    )
                )
                sys.exit(1)

            # Validate accounts provided as arguments
            provided_accounts = set(args.exclude_accounts + args.include_accounts)
            for account in provided_accounts:
                try:
                    organizations_client.describe_account(AccountId=account)
                except organizations_client.exceptions.AccountNotFoundException:
                    print("Unrecognized account in Organization: {}".format(account))
                    sys.exit(1)

            # Validate OUs provided as arguments
            provided_ous = set(args.exclude_ous + args.include_ous)
            for ou in provided_ous:
                try:
                    organizations_client.describe_organizational_unit(OrganizationalUnitId=ou)
                except organizations_client.exceptions.OrganizationalUnitNotFoundException:
                    print("Unrecognized OU in Organization: {}".format(ou))
                    sys.exit(1)

            # Populate trusted accounts when using SAMEORG
            if "SAMEORG" in args.trusted_accounts:
                organizations_accounts = []
                accounts_paginator = organizations_client.get_paginator("list_accounts")
                for accounts_page in accounts_paginator.paginate():
                    organizations_accounts.extend(account["Id"] for account in accounts_page["Accounts"])
                args.trusted_accounts = set(args.trusted_accounts + organizations_accounts) - set(["SAMEORG"])

            result_collector = ResultCollector(
                account_id,
                principal,
                args.scope,
                args.exclude_finding_issue_codes,
                args.include_finding_issue_codes,
                args.result_name,
            )
            organization_analyzer = OrganizationAnalyzer(
                describe_organization_response,
                args.member_accounts_role,
                boto_session,
                BOTO_CONFIG,
                result_collector,
                args.trusted_accounts,
                args.exclude_policy_types,
                args.include_policy_types,
                args.exclude_regions,
                args.include_regions,
                args.exclude_accounts,
                args.include_accounts,
                args.exclude_ous,
                args.include_ous,
            )
            organization_analyzer.analyze_organization()
            result_collector.write_result_files()

        except organizations_client.exceptions.AccessDeniedException:
            print("Insufficient permissions to communicate with the AWS Organizations service")
            sys.exit(1)

    print("Done. Results and policies written to results directory.")
