import json
import re

import modules.policy_types


ACCESS_ANALYZER_PARAMETERS_VALIDATE_POLICY = (
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/accessanalyzer/client/validate_policy.html
    "AWS::DynamoDB::Table",
    "AWS::IAM::AssumeRolePolicyDocument",
    "AWS::S3::AccessPoint",
    "AWS::S3::Bucket",
    "AWS::S3::MultiRegionAccessPoint",
    "AWS::S3ObjectLambda::AccessPoint",
)

ACCESS_ANALYZER_PARAMETERS_CHECK_NO_PUBLIC_ACCESS = (
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/accessanalyzer/client/check_no_public_access.html
    "AWS::DynamoDB::Stream",
    "AWS::DynamoDB::Table",
    "AWS::EFS::FileSystem",
    "AWS::IAM::AssumeRolePolicyDocument",
    "AWS::Kinesis::Stream",
    "AWS::Kinesis::StreamConsumer",
    "AWS::KMS::Key",
    "AWS::Lambda::Function",
    "AWS::OpenSearchService::Domain",
    "AWS::S3::AccessPoint",
    "AWS::S3::Bucket",
    "AWS::S3::Glacier",
    "AWS::S3Express::DirectoryBucket",
    "AWS::S3Outposts::AccessPoint",
    "AWS::S3Outposts::Bucket",
    "AWS::SecretsManager::Secret",
    "AWS::SNS::Topic",
    "AWS::SQS::Queue",
)

AWS_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12,}$")

AWS_IAM_STS_ARN_PATTERN = re.compile(r"^arn:aws:(iam|sts)::\d{12,}:[^\s]*$")

CUSTOM_POLICY_CHECKS_DETAILS = {
    "TRUSTED_IDENTITY_PROVIDER": {
        "description": "The policy trusts identity providers to verify caller identities. A review is recommended to determine whether this is the desired setup. Trusted identity providers: {}",
        "link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html",
    },
    "TRUSTED_OUTSIDE_PRINCIPAL": {
        "description": "The policy trusts principals outside the analyzed AWS account. A review is recommended to determine whether this is the desired setup. Trusted principals: {}",
        "link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html",
    },
    "TRUSTED_OUTSIDE_PRINCIPAL_WITH_CONDITIONS": {
        "description": "The policy trusts principals outside the analyzed AWS account, restricted by conditions. A review is recommended to determine whether this is the desired setup. Trusted principals: {}",
        "link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html",
    },
    "TRUSTED_WILDCARD_PRINCIPAL": {
        "description": "The policy trusts the wildcard principal ('*'). A review is recommended to determine whether this is the desired setup.",
        "link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html",
    },
    "TRUSTED_WILDCARD_PRINCIPAL_WITH_CONDITIONS": {
        "description": "The policy trusts the wildcard principal ('*'), restricted by conditions. A review is recommended to determine whether this is the desired setup.",
        "link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html",
    },
}


class PolicyAnalyzer:

    @staticmethod
    def _get_custom_policy_check_results(policy, account_id, trusted_account_ids):
        results = {
            "TRUSTED_IDENTITY_PROVIDER": set(),
            "TRUSTED_OUTSIDE_PRINCIPAL": set(),
            "TRUSTED_OUTSIDE_PRINCIPAL_WITH_CONDITIONS": set(),
            "TRUSTED_WILDCARD_PRINCIPAL": set(),
            "TRUSTED_WILDCARD_PRINCIPAL_WITH_CONDITIONS": set(),
        }
        policy = json.loads(policy)

        # Make sure the "Statement" block is represented as a list, even if it only consists of a single item
        if "Statement" in policy:
            if isinstance(policy["Statement"], list):
                statements = policy["Statement"]
            else:
                statements = [policy["Statement"]]

            # Iterate all statements
            for statement in statements:
                # Skip if the statement is not represented by a dict
                if not isinstance(statement, dict):
                    continue

                # Skip if there is no "Principal" element in the statement. "NotPrincipal" elements are not analyzed, because
                # Access Analyzer already reports on their usage.
                if "Principal" not in statement:
                    continue

                # Skip if there is no "Effect" element or if it is not set to "Allow"
                if "Effect" not in statement or statement["Effect"] != "Allow":
                    continue

                # Determine if the statement has non-empty conditions set
                statement_has_conditions = False
                if "Condition" in statement and statement["Condition"]:
                    statement_has_conditions = True

                # Handle case: "Principal": "*"
                if isinstance(statement["Principal"], str) and statement["Principal"] == "*":
                    if statement_has_conditions:
                        results["TRUSTED_WILDCARD_PRINCIPAL_WITH_CONDITIONS"].add("*")
                    else:
                        results["TRUSTED_WILDCARD_PRINCIPAL"].add("*")

                # Handle case: "Principal": {key: values, [...]}
                elif isinstance(statement["Principal"], dict):
                    for key, values in statement["Principal"].items():
                        # Make sure the values are represented as a list, even if there is only a single item
                        if not isinstance(values, list):
                            values = [values]

                        for value in values:
                            # Handle wildcards
                            if key == "AWS" and value == "*":
                                if statement_has_conditions:
                                    results["TRUSTED_WILDCARD_PRINCIPAL_WITH_CONDITIONS"].add("*")
                                else:
                                    results["TRUSTED_WILDCARD_PRINCIPAL"].add("*")

                            # Handle account numbers
                            elif key == "AWS" and AWS_ACCOUNT_ID_PATTERN.match(value):
                                if value != account_id and value not in trusted_account_ids:
                                    if statement_has_conditions:
                                        results["TRUSTED_OUTSIDE_PRINCIPAL_WITH_CONDITIONS"].add(value)
                                    else:
                                        results["TRUSTED_OUTSIDE_PRINCIPAL"].add(value)

                            # Handle principal ARNs
                            elif key == "AWS" and AWS_IAM_STS_ARN_PATTERN.match(value):
                                account_id_in_arn = value.split(":")[4]
                                if account_id_in_arn != account_id and account_id_in_arn not in trusted_account_ids:
                                    if statement_has_conditions:
                                        results["TRUSTED_OUTSIDE_PRINCIPAL_WITH_CONDITIONS"].add(value)
                                    else:
                                        results["TRUSTED_OUTSIDE_PRINCIPAL"].add(value)

                            # Handle identity providers
                            elif key == "Federated":
                                results["TRUSTED_IDENTITY_PROVIDER"].add(value)
        return results

    @staticmethod
    def get_supported_policy_type_names():
        return modules.policy_types.__all__

    def __init__(self, boto_session, boto_config, result_collector, trusted_account_ids):
        self._boto_session = boto_session
        self._boto_config = boto_config
        self._result_collector = result_collector
        self._trusted_account_ids = trusted_account_ids
        self._regional_access_analyzer_clients = {}

    def _get_regional_access_analyzer_client(self, region):
        try:
            return self._regional_access_analyzer_clients[region]
        except KeyError:
            regional_access_analyzer_client = self._boto_session.client(
                "accessanalyzer", config=self._boto_config, region_name=region
            )
            self._regional_access_analyzer_clients[region] = regional_access_analyzer_client
            return regional_access_analyzer_client

    def analyze_policy(
        self,
        account_id,
        region,
        source_service,
        resource_type,
        resource_name,
        resource_arn,
        policy_document,
        policy_type,
        disabled_finding_issue_codes=[],
    ):
        policy_descriptor = {
            "account_id": account_id,
            "region": region,
            "source_service": source_service,
            "resource_type": resource_type,
            "resource_name": resource_name,
            "resource_arn": resource_arn,
        }
        policy_file_name = self._result_collector.submit_policy(policy_descriptor, policy_document)

        # Send policy through Access Analyzer's validate_policy
        access_analyzer_client = self._get_regional_access_analyzer_client(region)
        findings_paginator = access_analyzer_client.get_paginator("validate_policy")
        call_parameters = {
            "locale": "EN",
            "policyType": policy_type,
            "policyDocument": policy_document,
        }
        if resource_type in ACCESS_ANALYZER_PARAMETERS_VALIDATE_POLICY:
            call_parameters["validatePolicyResourceType"] = resource_type
        for findings_page in findings_paginator.paginate(**call_parameters):
            for finding in findings_page["findings"]:
                result = {
                    **policy_descriptor,
                    "finding_type": finding["findingType"],
                    "finding_issue_code": finding["issueCode"],
                    "finding_description": finding["findingDetails"],
                    "finding_link": finding["learnMoreLink"],
                    "policy_file_name": policy_file_name,
                }
                self._result_collector.submit_result(result, disabled_finding_issue_codes)

        # Send policy through Access Analyzer's check_no_public_access, if supported
        if resource_type in ACCESS_ANALYZER_PARAMETERS_CHECK_NO_PUBLIC_ACCESS:
            try:
                check_no_public_access_response = access_analyzer_client.check_no_public_access(
                    policyDocument=policy_document, resourceType=resource_type
                )
            except access_analyzer_client.exceptions.from_code("InvalidParameterException"):
                # There are valid IAM policies that lead to an error with check_no_public_access, such as policies that
                # consist of only Deny statements. Ignore these errors here.
                pass
            else:
                if check_no_public_access_response["result"] == "FAIL":
                    result = {
                        **policy_descriptor,
                        "finding_type": "SECURITY_WARNING",
                        "finding_issue_code": "PUBLIC_ACCESS",
                        "finding_description": check_no_public_access_response["message"],
                        "finding_link": "https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckNoPublicAccess.html",
                        "policy_file_name": policy_file_name,
                    }
                    self._result_collector.submit_result(result, disabled_finding_issue_codes)

        # Send policy through custom policy checks
        if policy_type == "RESOURCE_POLICY":
            custom_policy_check_results = PolicyAnalyzer._get_custom_policy_check_results(
                policy_document, account_id, self._trusted_account_ids
            )
            for finding_issue_code, principals in custom_policy_check_results.items():
                if not principals:
                    continue

                result = {
                    **policy_descriptor,
                    "finding_type": "SECURITY_WARNING",
                    "finding_issue_code": finding_issue_code,
                    "finding_description": CUSTOM_POLICY_CHECKS_DETAILS[finding_issue_code]["description"].format(
                        sorted(principals)
                    ),
                    "finding_link": CUSTOM_POLICY_CHECKS_DETAILS[finding_issue_code]["link"],
                    "policy_file_name": policy_file_name,
                }
                self._result_collector.submit_result(result, disabled_finding_issue_codes)
