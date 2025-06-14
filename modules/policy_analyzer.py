import inspect
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
    "AWS::ApiGateway::RestApi",
    "AWS::Backup::BackupVault",
    "AWS::CloudTrail::Dashboard",
    "AWS::CloudTrail::EventDataStore",
    "AWS::CodeArtifact::Domain",
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
    "AWS::S3Express::AccessPoint",
    "AWS::S3Express::DirectoryBucket",
    "AWS::S3Outposts::AccessPoint",
    "AWS::S3Outposts::Bucket",
    "AWS::S3Tables::Table",
    "AWS::S3Tables::TableBucket",
    "AWS::SecretsManager::Secret",
    "AWS::SNS::Topic",
    "AWS::SQS::Queue",
)

AWS_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12,}$")

AWS_IAM_STS_ARN_PATTERN = re.compile(r"^arn:aws:(iam|sts)::\d{12,}:[^\s]*$")

PUBLIC_ACCESS_CHECKS_DETAILS = [
    {
        "finding_issue_code": "PUBLIC_ACCESS",
        "finding_link": "https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckNoPublicAccess.html",
    },
]

CUSTOM_POLICY_CHECKS_DETAILS = [
    {
        "finding_issue_code": "TRUSTED_IDENTITY_PROVIDER",
        "description": "The policy trusts identity providers to verify caller identities. A review is recommended to determine whether this is the desired setup. Trusted identity providers: {}",
        "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html",
    },
    {
        "finding_issue_code": "TRUSTED_OUTSIDE_PRINCIPAL",
        "description": "The policy trusts principals outside the analyzed AWS account. A review is recommended to determine whether this is the desired setup. Trusted principals: {}",
        "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html",
    },
    {
        "finding_issue_code": "TRUSTED_OUTSIDE_PRINCIPAL_WITH_CONDITIONS",
        "description": "The policy trusts principals outside the analyzed AWS account, restricted by conditions. A review is recommended to determine whether this is the desired setup. Trusted principals: {}",
        "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html",
    },
    {
        "finding_issue_code": "TRUSTED_WILDCARD_PRINCIPAL",
        "description": "The policy trusts the wildcard principal ('*'). A review is recommended to determine whether this is the desired setup.",
        "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html",
    },
    {
        "finding_issue_code": "TRUSTED_WILDCARD_PRINCIPAL_WITH_CONDITIONS",
        "description": "The policy trusts the wildcard principal ('*'), restricted by conditions. A review is recommended to determine whether this is the desired setup.",
        "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html",
    },
]


class PolicyAnalyzer:

    @staticmethod
    def _get_custom_policy_check_results(policy, account_id, trusted_accounts):
        results = {check["finding_issue_code"]: set() for check in CUSTOM_POLICY_CHECKS_DETAILS}
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
                                if value != account_id and value not in trusted_accounts:
                                    if statement_has_conditions:
                                        results["TRUSTED_OUTSIDE_PRINCIPAL_WITH_CONDITIONS"].add(value)
                                    else:
                                        results["TRUSTED_OUTSIDE_PRINCIPAL"].add(value)

                            # Handle principal ARNs
                            elif key == "AWS" and AWS_IAM_STS_ARN_PATTERN.match(value):
                                account_id_in_arn = value.split(":")[4]
                                if account_id_in_arn != account_id and account_id_in_arn not in trusted_accounts:
                                    if statement_has_conditions:
                                        results["TRUSTED_OUTSIDE_PRINCIPAL_WITH_CONDITIONS"].add(value)
                                    else:
                                        results["TRUSTED_OUTSIDE_PRINCIPAL"].add(value)

                            # Handle identity providers
                            elif key == "Federated":
                                results["TRUSTED_IDENTITY_PROVIDER"].add(value)
        return results

    @staticmethod
    def _get_details_for_finding_issue_code(finding_issue_code):
        for details in PUBLIC_ACCESS_CHECKS_DETAILS + CUSTOM_POLICY_CHECKS_DETAILS:
            if details["finding_issue_code"] == finding_issue_code:
                return details
        raise KeyError(finding_issue_code)

    @staticmethod
    def get_supported_policy_types():
        return modules.policy_types.__all__

    def __init__(self, boto_session, boto_config, result_collector, trusted_accounts):
        self._boto_session = boto_session
        self._boto_config = boto_config
        self._result_collector = result_collector
        self._trusted_accounts = trusted_accounts
        self._regional_access_analyzer_clients = {}

    def _get_calling_policy_type(self):
        for frame in inspect.getouterframes(inspect.currentframe()):
            calling_module = inspect.getmodulename(frame.filename)
            if calling_module in self.get_supported_policy_types():
                return calling_module
        return None

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
        access_analyzer_type,
        disabled_finding_issue_codes=[],
    ):
        result_descriptor = {
            "account_id": account_id,
            "region": region,
            "source_service": source_service,
            "resource_type": resource_type,
            "resource_name": resource_name,
            "resource_arn": resource_arn,
            "finding_type": None,
            "finding_issue_code": None,
            "finding_description": None,
            "finding_link": None,
            "policy_type": self._get_calling_policy_type(),
            "policy_file_name": self._result_collector.submit_policy(
                account_id, region, source_service, resource_type, resource_name, policy_document
            ),
        }

        # Send policy through Access Analyzer's validate_policy
        access_analyzer_client = self._get_regional_access_analyzer_client(region)
        findings_paginator = access_analyzer_client.get_paginator("validate_policy")
        call_parameters = {
            "locale": "EN",
            "policyType": access_analyzer_type,
            "policyDocument": policy_document,
        }
        if resource_type in ACCESS_ANALYZER_PARAMETERS_VALIDATE_POLICY:
            call_parameters["validatePolicyResourceType"] = resource_type
        for findings_page in findings_paginator.paginate(**call_parameters):
            for finding in findings_page["findings"]:
                self._result_collector.submit_result(
                    {
                        **result_descriptor,
                        "finding_type": finding["findingType"],
                        "finding_issue_code": finding["issueCode"],
                        "finding_description": finding["findingDetails"],
                        "finding_link": finding["learnMoreLink"],
                    },
                    disabled_finding_issue_codes,
                )

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
                    finding_details = PolicyAnalyzer._get_details_for_finding_issue_code("PUBLIC_ACCESS")
                    self._result_collector.submit_result(
                        {
                            **result_descriptor,
                            "finding_type": "SECURITY_WARNING",
                            "finding_issue_code": finding_details["finding_issue_code"],
                            "finding_description": check_no_public_access_response["message"],
                            "finding_link": finding_details["finding_link"],
                        },
                        disabled_finding_issue_codes,
                    )

        # Send policy through custom policy checks
        if access_analyzer_type == "RESOURCE_POLICY":
            custom_policy_check_results = PolicyAnalyzer._get_custom_policy_check_results(
                policy_document, account_id, self._trusted_accounts
            )
            for finding_issue_code, principals in custom_policy_check_results.items():
                if not principals:
                    continue

                finding_details = PolicyAnalyzer._get_details_for_finding_issue_code(finding_issue_code)
                self._result_collector.submit_result(
                    {
                        **result_descriptor,
                        "finding_type": "SECURITY_WARNING",
                        "finding_issue_code": finding_issue_code,
                        "finding_description": finding_details["description"].format(sorted(principals)),
                        "finding_link": finding_details["finding_link"],
                    },
                    disabled_finding_issue_codes,
                )
