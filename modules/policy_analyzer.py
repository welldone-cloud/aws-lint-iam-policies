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


class PolicyAnalyzer:

    @staticmethod
    def get_supported_policy_type_names():
        return modules.policy_types.__all__

    def __init__(self, boto_session, boto_config, result_collector):
        self._boto_session = boto_session
        self._boto_config = boto_config
        self._result_collector = result_collector
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

        # Write policy dump file
        policy_descriptor["policy_dump_file_name"] = self._result_collector.write_policy_dump_file(
            policy_descriptor, policy_document
        )

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
                finding_descriptor = {
                    "finding_type": finding["findingType"],
                    "finding_issue_code": finding["issueCode"],
                    "finding_description": finding["findingDetails"],
                    "finding_link": finding["learnMoreLink"],
                }
                self._result_collector.submit_result(
                    policy_descriptor, finding_descriptor, disabled_finding_issue_codes
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
                    finding_descriptor = {
                        "finding_type": "SECURITY_WARNING",
                        "finding_issue_code": "PUBLIC_ACCESS",
                        "finding_description": check_no_public_access_response["message"],
                        "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-custom-policy-checks.html",
                    }
                    self._result_collector.submit_result(
                        policy_descriptor, finding_descriptor, disabled_finding_issue_codes
                    )
