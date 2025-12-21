RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "codebuild"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    codebuild_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    report_groups_paginator = codebuild_client.get_paginator("list_report_groups")

    # Iterate all report groups
    try:
        for report_groups_page in report_groups_paginator.paginate():
            for report_group_arn in report_groups_page["reportGroups"]:
                # Fetch resource policy
                try:
                    get_resource_policy_response = codebuild_client.get_resource_policy(resourceArn=report_group_arn)
                except codebuild_client.exceptions.from_code("ResourceNotFoundException"):
                    # Skip if there is no policy set
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::CodeBuild::ReportGroup",
                    resource_name=report_group_arn.split(":")[-1],
                    resource_arn=report_group_arn,
                    policy_document=get_resource_policy_response["policy"],
                    access_analyzer_type="RESOURCE_POLICY",
                )

    except codebuild_client.exceptions.from_code("AccessDeniedException") as ex:
        # Some regions where CodeBuild is not available yield this error, but it can be distinguished from an actual
        # lack of permissions because the error message is empty
        if ex.response["Error"]["Message"]:
            raise
