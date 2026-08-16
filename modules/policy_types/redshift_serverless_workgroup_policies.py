RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "redshift-serverless"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    redshift_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    list_workgroups_paginator = redshift_client.get_paginator("list_workgroups")

    # Iterate all Redshift serverless workgroups
    try:
        for workgroups_page in list_workgroups_paginator.paginate():
            for workgroup in workgroups_page["workgroups"]:
                # Fetch the workgroup policy
                try:
                    get_resource_policy_response = redshift_client.get_resource_policy(
                        resourceArn=workgroup["workgroupArn"]
                    )
                except redshift_client.exceptions.from_code("ResourceNotFoundException"):
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::RedshiftServerless::Workgroup",
                    resource_name=workgroup["workgroupName"],
                    resource_arn=workgroup["workgroupArn"],
                    policy_document=get_resource_policy_response["resourcePolicy"]["policy"],
                    access_analyzer_type="RESOURCE_POLICY",
                    disabled_finding_issue_codes=["INVALID_SERVICE_CONDITION_KEY"],
                )

    # Redshift serverless is not available in this region
    except redshift_client.exceptions.from_code("ValidationException"):
        pass
