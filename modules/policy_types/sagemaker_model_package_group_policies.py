RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "sagemaker"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    sagemaker_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    list_model_package_groups_paginator = sagemaker_client.get_paginator("list_model_package_groups")

    # Iterate all model package groups
    try:
        for model_package_groups_page in list_model_package_groups_paginator.paginate():
            for model_package_group in model_package_groups_page["ModelPackageGroupSummaryList"]:
                # Fetch the model package group policy
                try:
                    get_model_package_group_policy_response = sagemaker_client.get_model_package_group_policy(
                        ModelPackageGroupName=model_package_group["ModelPackageGroupName"]
                    )
                except sagemaker_client.exceptions.from_code("ValidationException"):
                    # Skip if there is no policy configured
                    return

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::SageMaker::ModelPackageGroup",
                    resource_name=model_package_group["ModelPackageGroupName"],
                    resource_arn=model_package_group["ModelPackageGroupArn"],
                    policy_document=get_model_package_group_policy_response["ResourcePolicy"],
                    access_analyzer_type="RESOURCE_POLICY",
                )

    # Feature is not supported in this region
    except sagemaker_client.exceptions.from_code("UnknownOperationException"):
        pass
