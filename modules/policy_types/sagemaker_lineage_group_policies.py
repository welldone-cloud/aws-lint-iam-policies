import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "sagemaker"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    sagemaker_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    lineage_groups_paginator = sagemaker_client.get_paginator("list_lineage_groups")

    # Iterate all lineage groups
    try:
        for lineage_groups_page in lineage_groups_paginator.paginate():
            for lineage_group in lineage_groups_page["LineageGroupSummaries"]:
                # Fetch the lineage group policy
                get_lineage_group_policy_response = sagemaker_client.get_lineage_group_policy(
                    LineageGroupName=lineage_group["LineageGroupName"]
                )

                # Skip if there is no policy configured
                if not json.loads(get_lineage_group_policy_response["ResourcePolicy"]):
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::SageMaker::LineageGroup",
                    resource_name=lineage_group["LineageGroupName"],
                    resource_arn=lineage_group["LineageGroupArn"],
                    policy_document=get_lineage_group_policy_response["ResourcePolicy"],
                    policy_type="RESOURCE_POLICY",
                )

    # Skip regions where the lineage group feature is not available
    except sagemaker_client.exceptions.from_code("ValidationException"):
        return
