RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "xray"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    xray_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    resource_policies_paginator = xray_client.get_paginator("list_resource_policies")

    # Iterate all resource policies
    for resource_policies_page in resource_policies_paginator.paginate():
        for resource_policy in resource_policies_page["ResourcePolicies"]:
            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::XRay::ResourcePolicy",
                resource_name=resource_policy["PolicyName"],
                resource_arn="arn:aws:xray:{}:{}:resource-policy/{}:{}".format(
                    region, account_id, resource_policy["PolicyName"], resource_policy["PolicyRevisionId"]
                ),
                policy_document=resource_policy["PolicyDocument"],
                access_analyzer_type="RESOURCE_POLICY",
            )
