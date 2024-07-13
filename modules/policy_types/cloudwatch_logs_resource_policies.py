RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "logs"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    logs_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    policies_paginator = logs_client.get_paginator("describe_resource_policies")

    # Iterate all resource policies
    for policies_page in policies_paginator.paginate():
        for policy in policies_page["resourcePolicies"]:
            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Logs::ResourcePolicy",
                resource_name=policy["policyName"],
                resource_arn="arn:aws:logs:{}:{}:resource-policy:{}".format(region, account_id, policy["policyName"]),
                policy_document=policy["policyDocument"],
                policy_type="RESOURCE_POLICY",
            )
