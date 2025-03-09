RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "ssm-incidents"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ssm_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    response_plans_paginator = ssm_client.get_paginator("list_response_plans")

    # Iterate all response plans
    for response_plans_page in response_plans_paginator.paginate():
        for response_plan in response_plans_page["responsePlanSummaries"]:
            # Iterate all policies for the response plan
            resource_policies_paginator = ssm_client.get_paginator("get_resource_policies")
            for resource_policies_page in resource_policies_paginator.paginate(resourceArn=response_plan["arn"]):
                for resource_policy in resource_policies_page["resourcePolicies"]:
                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::SSMIncidents::ResponsePlan",
                        resource_name="{}:{}".format(response_plan["name"], resource_policy["policyId"]),
                        resource_arn=response_plan["arn"],
                        policy_document=resource_policy["policyDocument"],
                        access_analyzer_type="RESOURCE_POLICY",
                    )
