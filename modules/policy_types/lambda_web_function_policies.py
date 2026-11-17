RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "lambda-web"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    lambda_web_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    lambda_web_functions_paginator = lambda_web_client.get_paginator("list_web_functions")

    # Iterate all Lambda web functions
    try:
        for lambda_web_functions_page in lambda_web_functions_paginator.paginate():
            for lambda_web_function in lambda_web_functions_page["functions"]:

                # Fetch the policy of the web function
                try:
                    get_resource_policy_response = lambda_web_client.get_resource_policy(
                        resourceArn=lambda_web_function["functionArn"]
                    )
                except lambda_web_client.exceptions.from_code("ResourceNotFoundException"):
                    # This web function does not have a policy configured
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::Lambda::WebFunction",
                    resource_name=lambda_web_function["functionName"],
                    resource_arn=lambda_web_function["functionArn"],
                    policy_document=get_resource_policy_response["policy"],
                    access_analyzer_type="RESOURCE_POLICY",
                )

    # The service can also return AccessDenied exceptions when Lambda web functions are not available in
    # a region, instead of a lack of permissions. However, the respective error messages are different.
    except (
        lambda_web_client.exceptions.from_code("AccessDeniedException"),
        lambda_web_client.exceptions.from_code("403"),
    ) as ex:
        if "Unable to determine service/operation name" in ex.response["Error"].get("Message", ""):
            return
        raise
