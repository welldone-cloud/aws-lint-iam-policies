RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "lambda"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    lambda_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    lambda_functions_paginator = lambda_client.get_paginator("list_functions")

    # Iterate all Lambda functions
    for lambda_functions_page in lambda_functions_paginator.paginate():
        for lambda_function in lambda_functions_page["Functions"]:
            # Fetch all function aliases
            function_aliases_paginator = lambda_client.get_paginator("list_aliases")
            for function_aliases_page in function_aliases_paginator.paginate(
                FunctionName=lambda_function["FunctionName"]
            ):
                for function_alias in function_aliases_page["Aliases"]:
                    # Fetch the policy of the function alias
                    call_params = {
                        "FunctionName": lambda_function["FunctionName"],
                        "Qualifier": function_alias["Name"],
                    }
                    try:
                        get_policy_response = lambda_client.get_policy(**call_params)
                    except lambda_client.exceptions.from_code("ResourceNotFoundException"):
                        # This function alias does not have a policy configured
                        continue

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::Lambda::Alias",
                        resource_name="{}:{}".format(lambda_function["FunctionName"], function_alias["Name"]),
                        resource_arn=function_alias["AliasArn"],
                        policy_document=get_policy_response["Policy"],
                        access_analyzer_type="RESOURCE_POLICY",
                    )
