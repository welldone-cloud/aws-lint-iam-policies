def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    lambda_client = boto_session.client("lambda", config=boto_config, region_name=region)
    lambda_functions_paginator = lambda_client.get_paginator("list_functions")

    # Iterate all Lambda functions
    for lambda_functions_page in lambda_functions_paginator.paginate():
        for lambda_function in lambda_functions_page["Functions"]:
            # Fetch all function versions
            function_versions_paginator = lambda_client.get_paginator("list_versions_by_function")
            for function_versions_page in function_versions_paginator.paginate(
                FunctionName=lambda_function["FunctionName"]
            ):
                for function_version in function_versions_page["Versions"]:
                    # Fetch the policy of the function version
                    call_params = {"FunctionName": lambda_function["FunctionName"]}
                    if function_version["Version"] != "$LATEST":
                        call_params["Qualifier"] = function_version["Version"]
                    try:
                        get_policy_response = lambda_client.get_policy(**call_params)
                    except lambda_client.exceptions.from_code("ResourceNotFoundException"):
                        # This function version does not have a policy configured
                        continue

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        boto_session=boto_session,
                        resource_type="AWS::Lambda::Function",
                        resource_name="{}:v{}".format(lambda_function["FunctionName"], function_version["Version"]),
                        resource_arn=function_version["FunctionArn"],
                        policy_document=get_policy_response["Policy"],
                        policy_type="RESOURCE_POLICY",
                    )
