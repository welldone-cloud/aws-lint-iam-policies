def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    apigw_client = boto_session.client("apigateway", config=boto_config, region_name=region)
    apis_paginator = apigw_client.get_paginator("get_rest_apis")

    # Iterate all REST APIs
    for apis_page in apis_paginator.paginate():
        for api in apis_page["items"]:
            # Skip APIs that don't have a resource-based policy set
            if "policy" not in api:
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::ApiGateway::RestApi",
                resource_name=api["name"],
                resource_arn="arn:aws:apigateway:{}::/restapis/{}".format(region, api["id"]),
                policy_document=api["policy"].encode().decode("unicode_escape"),
                policy_type="RESOURCE_POLICY",
            )
