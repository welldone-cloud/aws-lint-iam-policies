RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "apigateway"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    apigw_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    domains_paginator = apigw_client.get_paginator("get_domain_names")

    # Iterate all domain names
    for domains_page in domains_paginator.paginate():
        for domain in domains_page["items"]:
            # Skip domain types other than private domains
            if "PRIVATE" not in domain["endpointConfiguration"]["types"]:
                continue

            # Fetch domain details
            get_domain_name_response = apigw_client.get_domain_name(
                domainName=domain["domainName"],
                domainNameId=domain["domainNameId"],
            )

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::ApiGateway::DomainNameV2",
                resource_name=domain["domainName"],
                resource_arn=domain["domainNameArn"],
                policy_document=get_domain_name_response["policy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
