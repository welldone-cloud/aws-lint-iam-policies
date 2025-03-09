import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "route53resolver"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    route53_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    resolver_query_log_configs_paginator = route53_client.get_paginator("list_resolver_query_log_configs")

    # Iterate all query log configs
    for resolver_query_log_configs_page in resolver_query_log_configs_paginator.paginate():
        for resolver_query_log_config in resolver_query_log_configs_page["ResolverQueryLogConfigs"]:

            # Fetch the resource policy
            try:
                get_resolver_query_log_config_policy_response = route53_client.get_resolver_query_log_config_policy(
                    Arn=resolver_query_log_config["Arn"]
                )
            except route53_client.exceptions.from_code("AccessDeniedException"):
                # The service unfortunately yields AccessDenied errors when there is no policy configured, making the
                # situation indistinguishable from an actual lack of permissions.
                continue

            # Skip if the returned policy is empty
            if not json.loads(get_resolver_query_log_config_policy_response["ResolverQueryLogConfigPolicy"]):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Route53Resolver::ResolverQueryLoggingConfig",
                resource_name=resolver_query_log_config["Name"],
                resource_arn=resolver_query_log_config["Arn"],
                policy_document=get_resolver_query_log_config_policy_response["ResolverQueryLogConfigPolicy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
