import json


SOURCE_SERVICE = "route53resolver"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    route53_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    list_resolver_rules_paginator = route53_client.get_paginator("list_resolver_rules")

    # Iterate all resolver rules
    for resolver_rules_page in list_resolver_rules_paginator.paginate():
        for resolver_rule in resolver_rules_page["ResolverRules"]:
            # Skip the default Internet resolver, as it cannot be shared
            if resolver_rule["Name"] == "Internet Resolver" and resolver_rule["OwnerId"] == "Route 53 Resolver":
                continue

            # Fetch the resource policy
            get_resolver_rule_policy_response = route53_client.get_resolver_rule_policy(Arn=resolver_rule["Arn"])

            # Skip if there is no resource policy configured
            if not json.loads(get_resolver_rule_policy_response["ResolverRulePolicy"]):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Route53Resolver::ResolverRule",
                resource_name=resolver_rule["Name"],
                resource_arn=resolver_rule["Arn"],
                policy_document=get_resolver_rule_policy_response["ResolverRulePolicy"],
                policy_type="RESOURCE_POLICY",
            )
