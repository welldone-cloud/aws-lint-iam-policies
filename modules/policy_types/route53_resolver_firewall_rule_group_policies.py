import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "route53resolver"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    route53_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    firewall_rule_groups_paginator = route53_client.get_paginator("list_firewall_rule_groups")

    # Iterate all firewall rule groups
    try:
        for firewall_rule_groups_page in firewall_rule_groups_paginator.paginate():
            for firewall_rule_group in firewall_rule_groups_page["FirewallRuleGroups"]:

                # Fetch the resource policy
                get_firewall_rule_group_policy_response = route53_client.get_firewall_rule_group_policy(
                    Arn=firewall_rule_group["Arn"]
                )

                # Skip if there is no resource policy configured
                if not json.loads(get_firewall_rule_group_policy_response["FirewallRuleGroupPolicy"]):
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::Route53Resolver::FirewallRuleGroup",
                    resource_name=firewall_rule_group["Name"],
                    resource_arn=firewall_rule_group["Arn"],
                    policy_document=get_firewall_rule_group_policy_response["FirewallRuleGroupPolicy"],
                    access_analyzer_type="RESOURCE_POLICY",
                )

    except route53_client.exceptions.from_code("AccessDeniedException") as ex:
        # When Route53 resolver firewall is not available in a region, it will raise an AccessDenied exception.
        # However, the error message will be different compared to when a caller is actually lacking permissions.
        # Ignore cases where the feature is not available.
        if ex.response["Error"]["Message"].strip() == "Account is not authorized to perform this operation.":
            return
        raise ex
