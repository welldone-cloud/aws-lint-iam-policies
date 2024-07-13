import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "route53resolver"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    route53_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    firewall_rule_groups_paginator = route53_client.get_paginator("list_firewall_rule_groups")

    # Iterate all firewall rule groups
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
                policy_type="RESOURCE_POLICY",
            )
