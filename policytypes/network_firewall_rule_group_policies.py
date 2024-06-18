SOURCE_SERVICE = "network-firewall"

RULE_GROUP_TYPES = ("STATELESS", "STATEFUL")


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    network_firewall_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    list_rule_groups_paginator = network_firewall_client.get_paginator("list_rule_groups")

    # Iterate rule group types and their rule groups
    for rule_group_type in RULE_GROUP_TYPES:
        for rule_groups_page in list_rule_groups_paginator.paginate(Type=rule_group_type):
            for rule_group in rule_groups_page["RuleGroups"]:

                # Fetch the resource policy
                try:
                    describe_resource_policy_response = network_firewall_client.describe_resource_policy(
                        ResourceArn=rule_group["Arn"]
                    )
                except network_firewall_client.exceptions.from_code("ResourceNotFoundException"):
                    # Skip if there is no resource policy configured
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    boto_session=boto_session,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::NetworkFirewall::RuleGroup",
                    resource_name=rule_group["Name"],
                    resource_arn=rule_group["Arn"],
                    policy_document=describe_resource_policy_response["Policy"],
                    policy_type="RESOURCE_POLICY",
                )
