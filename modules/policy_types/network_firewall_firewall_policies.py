RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "network-firewall"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    network_firewall_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    firewall_policies_paginator = network_firewall_client.get_paginator("list_firewall_policies")

    # Iterate all firewall policies
    for firewall_policies_page in firewall_policies_paginator.paginate():
        for firewall_policy in firewall_policies_page["FirewallPolicies"]:

            # Fetch the resource policy
            try:
                describe_resource_policy_response = network_firewall_client.describe_resource_policy(
                    ResourceArn=firewall_policy["Arn"]
                )
            except network_firewall_client.exceptions.from_code("ResourceNotFoundException"):
                # Skip if there is no resource policy configured
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::NetworkFirewall::FirewallPolicy",
                resource_name=firewall_policy["Name"],
                resource_arn=firewall_policy["Arn"],
                policy_document=describe_resource_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
