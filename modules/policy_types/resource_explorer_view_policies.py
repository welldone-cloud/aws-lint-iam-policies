import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "ram"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ram_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    resources_paginator = ram_client.get_paginator("list_resources")

    # Iterate resources via RAM
    try:
        for resource_page in resources_paginator.paginate(
            resourceType="resource-explorer-2:View",
            resourceOwner="SELF",
            resourceRegionScope="REGIONAL",
        ):
            for resource in resource_page["resources"]:

                # Iterate attached policies
                policies_paginator = ram_client.get_paginator("get_resource_policies")
                for policies_page in policies_paginator.paginate(resourceArns=[resource["arn"]]):
                    for policy in policies_page["policies"]:

                        # Skip if policy is empty
                        if not json.loads(policy):
                            continue

                        policy_analysis_function(
                            account_id=account_id,
                            region=region,
                            source_service=SOURCE_SERVICE,
                            resource_type="AWS::ResourceExplorer2::View",
                            resource_name=resource["arn"].split("/")[-2],
                            resource_arn=resource["arn"],
                            policy_document=policy,
                            policy_type="RESOURCE_POLICY",
                        )

    # Skip if this RAM resource type is not supported in this region
    except ram_client.exceptions.from_code("InvalidParameterException") as ex:
        if "Invalid resource type" in ex.response["Error"]["Message"]:
            return
        raise
