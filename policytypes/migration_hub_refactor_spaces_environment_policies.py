import json


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    refactor_spaces_client = boto_session.client(
        "migration-hub-refactor-spaces", config=boto_config, region_name=region
    )
    environments_paginator = refactor_spaces_client.get_paginator("list_environments")

    # Iterate all environments
    for environments_page in environments_paginator.paginate():
        for environment in environments_page["EnvironmentSummaryList"]:
            # Fetch the environment policy
            get_resource_policy_response = refactor_spaces_client.get_resource_policy(Identifier=environment["Arn"])

            # Skip if the environment does not have a policy configured
            if not json.loads(get_resource_policy_response["Policy"]):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::RefactorSpaces::Environment",
                resource_name=environment["Arn"].split("/")[-1],
                resource_arn=environment["Arn"],
                policy_document=get_resource_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
