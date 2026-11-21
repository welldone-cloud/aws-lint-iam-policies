RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "amp"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    amp_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    workspaces_paginator = amp_client.get_paginator("list_workspaces")

    # Iterate all workspaces
    for workspaces_page in workspaces_paginator.paginate():
        for workspace in workspaces_page["workspaces"]:

            # Fetch the workspace resource policy
            try:
                describe_resource_policy_response = amp_client.describe_resource_policy(
                    workspaceId=workspace["workspaceId"]
                )
            except amp_client.exceptions.from_code("ResourceNotFoundException"):
                # Skip if there is no policy set
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::APS::Workspace",
                resource_name=workspace["alias"],
                resource_arn=workspace["arn"],
                policy_document=describe_resource_policy_response["policyDocument"],
                access_analyzer_type="RESOURCE_POLICY",
            )
