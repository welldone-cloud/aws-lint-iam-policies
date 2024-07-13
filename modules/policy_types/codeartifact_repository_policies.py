RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "codeartifact"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    codeartifact_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    list_repositories_paginator = codeartifact_client.get_paginator("list_repositories")

    # Iterate all repositories
    for repositories_page in list_repositories_paginator.paginate():
        for repository in repositories_page["repositories"]:
            # Fetch the resource policy
            try:
                get_repository_permissions_policy_response = codeartifact_client.get_repository_permissions_policy(
                    domain=repository["domainName"], repository=repository["name"]
                )
            except codeartifact_client.exceptions.from_code("ResourceNotFoundException"):
                # Skip if there is no policy set
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::CodeArtifact::Repository",
                resource_name=repository["name"],
                resource_arn=repository["arn"],
                policy_document=get_repository_permissions_policy_response["policy"]["document"],
                policy_type="RESOURCE_POLICY",
            )
