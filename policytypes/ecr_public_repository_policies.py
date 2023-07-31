def analyze(account_id, region, boto_session, boto_config, validation_function):
    ecr_client = boto_session.client("ecr-public", config=boto_config, region_name=region)
    repositories_paginator = ecr_client.get_paginator("describe_repositories")

    # Iterate all public ECR repositories
    for repositories_page in repositories_paginator.paginate():
        for repository in repositories_page["repositories"]:
            # Fetch the repository policy
            try:
                get_repository_policy_response = ecr_client.get_repository_policy(
                    repositoryName=repository["repositoryName"]
                )
            except ecr_client.exceptions.from_code("RepositoryPolicyNotFoundException"):
                continue

            # Forward policy to validation
            validation_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::ECR::PublicRepository",
                resource_name=repository["repositoryName"],
                resource_arn=repository["repositoryArn"],
                policy_document=get_repository_policy_response["policyText"],
                policy_type="RESOURCE_POLICY",
            )