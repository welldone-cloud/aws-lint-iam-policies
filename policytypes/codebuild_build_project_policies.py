def analyze(account_id, region, boto_session, boto_config, validation_function):
    codebuild_client = boto_session.client("codebuild", config=boto_config, region_name=region)
    build_projects_paginator = codebuild_client.get_paginator("list_projects")

    # Iterate all build projects
    for build_projects_page in build_projects_paginator.paginate():
        for build_project_name in build_projects_page["projects"]:
            build_project_arn = "arn:aws:codebuild:{}:{}:project/{}".format(region, account_id, build_project_name)

            # Fetch resource policy
            try:
                get_resource_policy_response = codebuild_client.get_resource_policy(resourceArn=build_project_arn)
            except codebuild_client.exceptions.from_code("ResourceNotFoundException"):
                # Skip if there is no policy set
                continue

            # Forward policy to validation
            validation_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::CodeBuild::Project",
                resource_name=build_project_name,
                resource_arn=build_project_arn,
                policy_document=get_resource_policy_response["policy"],
                policy_type="RESOURCE_POLICY",
            )
