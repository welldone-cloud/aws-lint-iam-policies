def analyze(account_id, region, boto_session, boto_config, validation_function):
    rekognition_client = boto_session.client("rekognition", config=boto_config, region_name=region)
    describe_projects_paginator = rekognition_client.get_paginator("describe_projects")

    # Iterate all custom labels projects
    for projects_page in describe_projects_paginator.paginate():
        for project in projects_page["ProjectDescriptions"]:
            # Iterate all policies of the project
            list_project_policies_paginator = rekognition_client.get_paginator("list_project_policies")
            for policies_page in list_project_policies_paginator.paginate(ProjectArn=project["ProjectArn"]):
                for policy in policies_page["ProjectPolicies"]:
                    # Forward policy to validation
                    validation_function(
                        account_id=account_id,
                        region=region,
                        boto_session=boto_session,
                        resource_type="AWS::Rekognition::Project",
                        resource_name="{}:{}".format(project["ProjectArn"].split("/")[-2], policy["PolicyName"]),
                        resource_arn=project["ProjectArn"],
                        policy_document=policy["PolicyDocument"],
                        policy_type="RESOURCE_POLICY",
                    )
