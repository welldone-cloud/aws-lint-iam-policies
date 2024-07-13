RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "rekognition"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    rekognition_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Custom labels is a sub feature of Rekognition. There can be regions where Rekognition is available but
    # the custom labels feature is not. In these cases, the service unfortunately returns AccessDeniedException,
    # making the situation indistinguishable from an actual lack of permissions. We thus first only collect the
    # list of custom label projects. If the DescribeProjects call already returns an AccessDeniedException, we
    # assume it is a region where custom labels is not available.
    custom_label_projects = []
    describe_projects_paginator = rekognition_client.get_paginator("describe_projects")
    try:
        for projects_page in describe_projects_paginator.paginate():
            for project in projects_page["ProjectDescriptions"]:
                custom_label_projects.append(project)
    except rekognition_client.exceptions.from_code("AccessDeniedException"):
        return

    # Iterate all custom labels projects
    for project in custom_label_projects:
        # Iterate all policies of the project
        list_project_policies_paginator = rekognition_client.get_paginator("list_project_policies")
        for policies_page in list_project_policies_paginator.paginate(ProjectArn=project["ProjectArn"]):
            for policy in policies_page["ProjectPolicies"]:
                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::Rekognition::Project",
                    resource_name="{}:{}".format(project["ProjectArn"].split("/")[-2], policy["PolicyName"]),
                    resource_arn=project["ProjectArn"],
                    policy_document=policy["PolicyDocument"],
                    policy_type="RESOURCE_POLICY",
                )
