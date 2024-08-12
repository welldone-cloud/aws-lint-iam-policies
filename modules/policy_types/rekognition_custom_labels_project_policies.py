RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "rekognition"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    rekognition_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    describe_projects_paginator = rekognition_client.get_paginator("describe_projects")

    # Iterate all custom labels projects
    try:
        for projects_page in describe_projects_paginator.paginate():
            for project in projects_page["ProjectDescriptions"]:

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

    except rekognition_client.exceptions.from_code("AccessDeniedException"):
        # Regions that don't support this Rekognition custom labels unfortunately yield AccessDenied errors, making
        # the situation indistinguishable from an actual lack of permissions.
        pass
