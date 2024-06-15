SOURCE_SERVICE = "ssm"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ssm_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    parameters_paginator = ssm_client.get_paginator("describe_parameters")

    # Iterate all advanced tier parameters
    for parameters_page in parameters_paginator.paginate(
        ParameterFilters=[
            {
                "Key": "Tier",
                "Option": "Equals",
                "Values": ["Advanced"],
            }
        ],
        Shared=False,
    ):
        for parameter in parameters_page["Parameters"]:
            # Iterate all policies for the parameter
            policies_paginator = ssm_client.get_paginator("get_resource_policies")
            for policies_page in policies_paginator.paginate(ResourceArn=parameter["ARN"]):
                for policy in policies_page["Policies"]:

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        boto_session=boto_session,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::SSM::Parameter",
                        resource_name=parameter["Name"],
                        resource_arn=parameter["ARN"],
                        policy_document=policy["Policy"],
                        policy_type="RESOURCE_POLICY",
                    )
