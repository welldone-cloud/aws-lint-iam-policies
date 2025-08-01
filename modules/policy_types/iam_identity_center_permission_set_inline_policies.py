RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "sso-admin"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    sso_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all SSO instances
    instance_paginator = sso_client.get_paginator("list_instances")
    try:
        for instances_page in instance_paginator.paginate():
            for instance in instances_page["Instances"]:

                # Skip if this instance lives in a different AWS account, which happens when having SSO set up in the
                # Organizations management account, but running this script in an Organizations member account.
                if instance["OwnerAccountId"] != account_id:
                    continue

                # Iterate all permission sets
                instance_arn = instance["InstanceArn"]
                permission_set_paginator = sso_client.get_paginator("list_permission_sets")
                try:
                    for permission_set_page in permission_set_paginator.paginate(InstanceArn=instance_arn):
                        for permission_set_arn in permission_set_page["PermissionSets"]:

                            # Get inline policy
                            get_inline_policy_response = sso_client.get_inline_policy_for_permission_set(
                                InstanceArn=instance_arn,
                                PermissionSetArn=permission_set_arn,
                            )

                            # Skip if no inline policy is set
                            if not get_inline_policy_response["InlinePolicy"]:
                                continue

                            # Get permission set details
                            describe_permission_response = sso_client.describe_permission_set(
                                InstanceArn=instance_arn,
                                PermissionSetArn=permission_set_arn,
                            )

                            policy_analysis_function(
                                account_id=account_id,
                                region=region,
                                source_service=SOURCE_SERVICE,
                                resource_type="AWS::SSO::PermissionSet",
                                resource_name=describe_permission_response["PermissionSet"]["Name"],
                                resource_arn=permission_set_arn,
                                policy_document=get_inline_policy_response["InlinePolicy"],
                                access_analyzer_type="IDENTITY_POLICY",
                            )

                except sso_client.exceptions.from_code("ValidationException"):
                    # Account instances of Identity Center don't support permission sets, thus continue here
                    continue

    except sso_client.exceptions.from_code("AccessDeniedException") as ex:
        # When certain SSO features are not available in a region, it will raise AccessDenied with a blank error
        # message. If a caller is actually lacking permissions, there will be an error message set. Ignore cases
        # where features are not available.
        if not ex.response["Error"]["Message"].strip():
            return
        raise ex
