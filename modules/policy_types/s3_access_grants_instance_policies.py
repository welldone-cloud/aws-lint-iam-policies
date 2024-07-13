RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "s3control"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    s3_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Get the access grants instance
    try:
        get_access_grants_instance_response = s3_client.get_access_grants_instance(AccountId=account_id)
    except s3_client.exceptions.from_code("AccessGrantsInstanceNotExistsError"):
        # There is no access grants instance configured in this region
        return

    #  Get the access grants instance policy
    try:
        get_access_grants_instance_resource_policy_response = s3_client.get_access_grants_instance_resource_policy(
            AccountId=account_id
        )
    except s3_client.exceptions.from_code("AccessGrantsInstanceResourcePolicyNotExists"):
        # There is no access grants instance policy configured
        return

    policy_analysis_function(
        account_id=account_id,
        region=region,
        source_service=SOURCE_SERVICE,
        resource_type="AWS::S3::AccessGrantsInstance",
        resource_name=get_access_grants_instance_response["AccessGrantsInstanceId"],
        resource_arn=get_access_grants_instance_response["AccessGrantsInstanceArn"],
        policy_document=get_access_grants_instance_resource_policy_response["Policy"],
        policy_type="RESOURCE_POLICY",
    )
