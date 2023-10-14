def analyze(account_id, region, boto_session, boto_config, validation_function):
    organizations_client = boto_session.client("organizations", config=boto_config, region_name=region)
    try:
        describe_resource_policy_response = organizations_client.describe_resource_policy()
    except (
        organizations_client.exceptions.AccessDeniedException,
        organizations_client.exceptions.AWSOrganizationsNotInUseException,
    ):
        # Account is either not a management account or does not have Organizations enabled
        return
    except organizations_client.exceptions.ResourcePolicyNotFoundException:
        # There is no delegation policy set
        return

    # Forward policy to validation
    validation_function(
        account_id=account_id,
        region=region,
        boto_session=boto_session,
        resource_type="AWS::Organizations::ResourcePolicy",
        resource_name=describe_resource_policy_response["ResourcePolicy"]["ResourcePolicySummary"]["Id"],
        resource_arn=describe_resource_policy_response["ResourcePolicy"]["ResourcePolicySummary"]["Arn"],
        policy_document=describe_resource_policy_response["ResourcePolicy"]["Content"],
        policy_type="RESOURCE_POLICY",
    )
