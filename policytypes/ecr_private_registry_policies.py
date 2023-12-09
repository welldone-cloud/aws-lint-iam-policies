def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ecr_client = boto_session.client("ecr", config=boto_config, region_name=region)
    try:
        get_registry_policy_response = ecr_client.get_registry_policy()
    except ecr_client.exceptions.from_code("RegistryPolicyNotFoundException"):
        return

    policy_analysis_function(
        account_id=account_id,
        region=region,
        boto_session=boto_session,
        resource_type="AWS::ECR::RegistryPolicy",
        resource_name=get_registry_policy_response["registryId"],
        resource_arn="arn:aws:ecr:{}:{}".format(region, account_id),
        policy_document=get_registry_policy_response["policyText"],
        policy_type="RESOURCE_POLICY",
    )
