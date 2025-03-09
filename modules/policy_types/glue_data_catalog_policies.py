RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "glue"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    glue_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    try:
        get_resource_policy_response = glue_client.get_resource_policy()
    except glue_client.exceptions.from_code("EntityNotFoundException"):
        # This data catalog does not have a policy configured
        return

    policy_analysis_function(
        account_id=account_id,
        region=region,
        source_service=SOURCE_SERVICE,
        resource_type="AWS::Athena::DataCatalog",
        resource_name="catalog",
        resource_arn="arn:aws:glue:{}:{}:catalog".format(region, account_id),
        policy_document=get_resource_policy_response["PolicyInJson"],
        access_analyzer_type="RESOURCE_POLICY",
    )
