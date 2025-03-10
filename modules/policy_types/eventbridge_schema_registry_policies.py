RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "schemas"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    eventbridge_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    schema_registries_paginator = eventbridge_client.get_paginator("list_registries")

    # Iterate all schema registries local to the account
    for schema_registries_page in schema_registries_paginator.paginate(Scope="LOCAL"):
        for schema_registry in schema_registries_page["Registries"]:
            # Fetch the schema registry policy
            try:
                get_resource_policy_response = eventbridge_client.get_resource_policy(
                    RegistryName=schema_registry["RegistryName"]
                )
            except eventbridge_client.exceptions.from_code("NotFoundException"):
                # This schema registry does not have a policy configured
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::EventSchemas::Registry",
                resource_name=schema_registry["RegistryName"],
                resource_arn=schema_registry["RegistryArn"],
                policy_document=get_resource_policy_response["Policy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
