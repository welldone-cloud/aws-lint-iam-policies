RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "lambda"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    lambda_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    lambda_layers_paginator = lambda_client.get_paginator("list_layers")

    # Iterate all Lambda layers
    for lambda_layers_page in lambda_layers_paginator.paginate():
        for lambda_layer in lambda_layers_page["Layers"]:
            # Fetch all layer versions
            lambda_layer_versions_paginator = lambda_client.get_paginator("list_layer_versions")
            for layer_versions_page in lambda_layer_versions_paginator.paginate(LayerName=lambda_layer["LayerName"]):
                for layer_version in layer_versions_page["LayerVersions"]:
                    # Fetch the policy of the layer version
                    try:
                        get_policy_response = lambda_client.get_layer_version_policy(
                            LayerName=lambda_layer["LayerName"], VersionNumber=layer_version["Version"]
                        )
                    except lambda_client.exceptions.from_code("ResourceNotFoundException"):
                        # This layer version does not have a policy configured
                        continue

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::Lambda::LayerVersion",
                        resource_name="{}:v{}".format(lambda_layer["LayerName"], layer_version["Version"]),
                        resource_arn=layer_version["LayerVersionArn"],
                        policy_document=get_policy_response["Policy"],
                        access_analyzer_type="RESOURCE_POLICY",
                    )
