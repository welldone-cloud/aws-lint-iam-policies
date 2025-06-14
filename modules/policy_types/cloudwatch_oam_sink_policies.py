RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "oam"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    oam_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    sinks_paginator = oam_client.get_paginator("list_sinks")

    # Iterate all sinks
    for sinks_page in sinks_paginator.paginate():
        for sink in sinks_page["Items"]:

            # Retrieve the sink policy
            try:
                get_sink_policy_response = oam_client.get_sink_policy(SinkIdentifier=sink["Arn"])
            except oam_client.exceptions.from_code("ResourceNotFoundException"):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Oam::Sink",
                resource_name=sink["Name"],
                resource_arn=sink["Arn"],
                policy_document=get_sink_policy_response["Policy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
