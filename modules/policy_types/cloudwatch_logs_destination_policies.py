RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "logs"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    logs_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    destinations_paginator = logs_client.get_paginator("describe_destinations")

    # Iterate all destination policies
    for destinations_page in destinations_paginator.paginate():
        for destination in destinations_page["destinations"]:
            # Skip if there is no policy set
            if "accessPolicy" not in destination:
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Logs::Destination",
                resource_name=destination["destinationName"],
                resource_arn=destination["arn"],
                policy_document=destination["accessPolicy"],
                policy_type="RESOURCE_POLICY",
            )
