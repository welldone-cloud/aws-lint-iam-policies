def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    logs_client = boto_session.client("logs", config=boto_config, region_name=region)
    policies_paginator = logs_client.get_paginator("describe_destinations")

    # Iterate all destination policies
    for destinations_page in policies_paginator.paginate():
        for destination in destinations_page["destinations"]:
            # Skip if there is no policy set
            if "accessPolicy" not in destination:
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::Logs::Destination",
                resource_name=destination["destinationName"],
                resource_arn=destination["arn"],
                policy_document=destination["accessPolicy"],
                policy_type="RESOURCE_POLICY",
            )
