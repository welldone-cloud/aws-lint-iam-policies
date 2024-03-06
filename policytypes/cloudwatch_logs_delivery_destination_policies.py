def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    logs_client = boto_session.client("logs", config=boto_config, region_name=region)
    delivery_destinations_paginator = logs_client.get_paginator("describe_delivery_destinations")

    # Iterate all delivery destinations
    for delivery_destinations_page in delivery_destinations_paginator.paginate():
        for delivery_destination in delivery_destinations_page["deliveryDestinations"]:

            # Get the delivery destination policy
            get_delivery_destination_policy_response = logs_client.get_delivery_destination_policy(
                deliveryDestinationName=delivery_destination["name"]
            )

            # Skip if there is no delivery destination policy set
            if "deliveryDestinationPolicy" not in get_delivery_destination_policy_response["policy"]:
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::Logs::DeliveryDestination",
                resource_name=delivery_destination["name"],
                resource_arn=delivery_destination["arn"],
                policy_document=get_delivery_destination_policy_response["policy"]["deliveryDestinationPolicy"],
                policy_type="RESOURCE_POLICY",
            )
