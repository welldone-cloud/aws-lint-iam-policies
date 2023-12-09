def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    eventbridge_client = boto_session.client("events", config=boto_config, region_name=region)

    # Iterate all event buses (there is unfortunately no paginator available for this at the moment)
    call_params = {}
    while True:
        list_event_buses_response = eventbridge_client.list_event_buses(**call_params)
        for event_bus in list_event_buses_response["EventBuses"]:
            # Skip if there is no policy set on the event bus
            if "Policy" not in event_bus:
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::Events::EventBusPolicy",
                resource_name=event_bus["Name"],
                resource_arn=event_bus["Arn"],
                policy_document=event_bus["Policy"],
                policy_type="RESOURCE_POLICY",
            )

        try:
            call_params["NextToken"] = list_event_buses_response["NextToken"]
        except KeyError:
            break
