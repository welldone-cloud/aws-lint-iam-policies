RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "rum"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    rum_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Collect a list of app monitors names
    app_monitors_names = []
    app_monitors_paginator = rum_client.get_paginator("list_app_monitors")
    try:
        for app_monitors_page in app_monitors_paginator.paginate():
            for app_monitor in app_monitors_page["AppMonitorSummaries"]:
                app_monitors_names.append(app_monitor["Name"])
    except rum_client.exceptions.from_code("AccessDeniedException") as ex:
        # Ignore regions where RUM is not available
        if ex.response["Error"]["Message"] != "Account is not authorized":
            raise

    # Iterate app monitors names and retrieve their resource-based policy
    for app_monitor_name in app_monitors_names:
        try:
            get_resource_policy_response = rum_client.get_resource_policy(Name=app_monitor_name)
        except (
            rum_client.exceptions.from_code("PolicyNotFoundException"),
            rum_client.exceptions.from_code("ResourceNotFoundException"),
        ):
            continue

        policy_analysis_function(
            account_id=account_id,
            region=region,
            source_service=SOURCE_SERVICE,
            resource_type="AWS::RUM::AppMonitor",
            resource_name=app_monitor_name,
            resource_arn="arn:aws:rum:{}:{}:appmonitor/{}".format(region, account_id, app_monitor_name),
            policy_document=get_resource_policy_response["PolicyDocument"],
            access_analyzer_type="RESOURCE_POLICY",
        )
