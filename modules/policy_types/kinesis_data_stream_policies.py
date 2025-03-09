import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "kinesis"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    kinesis_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    streams_paginator = kinesis_client.get_paginator("list_streams")

    # Iterate all Kinesis streams
    for streams_page in streams_paginator.paginate():
        for stream in streams_page["StreamSummaries"]:
            # Fetch the stream policy
            get_resource_policy_response = kinesis_client.get_resource_policy(ResourceARN=stream["StreamARN"])

            # Skip empty policies
            if not json.loads(get_resource_policy_response["Policy"]):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Kinesis::Stream",
                resource_name=stream["StreamName"],
                resource_arn=stream["StreamARN"],
                policy_document=get_resource_policy_response["Policy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
