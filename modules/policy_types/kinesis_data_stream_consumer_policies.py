import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "kinesis"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    kinesis_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    streams_paginator = kinesis_client.get_paginator("list_streams")

    # Iterate all Kinesis streams
    for streams_page in streams_paginator.paginate():
        for stream in streams_page["StreamSummaries"]:
            # Iterate all consumers of the stream
            consumers_paginator = kinesis_client.get_paginator("list_stream_consumers")
            for consumers_page in consumers_paginator.paginate(StreamARN=stream["StreamARN"]):
                for consumer in consumers_page["Consumers"]:
                    # Fetch the consumer policy
                    get_resource_policy_response = kinesis_client.get_resource_policy(
                        ResourceARN=consumer["ConsumerARN"]
                    )

                    # Skip empty policies
                    if not json.loads(get_resource_policy_response["Policy"]):
                        continue

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::Kinesis::StreamConsumer",
                        resource_name=consumer["ConsumerName"],
                        resource_arn=consumer["ConsumerARN"],
                        policy_document=get_resource_policy_response["Policy"],
                        policy_type="RESOURCE_POLICY",
                    )
