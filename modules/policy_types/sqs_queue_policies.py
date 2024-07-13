RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "sqs"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    sqs_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    queues_paginator = sqs_client.get_paginator("list_queues")

    # Iterate all SQS queues
    for queues_page in queues_paginator.paginate():
        if not "QueueUrls" in queues_page:
            continue
        for queue_url in queues_page["QueueUrls"]:
            # Fetch the queue policy and skip validation if there is none
            get_queue_attributes_response = sqs_client.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["Policy", "QueueArn"]
            )
            if "Policy" not in get_queue_attributes_response["Attributes"]:
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::SQS::Queue",
                resource_name=get_queue_attributes_response["Attributes"]["QueueArn"].split(":")[-1],
                resource_arn=get_queue_attributes_response["Attributes"]["QueueArn"],
                policy_document=get_queue_attributes_response["Attributes"]["Policy"],
                policy_type="RESOURCE_POLICY",
            )
