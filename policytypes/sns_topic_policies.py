def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    sns_client = boto_session.client("sns", config=boto_config, region_name=region)
    topics_paginator = sns_client.get_paginator("list_topics")

    # Iterate all SNS topics
    for topics_page in topics_paginator.paginate():
        for topic in topics_page["Topics"]:
            # Fetch the topic policy
            get_topic_attributes_response = sns_client.get_topic_attributes(TopicArn=topic["TopicArn"])

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::SNS::TopicPolicy",
                resource_name=topic["TopicArn"].split(":")[-1],
                resource_arn=topic["TopicArn"],
                policy_document=get_topic_attributes_response["Attributes"]["Policy"],
                policy_type="RESOURCE_POLICY",
            )
