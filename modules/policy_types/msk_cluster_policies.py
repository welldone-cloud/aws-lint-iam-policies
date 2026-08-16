RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "kafka"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    kafka_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    cluster_paginator = kafka_client.get_paginator("list_clusters_v2")

    # Iterate all clusters
    for cluster_page in cluster_paginator.paginate():
        for cluster in cluster_page["ClusterInfoList"]:

            # Fetch the resource policy
            try:
                get_cluster_policy_response = kafka_client.get_cluster_policy(ClusterArn=cluster["ClusterArn"])
            except kafka_client.exceptions.from_code("NotFoundException"):
                # Skip if there is no resource policy configured
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::MSK::Cluster",
                resource_name=cluster["ClusterName"],
                resource_arn=cluster["ClusterArn"],
                policy_document=get_cluster_policy_response["Policy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
