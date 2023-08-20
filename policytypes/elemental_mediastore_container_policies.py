def analyze(account_id, region, boto_session, boto_config, validation_function):
    mediastore_client = boto_session.client("mediastore", config=boto_config, region_name=region)
    containers_paginator = mediastore_client.get_paginator("list_containers")

    # Iterate all containers
    for containers_page in containers_paginator.paginate():
        for container in containers_page["Containers"]:
            # Fetch the container policy
            try:
                get_container_policy_response = mediastore_client.get_container_policy(ContainerName=container["Name"])
            except mediastore_client.exceptions.from_code("PolicyNotFoundException"):
                # This container does not have a policy configured
                continue

            # Forward policy to validation
            validation_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::MediaStore::Container",
                resource_name=container["Name"],
                resource_arn=container["ARN"],
                policy_document=get_container_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
