def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    codeartifact_client = boto_session.client("codeartifact", config=boto_config, region_name=region)
    list_domains_paginator = codeartifact_client.get_paginator("list_domains")

    # Iterate all domains
    for domains_page in list_domains_paginator.paginate():
        for domain in domains_page["domains"]:
            # Fetch the resource policy
            try:
                get_domain_permissions_policy_response = codeartifact_client.get_domain_permissions_policy(
                    domain=domain["name"]
                )
            except codeartifact_client.exceptions.from_code("ResourceNotFoundException"):
                # Skip if there is no policy set
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::CodeArtifact::Domain",
                resource_name=domain["name"],
                resource_arn=domain["arn"],
                policy_document=get_domain_permissions_policy_response["policy"]["document"],
                policy_type="RESOURCE_POLICY",
            )
