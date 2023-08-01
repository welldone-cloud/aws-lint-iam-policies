def analyze(account_id, region, boto_session, boto_config, validation_function):
    opensearch_client = boto_session.client("opensearch", config=boto_config, region_name=region)

    # Iterate all OpenSearch domains
    list_domain_names_response = opensearch_client.list_domain_names()
    for domain in list_domain_names_response["DomainNames"]:
        describe_domain_response = opensearch_client.describe_domain(DomainName=domain["DomainName"])

        # Skip if there is an empty policy set
        if not describe_domain_response["DomainStatus"]["AccessPolicies"]:
            continue

        # Forward policy to validation
        validation_function(
            account_id=account_id,
            region=region,
            boto_session=boto_session,
            resource_type="AWS::OpenSearchService::Domain",
            resource_name=domain["DomainName"],
            resource_arn=describe_domain_response["DomainStatus"]["ARN"],
            policy_document=describe_domain_response["DomainStatus"]["AccessPolicies"],
            policy_type="RESOURCE_POLICY",
        )
