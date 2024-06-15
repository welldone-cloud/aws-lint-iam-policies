SOURCE_SERVICE = "opensearch"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    opensearch_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all OpenSearch domains
    list_domain_names_response = opensearch_client.list_domain_names()
    for domain in list_domain_names_response["DomainNames"]:
        describe_domain_response = opensearch_client.describe_domain(DomainName=domain["DomainName"])

        # Skip if there is an empty policy set
        if not describe_domain_response["DomainStatus"]["AccessPolicies"]:
            continue

        policy_analysis_function(
            account_id=account_id,
            region=region,
            boto_session=boto_session,
            source_service=SOURCE_SERVICE,
            resource_type="AWS::OpenSearchService::Domain",
            resource_name=domain["DomainName"],
            resource_arn=describe_domain_response["DomainStatus"]["ARN"],
            policy_document=describe_domain_response["DomainStatus"]["AccessPolicies"],
            policy_type="RESOURCE_POLICY",
        )
