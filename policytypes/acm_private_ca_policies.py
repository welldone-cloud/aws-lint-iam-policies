def analyze(account_id, region, boto_session, boto_config, validation_function):
    acm_pca_client = boto_session.client("acm-pca", config=boto_config, region_name=region)
    certificate_authorities_paginator = acm_pca_client.get_paginator("list_certificate_authorities")

    # Iterate all private CAs
    for certificate_authorities_page in certificate_authorities_paginator.paginate():
        for certificate_authority in certificate_authorities_page["CertificateAuthorities"]:
            # Fetch the private CA policy
            try:
                get_policy_response = acm_pca_client.get_policy(ResourceArn=certificate_authority["Arn"])
            except acm_pca_client.exceptions.from_code("ResourceNotFoundException"):
                # Skip if there is no policy set
                continue

            # Use the CA ID if it does not have a common name configured
            try:
                ca_name = certificate_authority["CertificateAuthorityConfiguration"]["Subject"]["CommonName"]
            except KeyError:
                ca_name = certificate_authority["Arn"].split("/")[-1]

            # Forward policy to validation
            validation_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::ACMPCA::CertificateAuthority",
                resource_name=ca_name,
                resource_arn=certificate_authority["Arn"],
                policy_document=get_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
