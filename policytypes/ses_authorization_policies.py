SOURCE_SERVICE = "ses"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ses_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    identities_paginator = ses_client.get_paginator("list_identities")

    # Iterate all identities
    for identities_page in identities_paginator.paginate():
        for identity_name in identities_page["Identities"]:
            # Fetch the list of policies attached to this identity
            list_identity_policies_response = ses_client.list_identity_policies(Identity=identity_name)

            # Fetch each policy document
            for policy_name in list_identity_policies_response["PolicyNames"]:
                get_identity_policies_response = ses_client.get_identity_policies(
                    Identity=identity_name, PolicyNames=[policy_name]
                )

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    boto_session=boto_session,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::SES::EmailIdentity",
                    resource_name="{}:{}".format(identity_name, policy_name),
                    resource_arn="arn:aws:ses:{}:{}:identity/{}".format(region, account_id, identity_name),
                    policy_document=get_identity_policies_response["Policies"][policy_name],
                    policy_type="RESOURCE_POLICY",
                )
