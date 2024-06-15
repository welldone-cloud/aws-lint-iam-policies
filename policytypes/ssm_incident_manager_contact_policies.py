import json


SOURCE_SERVICE = "ssm-contacts"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ssm_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    contacts_paginator = ssm_client.get_paginator("list_contacts")

    # Iterate all contacts
    for contacts_page in contacts_paginator.paginate():
        for contact in contacts_page["Contacts"]:
            # Fetch the contact policy
            get_contact_policy_response = ssm_client.get_contact_policy(ContactArn=contact["ContactArn"])

            # Skip if the contact does not have a policy configured
            if not json.loads(get_contact_policy_response["Policy"]):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::SSMContacts::Contact",
                resource_name=contact["DisplayName"],
                resource_arn=contact["ContactArn"],
                policy_document=get_contact_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
