import json


def analyze(account_id, region, boto_session, boto_config, validation_function):
    ssm_client = boto_session.client("ssm-contacts", config=boto_config, region_name=region)
    contacts_paginator = ssm_client.get_paginator("list_contacts")

    # Iterate all contacts
    for contacts_page in contacts_paginator.paginate():
        for contact in contacts_page["Contacts"]:
            # Fetch the contact policy
            get_contact_policy_response = ssm_client.get_contact_policy(ContactArn=contact["ContactArn"])

            # Skip if the contact does not have a policy configured
            if not json.loads(get_contact_policy_response["Policy"]):
                continue

            # Forward policy to validation
            validation_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::SSMContacts::Contact",
                resource_name=contact["DisplayName"],
                resource_arn=contact["ContactArn"],
                policy_document=get_contact_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
