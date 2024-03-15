import json


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ram_client = boto_session.client("ram", config=boto_config, region_name=region)

    # Iterate all permissions (there is unfortunately no paginator available for this at the moment)
    call_params = {"permissionType": "CUSTOMER_MANAGED"}
    while True:
        list_permissions_response = ram_client.list_permissions(**call_params)
        for permission in list_permissions_response["permissions"]:
            # Fetch the policy stub behind the permission
            get_permission_response = ram_client.get_permission(permissionArn=permission["arn"])
            policy_statement = json.loads(get_permission_response["permission"]["permission"])

            # RAM permissions only store the statement part of an IAM policy.
            # They thus need to be embedded before linting.
            policy = json.dumps({"Version": "2012-10-17", "Statement": policy_statement})

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::RAM::Permission",
                resource_name=permission["name"],
                resource_arn=permission["arn"],
                policy_document=policy,
                policy_type="RESOURCE_POLICY",
                ignore_finding_issue_codes=["MISSING_PRINCIPAL"],
            )

        try:
            call_params["NextToken"] = list_permissions_response["NextToken"]
        except KeyError:
            break
