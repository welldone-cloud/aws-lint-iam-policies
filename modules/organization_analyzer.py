import boto3
import botocore.exceptions

from modules.account_analyzer import AccountAnalyzer


class OrganizationAnalyzer:
    def __init__(
        self,
        organization_description,
        member_accounts_role,
        boto_session,
        boto_config,
        result_collector,
        exclude_policy_types,
        include_policy_types,
        exclude_regions,
        include_regions,
        exclude_accounts,
        include_accounts,
        exclude_ous,
        include_ous,
    ):
        self._organization_id = organization_description["Organization"]["Id"]
        self._management_account_id = organization_description["Organization"]["MasterAccountId"]
        self._member_accounts_role = member_accounts_role
        self._boto_session = boto_session
        self._boto_config = boto_config
        self._result_collector = result_collector
        self._exclude_policy_types = exclude_policy_types
        self._include_policy_types = include_policy_types
        self._exclude_regions = exclude_regions
        self._include_regions = include_regions
        self._exclude_accounts = exclude_accounts
        self._include_accounts = include_accounts
        self._exclude_ous = exclude_ous
        self._include_ous = include_ous
        self._organizations_parents = {}

    def _get_organizations_parents(self, organizations_client, child_id):
        try:
            return self._organizations_parents[child_id]
        except KeyError:
            all_parents = []
            direct_parent = organizations_client.list_parents(ChildId=child_id)["Parents"][0]
            all_parents.append(direct_parent["Id"])
            if direct_parent["Type"] != "ROOT":
                all_parents.extend(self._get_organizations_parents(organizations_client, direct_parent["Id"]))
            self._organizations_parents[child_id] = all_parents
            return all_parents

    def analyze_organization(self):
        print(
            "Analyzing organization ID {} under management account ID {}".format(
                self._organization_id, self._management_account_id
            )
        )
        organizations_client = self._boto_session.client("organizations", config=self._boto_config)
        sts_client = self._boto_session.client(
            "sts",
            config=self._boto_config,
            endpoint_url="https://sts.{}.amazonaws.com".format(self._boto_session.region_name),
        )

        # Iterate all accounts of the Organization
        accounts_paginator = organizations_client.get_paginator("list_accounts")
        for accounts_page in accounts_paginator.paginate():
            for account in accounts_page["Accounts"]:
                account_id = account["Id"]

                # Skip accounts that should not be targeted because of include or exclude arguments
                if account_id in self._exclude_accounts:
                    continue
                if self._include_accounts and account_id not in self._include_accounts:
                    continue
                if self._exclude_ous or self._include_ous:
                    organizations_parents = self._get_organizations_parents(organizations_client, account_id)
                    if self._exclude_ous and any(ou in self._exclude_ous for ou in organizations_parents):
                        continue
                    if self._include_ous and all(ou not in self._include_ous for ou in organizations_parents):
                        continue

                # Skip accounts that are not active
                if account["Status"] != "ACTIVE":
                    self._result_collector.submit_error(
                        "Error for account ID {}: account status is not active".format(account_id)
                    )
                    continue

                # Assume the provided role in the account, except for when we are currently analyzing the management
                # account itself
                if account_id == self._management_account_id:
                    account_session = self._boto_session
                else:
                    try:
                        assume_role_response = sts_client.assume_role(
                            RoleArn="arn:aws:iam::{}:role/{}".format(account_id, self._member_accounts_role),
                            RoleSessionName="aws-lint-iam-policies",
                        )
                    except botocore.exceptions.ClientError:
                        self._result_collector.submit_error(
                            "Error for account ID {}: cannot assume specified member accounts role".format(account_id)
                        )
                        continue
                    account_session = boto3.Session(
                        aws_access_key_id=assume_role_response["Credentials"]["AccessKeyId"],
                        aws_secret_access_key=assume_role_response["Credentials"]["SecretAccessKey"],
                        aws_session_token=assume_role_response["Credentials"]["SessionToken"],
                        region_name=self._boto_session.region_name,
                    )

                # Run account analysis
                account_analyzer = AccountAnalyzer(
                    account_id,
                    account_session,
                    self._boto_config,
                    self._result_collector,
                    self._exclude_policy_types,
                    self._include_policy_types,
                    self._exclude_regions,
                    self._include_regions,
                )
                account_analyzer.analyze_account()
