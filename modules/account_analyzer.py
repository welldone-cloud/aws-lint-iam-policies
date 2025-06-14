import botocore.exceptions
import concurrent.futures
import os
import traceback

import modules.policy_types

from modules.policy_analyzer import PolicyAnalyzer
from modules.policy_types import *


THREADS_PER_CPU_AVAILABLE = 4


class AccountAnalyzer:

    def __init__(
        self,
        account_id,
        boto_session,
        boto_config,
        result_collector,
        trusted_accounts,
        exclude_policy_types,
        include_policy_types,
        exclude_regions,
        include_regions,
    ):
        self._account_id = account_id
        self._boto_session = boto_session
        self._boto_config = boto_config
        self._result_collector = result_collector
        self._trusted_accounts = trusted_accounts
        self._exclude_policy_types = exclude_policy_types
        self._include_policy_types = include_policy_types
        self._exclude_regions = exclude_regions
        self._include_regions = include_regions

    def _get_ram_resource_types_used_in_region(self, region, ram_resource_types_per_region):
        ram_resource_types_per_region[region] = set()
        ram_client = self._boto_session.client("ram", config=self._boto_config, region_name=region)
        resources_paginator = ram_client.get_paginator("list_resources")
        try:
            for resource_page in resources_paginator.paginate(resourceOwner="SELF"):
                for resource in resource_page["resources"]:
                    ram_resource_types_per_region[region].add(resource["type"])
        except botocore.exceptions.ClientError as ex:
            self._result_collector.submit_error(
                "Error for account ID {}, region {}: Cannot communicate with AWS RAM service: {} ({})".format(
                    self._account_id,
                    region,
                    ex.response["Error"]["Code"],
                    ex.response["Error"]["Message"],
                )
            )

    def analyze_account(self):
        # Get all regions enabled in the account and determine the actual target regions
        ec2_client = self._boto_session.client("ec2", config=self._boto_config)
        try:
            describe_regions_response = ec2_client.describe_regions(AllRegions=False)
        except botocore.exceptions.ClientError:
            self._result_collector.submit_error(
                "Error for account ID {}: cannot read enabled regions, skipping account".format(self._account_id)
            )
            return
        target_regions = []
        for region in sorted([region["RegionName"] for region in describe_regions_response["Regions"]]):
            if region in self._exclude_regions:
                continue
            if self._include_regions and region not in self._include_regions:
                continue
            target_regions.append(region)

        # Iterate resources shared via RAM for each region and collect their RAM resource types. This allows to later
        # skip policy type implementations that use RAM, if there are anyhow no such resources in a certain region.
        print("Analyzing account ID {}".format(self._account_id))
        ram_resource_types_per_region = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(target_regions)) as executor:
            for region in target_regions:
                executor.submit(self._get_ram_resource_types_used_in_region, region, ram_resource_types_per_region)

        # Iterate all policy types and target regions and trigger analysis for applicable combinations that are
        # also allowed by include and exclude arguments
        policy_analyzer = PolicyAnalyzer(
            self._boto_session, self._boto_config, self._result_collector, self._trusted_accounts
        )
        futures = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() * THREADS_PER_CPU_AVAILABLE) as executor:
            for policy_type in PolicyAnalyzer.get_supported_policy_types():
                if policy_type in self._exclude_policy_types:
                    continue
                if self._include_policy_types and policy_type not in self._include_policy_types:
                    continue

                policy_type_implementation = getattr(modules.policy_types, policy_type)
                for region in target_regions:
                    if policy_type_implementation.RUN_IN_REGION not in ("ALL", region):
                        continue
                    if policy_type_implementation.SOURCE_SERVICE == "ram":
                        if policy_type_implementation.RAM_RESOURCE_TYPE not in ram_resource_types_per_region[region]:
                            continue

                    # Submit future
                    future_params = {
                        "account_id": self._account_id,
                        "region": region,
                        "boto_session": self._boto_session,
                        "boto_config": self._boto_config,
                        "policy_analysis_function": policy_analyzer.analyze_policy,
                    }
                    future = executor.submit(policy_type_implementation.analyze, **future_params)
                    future_params["policy_type"] = policy_type
                    futures[future] = future_params

            # Show status and process any errors that occurred
            futures_completed = 0
            for future in concurrent.futures.as_completed(futures.keys()):
                futures_completed += 1
                print("{}%".format(int(futures_completed * 100 / len(futures))), end="\r")

                try:
                    future.result()
                except (botocore.exceptions.EndpointConnectionError, botocore.exceptions.ConnectTimeoutError):
                    # Ignore errors when an AWS service is not available in a certain region
                    pass
                except botocore.exceptions.ClientError as ex:
                    # Log expected errors such as a lack of permissions, regions/services denied by SCPs, etc.
                    self._result_collector.submit_error(
                        "Error for account ID {}, region {}, policy type {}: {} ({})".format(
                            self._account_id,
                            futures[future]["region"],
                            futures[future]["policy_type"],
                            ex.response["Error"]["Code"],
                            ex.response["Error"]["Message"].strip(),
                        )
                    )
                except Exception as ex:
                    # Log all remaining and unexpected errors and print stack trace details
                    msg = "Uncaught exception for account ID {}, region {}, policy type {}: {}. "
                    msg += "Please report this as an issue along with the stack trace information."
                    self._result_collector.submit_error(
                        msg.format(
                            self._account_id,
                            futures[future]["region"],
                            futures[future]["policy_type"],
                            ex.__class__.__name__,
                        )
                    )
                    print(traceback.format_exc())
