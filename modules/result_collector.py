import datetime
import json
import os
import pathlib
import re
import string
import sys


RESULTS_DIRECTORY_NAME = "results"

TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"

VALID_FILE_NAME_CHARACTERS = string.ascii_letters + string.digits + "_+=,.@-"


class ResultCollector:

    @staticmethod
    def _get_results_directory_path():
        return os.path.join(pathlib.Path(__file__).parent.parent, RESULTS_DIRECTORY_NAME)

    def __init__(self, account_id, principal, scope, exclude_finding_issue_codes, include_finding_issue_codes):
        self._run_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(TIMESTAMP_FORMAT)
        self._exclude_finding_issue_codes = exclude_finding_issue_codes
        self._include_finding_issue_codes = include_finding_issue_codes

        # Prepare result collection JSON structure
        self._result_collection = {
            "_metadata": {
                "invocation": " ".join(sys.argv),
                "accountid": account_id,
                "principal": principal,
                "scope": scope,
                "run_timestamp": self._run_timestamp,
                "stats": {
                    "number_of_policies_analyzed": 0,
                    "number_of_results_collected": 0,
                },
                "errors": [],
            },
            "results": {},
        }

        # Ensure results directory exists
        try:
            os.mkdir(ResultCollector._get_results_directory_path())
        except FileExistsError:
            pass

    def submit_error(self, msg):
        print(msg)
        self._result_collection["_metadata"]["errors"].append(msg.strip())

    def submit_policy(self, policy_descriptor, policy_document):
        self._result_collection["_metadata"]["stats"]["number_of_policies_analyzed"] += 1

        # Ensure the policy dump directory exists
        policy_dump_directory = os.path.join(
            ResultCollector._get_results_directory_path(), "policy_dump_{}".format(self._run_timestamp)
        )
        try:
            os.mkdir(policy_dump_directory)
        except FileExistsError:
            pass

        # Some AWS resources can have multiple policies attached or are allowed to have the same name, while using
        # different IDs. An index is thus put at the end of the file name to handle collisions.
        file_index = 0
        while True:
            policy_dump_file_name = "{}_{}_{}_{}_{}_{}.json".format(
                policy_descriptor["account_id"],
                policy_descriptor["region"],
                policy_descriptor["source_service"],
                policy_descriptor["resource_type"],
                policy_descriptor["resource_name"],
                file_index,
            )
            policy_dump_file_name = re.sub(
                "_+",
                "_",
                "".join(char if char in VALID_FILE_NAME_CHARACTERS else "_" for char in policy_dump_file_name),
            )
            policy_dump_file_path = os.path.join(policy_dump_directory, policy_dump_file_name)
            if os.path.isfile(policy_dump_file_path):
                file_index += 1
                continue
            break

        # Write policy document to file
        with open(policy_dump_file_path, "w") as out_file:
            json.dump(json.loads(policy_document), out_file, indent=2)
        return policy_dump_file_name

    def submit_result(self, policy_descriptor, finding_descriptor, disabled_finding_issue_codes):
        finding_issue_code = finding_descriptor["finding_issue_code"]

        # Skip if finding issue code should not be reported, either because set forth by the policy type implementation
        # or because of include or exclude arguments
        if finding_issue_code in disabled_finding_issue_codes:
            return
        if finding_issue_code in self._exclude_finding_issue_codes:
            return
        if self._include_finding_issue_codes and finding_issue_code not in self._include_finding_issue_codes:
            return

        result = {**policy_descriptor, **finding_descriptor}
        finding_type = finding_descriptor["finding_type"]
        self._result_collection["_metadata"]["stats"]["number_of_results_collected"] += 1

        # Add to results
        try:
            self._result_collection["results"][finding_type][finding_issue_code].append(result)
        except KeyError:
            if finding_type not in self._result_collection["results"]:
                self._result_collection["results"][finding_type] = {}
            self._result_collection["results"][finding_type][finding_issue_code] = [result]

    def write_result_collection_file(self):
        result_collection_file = os.path.join(
            ResultCollector._get_results_directory_path(), "policy_linting_results_{}.json".format(self._run_timestamp)
        )
        with open(result_collection_file, "w") as out_file:
            json.dump(self._result_collection, out_file, indent=2)
