import datetime
import html
import jinja2
import json
import os
import pandas
import pathlib
import plotly.express
import re
import shutil
import string
import sys


RESULTS_DIRECTORY_NAME = "results"

RESULTS_FILE_JSON_NAME = "results_{}.json"

RESULTS_FILE_HTML_NAME = "results_{}.html"

RESULTS_FILE_HTML_TEMPLATE_PATH = os.path.join(
    pathlib.Path(__file__).parent.parent, "resources", "results_html_template.jinja2"
)

POLICIES_DIRECTORY_NAME = "policies_{}"

TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"

VALID_FILE_NAME_CHARACTERS = string.ascii_letters + string.digits + "_+=,.@-"


class ResultCollector:

    @staticmethod
    def _get_div_element_for_plotly_figure(figure):
        return plotly.offline.plot(figure, include_plotlyjs=False, config={"displayModeBar": False}, output_type="div")

    @staticmethod
    def _get_treemap_chart_html(data, path, values):
        figure = plotly.express.treemap(data, path=path, values=values)
        figure.update_traces(root_color="lightgrey", hovertemplate="category=%{label}<br />count=%{value}")
        figure.update_layout(
            margin=dict(t=25, l=30, r=70, b=10),
            showlegend=False,
            font=dict(family="Verdana"),
        )
        return ResultCollector._get_div_element_for_plotly_figure(figure)

    @staticmethod
    def _get_bar_chart_html(data, x_axis, y_axis):
        figure = plotly.express.bar(data, x=x_axis, y=y_axis, color=x_axis)
        figure.update_layout(
            xaxis=dict(title=None, fixedrange=True),
            yaxis=dict(title=dict(text=y_axis), fixedrange=True),
            margin=dict(t=25, l=90, r=70, b=10),
            showlegend=False,
            font=dict(family="Verdana"),
        )
        return ResultCollector._get_div_element_for_plotly_figure(figure)

    @staticmethod
    def _get_pie_chart_html(data, names, values):
        figure = plotly.express.pie(data, names=names, values=values)
        figure.update_traces(textinfo="label+percent")
        figure.update_layout(
            margin=dict(t=25, l=30, r=70, b=10),
            showlegend=False,
            font=dict(family="Verdana"),
        )
        return ResultCollector._get_div_element_for_plotly_figure(figure)

    def __init__(
        self, account_id, principal, scope, exclude_finding_issue_codes, include_finding_issue_codes, result_name
    ):
        self._exclude_finding_issue_codes = exclude_finding_issue_codes
        self._include_finding_issue_codes = include_finding_issue_codes
        run_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(TIMESTAMP_FORMAT)
        self._result_name = result_name if result_name else run_timestamp
        self._json_policies = {}

        # Ensure the results directory exists
        self._results_directory = os.path.join(pathlib.Path(__file__).parent.parent, RESULTS_DIRECTORY_NAME)
        try:
            os.mkdir(self._results_directory)
        except FileExistsError:
            pass

        # If result files with the same name already exists, remove them
        for results_file_name in (
            RESULTS_FILE_JSON_NAME.format(self._result_name),
            RESULTS_FILE_HTML_NAME.format(self._result_name),
        ):
            try:
                os.remove(os.path.join(self._results_directory, results_file_name))
            except FileNotFoundError:
                pass

        # Create the policies directory or replace it, if it already exists
        self._policies_directory = os.path.join(
            self._results_directory, POLICIES_DIRECTORY_NAME.format(self._result_name)
        )
        try:
            os.mkdir(self._policies_directory)
        except FileExistsError:
            shutil.rmtree(self._policies_directory)
            os.mkdir(self._policies_directory)

        # Prepare the result collection JSON structure
        self._result_collection = {
            "_metadata": {
                "invocation": " ".join(sys.argv),
                "account_id": account_id,
                "principal": principal,
                "scope": scope,
                "run_timestamp": run_timestamp,
                "number_of_policies_analyzed": 0,
                "number_of_results_collected": 0,
                "errors": [],
            },
            "results": [],
        }

    def _write_json_result_file(self):
        json_file_name = os.path.join(self._results_directory, RESULTS_FILE_JSON_NAME.format(self._result_name))
        with open(json_file_name, "w") as out_file:
            json.dump(self._result_collection, out_file, indent=2)

    def _write_html_result_file(self):
        unique_finding_issue_codes = []
        unique_account_ids = []
        results_by_finding_issue_code = None
        results_by_resource_type = None
        results_by_account_id = None
        results_by_region = None
        json_policies_html_encoded = {}

        if self._result_collection["results"]:
            results_df = pandas.DataFrame(self._result_collection["results"])
            unique_finding_issue_codes = sorted(results_df["finding_issue_code"].unique())
            unique_account_ids = sorted(results_df["account_id"].unique())

            # Create figure "results by finding_issue_code"
            results_by_finding_issue_code_df = (
                results_df.groupby(["finding_type", "finding_issue_code"])
                .size()
                .reset_index()
                .rename(columns={0: "count"})
            )
            results_by_finding_issue_code = ResultCollector._get_treemap_chart_html(
                results_by_finding_issue_code_df,
                [plotly.express.Constant("ALL"), "finding_type", "finding_issue_code"],
                "count",
            )

            # Create figure "results by resource_type"
            results_by_resource_type_df = (
                results_df["resource_type"]
                .value_counts()
                .reset_index()
                .rename(columns={"index": "resource_type", 0: "count"})
            )
            results_by_resource_type = ResultCollector._get_bar_chart_html(
                results_by_resource_type_df, "resource_type", "count"
            )

            # Create figure "results by account_id"
            results_by_account_id_df = (
                results_df["account_id"]
                .value_counts()
                .reset_index()
                .rename(columns={"index": "account_id", 0: "count"})
            )
            results_by_account_id = ResultCollector._get_pie_chart_html(
                results_by_account_id_df,
                "account_id",
                "count",
            )

            # Create figure "results by region"
            results_by_region_df = (
                results_df["region"].value_counts().reset_index().rename(columns={"index": "region", 0: "count"})
            )
            results_by_region = ResultCollector._get_bar_chart_html(results_by_region_df, "region", "count")

            # Prepare JSON policies for embedding into HTML
            json_policies_html_encoded = {
                key: html.escape(self._json_policies[key])
                for key in self._json_policies
                if key in set(results_df["policy_file_name"])
            }

        # Render HTML template and write output
        with open(RESULTS_FILE_HTML_TEMPLATE_PATH) as template_file:
            jinja_template = jinja2.Template(
                template_file.read(),
                autoescape=True,
                trim_blocks=True,
                lstrip_blocks=True,
            )
        html_file_name = os.path.join(self._results_directory, RESULTS_FILE_HTML_NAME.format(self._result_name))
        with open(html_file_name, "w") as out_file:
            out_file.write(
                jinja_template.render(
                    invocation=self._result_collection["_metadata"]["invocation"],
                    account_id=self._result_collection["_metadata"]["account_id"],
                    principal=self._result_collection["_metadata"]["principal"],
                    scope=self._result_collection["_metadata"]["scope"],
                    run_timestamp=self._result_collection["_metadata"]["run_timestamp"],
                    number_of_policies_analyzed=self._result_collection["_metadata"]["number_of_policies_analyzed"],
                    number_of_results_collected=self._result_collection["_metadata"]["number_of_results_collected"],
                    errors=self._result_collection["_metadata"]["errors"],
                    results_by_finding_issue_code=results_by_finding_issue_code,
                    results_by_resource_type=results_by_resource_type,
                    results_by_account_id=results_by_account_id,
                    results_by_region=results_by_region,
                    unique_finding_issue_codes=unique_finding_issue_codes,
                    unique_account_ids=unique_account_ids,
                    results=self._result_collection["results"],
                    json_policies=json_policies_html_encoded,
                )
            )

    def submit_error(self, msg):
        print(msg)
        self._result_collection["_metadata"]["errors"].append(msg.strip())

    def submit_policy(self, policy_descriptor, policy_document):
        policy_document = json.dumps(json.loads(policy_document), indent=2)
        self._result_collection["_metadata"]["number_of_policies_analyzed"] += 1

        # Some AWS resources can have multiple policies attached or are allowed to have the same name, while using
        # different IDs. An index is thus put at the end of the file name to handle collisions.
        file_index = 0
        while True:
            policy_file_name = "{}_{}_{}_{}_{}_{}.json".format(
                policy_descriptor["account_id"],
                policy_descriptor["region"],
                policy_descriptor["source_service"],
                policy_descriptor["resource_type"],
                policy_descriptor["resource_name"],
                file_index,
            )
            policy_file_name = re.sub(
                "_+",
                "_",
                "".join(char if char in VALID_FILE_NAME_CHARACTERS else "_" for char in policy_file_name),
            )
            policy_file = os.path.join(self._policies_directory, policy_file_name)
            if os.path.isfile(policy_file):
                file_index += 1
                continue
            break

        # Write policy document to file
        with open(policy_file, "w") as out_file:
            out_file.write(policy_document)

        # Keep a copy of the policy document in memory
        self._json_policies[policy_file_name] = policy_document

        return policy_file_name

    def submit_result(self, result, disabled_finding_issue_codes):
        # Skip if finding issue code should not be reported, either because set forth by the policy type implementation
        # or because of include or exclude arguments
        finding_issue_code = result["finding_issue_code"]
        if finding_issue_code in disabled_finding_issue_codes:
            return
        if finding_issue_code in self._exclude_finding_issue_codes:
            return
        if self._include_finding_issue_codes and finding_issue_code not in self._include_finding_issue_codes:
            return

        self._result_collection["results"].append(result)
        self._result_collection["_metadata"]["number_of_results_collected"] += 1

    def write_result_files(self):
        self._result_collection["results"].sort(
            key=lambda val: (
                val["account_id"],
                val["region"],
                val["source_service"],
                val["resource_type"],
                val["resource_name"],
            )
        )
        self._write_json_result_file()
        self._write_html_result_file()
