# aws-lint-iam-policies

Runs IAM policy linting and security checks against either a single AWS account or a set of member accounts of an AWS Organization. Stores all supported identity-based and resource-based policies to a local directory and reports on those that may violate security best practices or contain errors. 

The script makes use of three mechanisms:

1. AWS IAM Access Analyzer policy validation, which is mostly known for showing recommendations when manually editing IAM policies on the AWS Console UI. The checks are created and maintained by AWS and are described closer [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html).
![](./doc/access_analyzer_console.png)

2. AWS IAM Access Analyzer checks for public access, which test whether resource-based policies grant unrestricted public access (e.g., to S3 buckets, SQS queues, etc.). This is closer described [here](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckNoPublicAccess.html).

3. Custom policy checks that report on trust relationships to other AWS accounts and to identity providers. Please note that these are only basic checks. They neither make use of automated reasoning nor evaluate the meaning of policy conditions.



## Usage

Make sure you have AWS credentials configured for your target environment. This can either be done using [environment 
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html) or by specifying a [named 
profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) in the optional `--profile` 
argument.

* If your are running the script against a single AWS account, you require at least [these permissions](resources/permissions_scope_account.json). 

* If you are running the script against a set of member accounts of an AWS Organization, you must use credentials that belong to the Organizations management account and have at least [these permissions](resources/permissions_scope_organization.json). The member accounts need to have an IAM role configured that can be assumed from the Organizations management account. In many cases, there is the default `OrganizationAccountAccessRole` available. When the script assumes the role you specify, it will automatically drop its permissions to only those that are required. 

By default, all supported policy types and all regions are analyzed in the targeted AWS account(s). See the list of supported arguments below, in case you want to reduce coverage.

Install dependencies:

```bash
pip install -r requirements.txt
```

Example invocations:

```bash
python aws_lint_iam_policies.py --scope ACCOUNT

python aws_lint_iam_policies.py --scope ACCOUNT --include-policy-types s3_bucket_policies,kms_key_policies

python aws_lint_iam_policies.py --scope ORGANIZATION --member-accounts-role OrganizationAccountAccessRole

python aws_lint_iam_policies.py --scope ORGANIZATION --member-accounts-role OrganizationAccountAccessRole --exclude-accounts 112233445566,998877665544
```



## Supported arguments
```
--list-policy-types
    list all supported policy types and exit
--scope {ACCOUNT,ORGANIZATION}
    target either an individual account or all accounts of an AWS Organization
--member-accounts-role MEMBER_ACCOUNTS_ROLE
    IAM role name present in member accounts that can be assumed from the Organizations management account
--profile PROFILE
    named AWS profile to use
--result-name RESULT_NAME
    result name to use instead of the run timestamp
--trusted-account-ids TRUSTED_ACCOUNT_IDS
    list of comma-separated account IDs that should not be reported in trusted outside principal findings
--exclude-policy-types EXCLUDE_POLICY_TYPES
    do not target the specified comma-separated list of policy types
--include-policy-types INCLUDE_POLICY_TYPES
    only target the specified comma-separated list of policy types
--exclude-regions EXCLUDE_REGIONS
    do not target the specified comma-separated list of regions
--include-regions INCLUDE_REGIONS
    only target the specified comma-separated list of regions
--exclude-accounts EXCLUDE_ACCOUNTS
    do not target the specified comma-separated list of account IDs
--include-accounts INCLUDE_ACCOUNTS
    only target the specified comma-separated list of account IDs
--exclude-ous EXCLUDE_OUS
    do not target the specified comma-separated list of Organizations OU IDs
--include-ous INCLUDE_OUS
    only target the specified comma-separated list of Organizations OU IDs
--exclude-finding-issue-codes EXCLUDE_FINDING_ISSUE_CODES
    do not report the specified comma-separated list of finding issue codes
--include-finding-issue-codes INCLUDE_FINDING_ISSUE_CODES
    only report the specified comma-separated list of finding issue codes
```



## Example results

Results are written both to a JSON file ([see example](doc/example_results.json)) and an HTML file ([see example](https://welldone.cloud/resources/aws-lint-iam-policies/example_results.html)).




## Supported policy types
The following IAM policy types are analyzed:

* ACM private CA policies
* API Gateway custom domain name policies
* API Gateway custom domain name private domain policies
* API Gateway REST API policies
* App Mesh mesh policies
* AppSync GraphQL API policies
* Backup vault policies
* Bedrock custom model policies
* Cloud WAN core network policies
* CloudHSM backup policies
* CloudTrail channel policies
* CloudWatch Logs delivery destination policies
* CloudWatch Logs destination policies
* CloudWatch Logs resource policies
* CodeArtifact domain policies
* CodeArtifact repository policies
* CodeBuild build project policies
* CodeBuild report group policies
* DataZone domain policies
* DynamoDB stream policies
* DynamoDB table policies
* EC2 capacity reservation policies
* EC2 CoIP pool policies
* EC2 dedicated host policies
* EC2 Image Builder component policies
* EC2 Image Builder container recipe policies
* EC2 Image Builder image policies
* EC2 Image Builder image recipe policies
* EC2 placement group policies
* ECR private registry policies
* ECR private repository policies
* ECR public repository policies
* EFS file system policies
* Elemental MediaStore container policies
* End User Messaging opt-out list policies
* End User Messaging phone number policies
* End User Messaging pool policies
* End User Messaging sender ID policies
* EventBridge event bus policies
* EventBridge schema registry policies
* FSx volume policies
* Glacier vault lock policies
* Glacier vault resource policies
* Glue data catalog policies
* Glue database policies
* Glue table policies
* IAM Identity Center application policies
* IAM Identity Center permission set inline policies
* IAM group inline policies
* IAM managed policies
* IAM role inline policies
* IAM role trust policies
* IAM user inline policies
* IoT core policies
* Kinesis data stream consumer policies
* Kinesis data stream policies
* KMS key policies
* Lambda function policies
* Lambda layer policies
* Lex bot alias policies
* Lex bot policies
* License Manager license configuration policies
* Marketplace Catalog entity policies
* Migration Hub Refactor Spaces environment policies
* Network Firewall firewall policies
* Network Firewall rule group policies
* OpenSearch domain policies
* Organizations delegation policies
* Organizations resource control policies
* Organizations service control policies
* Outposts local gateway route table policies
* Outposts outpost policies
* Outposts site policies
* RDS Aurora cluster policies
* Redshift serverless snapshot policies
* Rekognition custom labels project policies
* Resource Explorer view policies
* Resource Groups group policies
* Route53 Application Recovery Controller cluster policies
* Route53 Profiles profile policies
* Route53 Resolver firewall rule group policies
* Route53 Resolver resolver rule policies
* Route53 Resolver resolver query log config policies
* S3 access grants instance policies
* S3 access point policies
* S3 bucket policies
* S3 directory bucket policies
* S3 multi-region access point policies
* S3 object Lambda access point policies
* S3 on Outposts access point policies
* S3 on Outposts bucket policies
* SageMaker feature group catalog policies
* SageMaker feature group policies
* SageMaker hub policies
* SageMaker lineage group policies
* SageMaker model card policies
* SageMaker model package group policies
* SageMaker pipeline policies
* Secrets manager secret policies
* Security Hub product subscription policies
* Service Catalog AppRegistry application policies
* Service Catalog AppRegistry attribute group policies
* SES authorization policies
* SNS topic policies
* SQS queue policies
* SSM Incident Manager contact policies
* SSM Incident Manager response plan policies
* SSM OpsCenter OpsItemGroup resource policies
* SSM Parameter Store parameter policies
* Verified Access group policies
* VPC endpoint policies
* VPC IPAM pool policies
* VPC IPAM resource discovery policies
* VPC Lattice resource configuration policies
* VPC Lattice service auth policies
* VPC Lattice service network auth policies
* VPC Lattice service network policies
* VPC Lattice service policies
* VPC prefix list policies
* VPC security group policies
* VPC subnet policies
* VPC Traffic Mirroring target policies
* VPC Transit Gateway multicast domain policies
* VPC Transit Gateway policies



## Notes

* The provided minimum IAM permissions exceed the policy size limit for IAM user inline policies (2048 characters). Consider using managed policies or roles instead, which have higher policy size limits.

* The script can only lint policies that are using the AWS IAM policy language. It is not capable of linting other policy languages, such as Cedar policies (as used in AWS Verified Access and AWS Verified Permissions, for example).
