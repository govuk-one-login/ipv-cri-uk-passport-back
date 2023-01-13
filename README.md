# Digital Identity IPV UK Passport CRI Backend

`di-ipv-cri-uk-passport-back`

This the back-end code for the UK Passport Credential Issuer(CRI) for the Identity Proofing and Verification (IPV) system within the GDS digital identity platform, GOV.UK Sign In.

## Environment variables

* IS_LOCAL - This only needs to be assigned when running locally. This is set to `true` in `local-startup`.
### DynamoDB table name variables:
Each environment has a specific table name prefix e.g. `dev-{dynamo-table-name}`

These values are automatically assigned by terraform within the `aws_lambda_function` resource
* ACCESS_TOKENS_TABLE_NAME
* AUTH_CODES_TABLE_NAME
* CRI_PASSPORT_CREDENTIALS_TABLE_NAME


## Pre-Commit Checking / Verification

Completely optional, there is a `.pre-commit-config.yaml` configuration setup in this repo, this uses [pre-commit](https://pre-commit.com/) to verify your commit before actually commiting, it runs the following checks:

* Check Json files for formatting issues
* Fixes end of file issues (it will auto correct if it spots an issue - you will need to run the git commit again after it has fixed the issue)
* It automatically removes trailing whitespaces (again will need to run commit again after it detects and fixes the issue)
* Detects aws credentials or private keys accidentally added to the repo
* runs cloud formation linter and detects issues
* runs checkov and checks for any issues.


### Dependency Installation
To use this locally you will first need to install the dependencies, this can be done in 2 ways:

#### Method 1 - Python pip

Run the following in a terminal:

```
sudo -H pip3 install checkov pre-commit cfn-lint
```

this should work across platforms

#### Method 2 - Brew

If you have brew installed please run the following:

```
brew install pre-commit ;\
brew install cfn-lint ;\
brew install checkov
```

### Post Installation Configuration
once installed run:
```
pre-commit install
```

To update the various versions of the pre-commit plugins, this can be done by running:

```
pre-commit autoupdate && pre-commit install
```

This will install / configure the pre-commit git hooks,  if it detects an issue while committing it will produce an output like the following:

```
 git commit -a
check json...........................................(no files to check)Skipped
fix end of files.........................................................Passed
trim trailing whitespace.................................................Passed
detect aws credentials...................................................Passed
detect private key.......................................................Passed
AWS CloudFormation Linter................................................Failed
- hook id: cfn-python-lint
- exit code: 4

W3011 Both UpdateReplacePolicy and DeletionPolicy are needed to protect Resources/PublicHostedZone from deletion
core/deploy/dns-zones/template.yaml:20:3

Checkov..............................................(no files to check)Skipped
- hook id: checkov
```

## Build

Build with `./gradlew`

## Deploy

### Prerequisites

See onboarding guide for instructions on how to setup the following command line interfaces (CLI)
- aws cli
- aws-vault
- sam cli
- gds cli

### Deploy to dev account

Any time you wish to deploy, run:

`gds aws di-ipv-cri-dev -- ./deploy.sh my-ukpassport-api-stack-name`

### Delete stack from dev account
> The stack name *must* be unique to you and created by you in the deploy stage above.
> Type `y`es when prompted to delete the stack and the folders in S3 bucket

The command to run is:

`gds aws di-ipv-cri-dev -- sam delete --config-env dev --stack-name <unique-stack-name>`