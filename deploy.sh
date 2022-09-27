#!/usr/bin/env bash
set -eu
./gradlew clean build
./gradlew buildzip
sam validate -t infrastructure/lambda/template.yaml --config-env dev
sam build -t infrastructure/lambda/template.yaml --config-env dev
sam deploy --config-file samconfig.toml --no-fail-on-empty-changeset -t infrastructure/lambda/template.yaml --config-env dev