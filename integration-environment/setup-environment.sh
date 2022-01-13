#!/usr/bin/env bash

set -euo pipefail

cat << 'EOF'
██╗███╗   ██╗████████╗███████╗ ██████╗ ██████╗  █████╗ ████████╗██╗ ██████╗ ███╗   ██╗    ████████╗███████╗███████╗████████╗███████╗
██║████╗  ██║╚══██╔══╝██╔════╝██╔════╝ ██╔══██╗██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝
██║██╔██╗ ██║   ██║   █████╗  ██║  ███╗██████╔╝███████║   ██║   ██║██║   ██║██╔██╗ ██║       ██║   █████╗  ███████╗   ██║   ███████╗
██║██║╚██╗██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██╔══██║   ██║   ██║██║   ██║██║╚██╗██║       ██║   ██╔══╝  ╚════██║   ██║   ╚════██║
██║██║ ╚████║   ██║   ███████╗╚██████╔╝██║  ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║       ██║   ███████╗███████║   ██║   ███████║
╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝

 █████╗ ██████╗ ███████╗     ██████╗  ██████╗
██╔══██╗██╔══██╗██╔════╝    ██╔════╝ ██╔═══██╗
███████║██████╔╝█████╗      ██║  ███╗██║   ██║
██╔══██║██╔══██╗██╔══╝      ██║   ██║██║   ██║
██║  ██║██║  ██║███████╗    ╚██████╔╝╚██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝     ╚═════╝  ╚═════╝

EOF

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

trap "rm -f ${SCRIPT_DIR}/terraform.tfstate*" EXIT

docker ps -q --filter "name=localstack-integration-tests" | grep -q . && docker stop localstack-integration-tests
docker run -d \
           --rm \
           --name localstack-integration-tests \
           --env SERVICES=dynamodb \
           -p 4566:4566 \
           -p 4571:4571 \
           localstack/localstack:0.13.0.4

rm -f "${SCRIPT_DIR}"/terraform.tfstate*

terraform -chdir="${SCRIPT_DIR}" init

# shellcheck disable=SC2034
for attempts in 1 2; do
  terraform -chdir="${SCRIPT_DIR}" \
            apply \
            -target="module.cri-passport-lambda.aws_dynamodb_table.dcs-response" \
            -target="module.cri-passport-lambda.aws_dynamodb_table.cri-passport-auth-codes" \
            --auto-approve \
  && break
  echo "Retrying terraform apply"
done



