#!/usr/bin/env bash
# AWS Adapter: deploys the adapter (the token issuer and the External service policy endpoint) to AWS as one HTTP API
# and one Lambda function, then prints the two URLs the Unity Catalog connection needs. Re-runnable.
#
# Before the first run, store the Prisma AIRS API key as the SecureString /dbx-airs/airs_api_key (README, AWS Adapter).
# Usage: AWS_PROFILE=<profile> AWS_REGION=<region> ./deploy.sh        (optional: STACK=<name>, default dbx-airs)
# The first run also creates three random SecureStrings, never shown: /dbx-airs/c_client_id, /dbx-airs/c_client_secret
# and /dbx-airs/c_signing_key. One deployment per account and region (the function is named dbx-airs-adapter).
# Remove: delete the stack, then the four parameters.
set -euo pipefail
export AWS_PAGER=""
: "${AWS_REGION:?set AWS_REGION to the region to deploy to}"
export AWS_DEFAULT_REGION="$AWS_REGION"        # AWS CLI v1 reads only this one
STACK="${STACK:-dbx-airs}"
for tool in aws python3 zip; do
  command -v "$tool" > /dev/null || { echo "stop: $tool is needed" >&2; exit 1; }
done
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"

exists() {  # true if the parameter exists, false if it does not; any other error stops the script
  local err
  if err="$(aws ssm get-parameter --name "$1" --query Parameter.Name --output text 2>&1 > /dev/null)"; then
    return 0
  fi
  case "$err" in
    *ParameterNotFound*) return 1 ;;
    *) echo "stop: cannot read $1: $(printf '%s' "$err" | head -n 1)" >&2; exit 1 ;;
  esac
}

aws sts get-caller-identity --query Arn --output text > /dev/null
if ! exists /dbx-airs/airs_api_key; then
  echo "stop: store the Prisma AIRS key as the SecureString /dbx-airs/airs_api_key in $AWS_REGION first (README, AWS Adapter)" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"
for name in c_client_id c_client_secret c_signing_key; do
  if ! exists "/dbx-airs/$name"; then
    (umask 077 && python3 -c 'import secrets; print(secrets.token_urlsafe(32), end="")' > "$WORK/value")
    aws ssm put-parameter --name "/dbx-airs/$name" --type SecureString --value "file://$WORK/value" > /dev/null
    rm -f "$WORK/value"
    echo "created /dbx-airs/$name (random, not shown)"
  fi
done

aws cloudformation deploy --stack-name "$STACK" --template-file "$HERE/template.json" \
  --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset --tags app=prisma-airs-unity-gateway

mkdir "$WORK/code"
printf 'from lambda_adapter import handler  # noqa: F401\n' > "$WORK/code/index.py"
cp "$HERE/lambda_adapter.py" "$HERE/token_issuer.py" "$SRC/airs_adapter.py" "$SRC/airs_core.py" "$WORK/code/"
(cd "$WORK/code" && zip -q -X code.zip ./*.py)
aws lambda update-function-code --function-name dbx-airs-adapter --zip-file "fileb://$WORK/code/code.zip" \
  --query CodeSha256 --output text > /dev/null
aws lambda wait function-updated --function-name dbx-airs-adapter
echo "code uploaded: dbx-airs-adapter"
aws cloudformation describe-stacks --stack-name "$STACK" \
  --query "Stacks[0].Outputs[].[OutputKey,OutputValue]" --output text
