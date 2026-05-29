# Provisioner image for the AIRS-on-Apigee Cloud Run Job.
#
# Base: Google Cloud SDK (slim) — ships gcloud + bash + curl. We add jq and
# zip, which provision.sh needs to build the Apigee bundle archives and parse
# the management-API JSON responses.

FROM google/cloud-sdk:slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends jq zip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The provisioning script and the Apigee bundles it deploys.
COPY provision.sh /app/provision.sh
COPY bundles/ /app/bundles/

RUN chmod +x /app/provision.sh

# The Job runs the script to completion and exits. No long-running process.
ENTRYPOINT ["/app/provision.sh"]
