# Provisioner image for the monolithic AIRS-on-Apigee proxy Cloud Run Job.
#
# Base: Google Cloud SDK (slim) — ships gcloud + bash + curl. We add jq and
# zip, which provision.sh needs to build the Apigee bundle archive and parse
# the management-API JSON responses.

FROM google/cloud-sdk:slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends jq zip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY provision.sh /app/provision.sh
COPY bundles/ /app/bundles/

RUN chmod +x /app/provision.sh

ENTRYPOINT ["/app/provision.sh"]
