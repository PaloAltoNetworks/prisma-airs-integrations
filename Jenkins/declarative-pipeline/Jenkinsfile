// Prisma AIRS Model Security Scan & Deploy Pipeline
//
// This pipeline scans an AI model with Palo Alto Networks Prisma AIRS
// Model Security before deploying it to Google Cloud Vertex AI.
//
// Required Jenkins Credentials (configured in Jenkins > Manage Credentials):
//   - gcp-sa-key              (Secret file)   — GCP service account JSON key
//   - gcp-project-id          (Secret text)    — GCP project ID
//   - gcp-region              (Secret text)    — GCP region (e.g. us-central1)
//   - model-security-client-id     (Secret text) — Prisma AIRS OAuth client ID
//   - model-security-client-secret (Secret text) — Prisma AIRS OAuth client secret
//   - model-security-profile-id    (Secret text) — Prisma AIRS security profile UUID
//   - model-security-api-endpoint  (Secret text) — Prisma AIRS API endpoint URL
//   - tsg-id                  (Secret text)    — Prisma AIRS Tenant Service Group ID
//   - hf-token                (Secret text)    — HuggingFace access token

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    triggers {
        // Poll SCM every 5 minutes for changes
        pollSCM('H/5 * * * *')
    }

    parameters {
        booleanParam(
            name: 'FORCE_RUN',
            defaultValue: false,
            description: 'Run the pipeline even if model config has not changed'
        )
        booleanParam(
            name: 'SKIP_DEPLOY',
            defaultValue: false,
            description: 'Run security scan only, skip deployment'
        )
    }

    environment {
        CONFIG_FILE = 'config/model-config.yaml'
    }

    stages {

        // --------------------------------------------------------------------
        // Customer-specific: Detect whether the model config file changed.
        // Adapt the changeset condition to match your own config structure.
        // --------------------------------------------------------------------
        stage('Detect Changes') {
            steps {
                script {
                    env.MODEL_CHANGED = 'false'

                    if (params.FORCE_RUN) {
                        echo 'FORCE_RUN enabled — skipping change detection.'
                        env.MODEL_CHANGED = 'true'
                        return
                    }

                    // Check if model config was modified in the latest changeset
                    def changes = currentBuild.changeSets.collectMany { it.items.collectMany { item -> item.affectedFiles.collect { it.path } } }
                    if (changes.any { it == 'config/model-config.yaml' }) {
                        echo 'Model config changed — proceeding with scan.'
                        env.MODEL_CHANGED = 'true'
                    } else {
                        echo 'No model config changes detected. Use FORCE_RUN to override.'
                    }
                }
            }
        }

        // --------------------------------------------------------------------
        // AIRS Model Security Integration — Prisma AIRS Model Security Scan
        //
        // This stage is the integration point with Palo Alto Networks Prisma
        // AIRS. It installs the official Model Security SDK from a private
        // PyPI, then scans the model. The scan returns ALLOWED or BLOCKED.
        //
        // To add Prisma AIRS scanning to your own pipeline, replicate this
        // stage:
        //   1. Authenticate with SCM to get the private PyPI URL
        //      (get_pypi_url.sh)
        //   2. Install the model-security-client SDK
        //   3. Run the scan script (scan_model.py)
        //
        // Required credentials:
        //   model-security-client-id      — Prisma AIRS OAuth client ID
        //   model-security-client-secret   — Prisma AIRS OAuth client secret
        //   model-security-api-endpoint    — Prisma AIRS API endpoint URL
        //   model-security-profile-id      — Security group UUID for scan rules
        //   tsg-id                         — Tenant Service Group ID
        // --------------------------------------------------------------------
        stage('Prisma AIRS Model Security Scan') {
            when {
                expression { env.MODEL_CHANGED == 'true' }
            }
            steps {
                withCredentials([
                    string(credentialsId: 'model-security-client-id',     variable: 'MODEL_SECURITY_CLIENT_ID'),
                    string(credentialsId: 'model-security-client-secret', variable: 'MODEL_SECURITY_CLIENT_SECRET'),
                    string(credentialsId: 'model-security-api-endpoint',  variable: 'MODEL_SECURITY_API_ENDPOINT'),
                    string(credentialsId: 'model-security-profile-id',    variable: 'MODEL_SECURITY_PROFILE_ID'),
                    string(credentialsId: 'tsg-id',                       variable: 'TSG_ID'),
                ]) {
                    sh '''
                        echo "=== Setting up Python environment ==="
                        python3 -m venv .venv
                        . .venv/bin/activate

                        echo "=== Installing base dependencies ==="
                        pip install --quiet -r requirements.txt

                        echo "=== Authenticating with Prisma AIRS for SDK access ==="
                        PYPI_URL=$(bash scripts/get_pypi_url.sh)

                        echo "=== Installing Model Security SDK ==="
                        pip install --quiet "model-security-client[all]" --extra-index-url "${PYPI_URL}"

                        echo "=== Running Prisma AIRS Model Security Scan ==="
                        python scripts/scan_model.py --config ${CONFIG_FILE}
                    '''
                }
            }
        }

        // --------------------------------------------------------------------
        // Customer-specific: Deploy the scanned model to Google Cloud Vertex
        // AI. Replace this stage with your own deployment logic (e.g., AWS
        // SageMaker, Azure ML, on-prem infrastructure, etc.).
        // Only runs on the main branch after a passing scan.
        // --------------------------------------------------------------------
        stage('Deploy Model to Vertex AI') {
            when {
                allOf {
                    expression { env.MODEL_CHANGED == 'true' }
                    expression { !params.SKIP_DEPLOY }
                    expression { env.GIT_BRANCH == 'main' || env.GIT_BRANCH == 'origin/main' }
                }
            }
            steps {
                withCredentials([
                    file(credentialsId: 'gcp-sa-key',      variable: 'GOOGLE_APPLICATION_CREDENTIALS'),
                    string(credentialsId: 'gcp-project-id', variable: 'GCP_PROJECT_ID'),
                    string(credentialsId: 'gcp-region',     variable: 'GCP_REGION'),
                    string(credentialsId: 'hf-token',       variable: 'HF_TOKEN'),
                ]) {
                    sh '''
                        echo "=== Authenticating with Google Cloud ==="
                        gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}"
                        gcloud config set project "${GCP_PROJECT_ID}"

                        echo "=== Installing dependencies ==="
                        . .venv/bin/activate
                        pip install --quiet -r requirements.txt

                        echo "=== Deploying Model ==="
                        bash scripts/deploy_model.sh
                    '''
                }
            }
        }

        // --------------------------------------------------------------------
        // Customer-specific: Validate the deployed endpoint by sending a test
        // prompt. Replace with your own smoke tests or integration tests.
        // --------------------------------------------------------------------
        stage('Test Model Endpoint') {
            when {
                allOf {
                    expression { env.MODEL_CHANGED == 'true' }
                    expression { !params.SKIP_DEPLOY }
                    expression { env.GIT_BRANCH == 'main' || env.GIT_BRANCH == 'origin/main' }
                }
            }
            steps {
                withCredentials([
                    file(credentialsId: 'gcp-sa-key',      variable: 'GOOGLE_APPLICATION_CREDENTIALS'),
                    string(credentialsId: 'gcp-project-id', variable: 'GCP_PROJECT_ID'),
                    string(credentialsId: 'gcp-region',     variable: 'GCP_REGION'),
                ]) {
                    sh '''
                        echo "=== Authenticating with Google Cloud ==="
                        gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}"

                        echo "=== Testing Model Endpoint ==="
                        . .venv/bin/activate
                        python scripts/test_model.py --config ${CONFIG_FILE}
                    '''
                }
            }
        }
    }

    post {
        success {
            echo 'Pipeline completed successfully.'
        }
        failure {
            echo 'Pipeline failed. Check the logs above for details.'
        }
        always {
            // Clean up the Python virtual environment
            sh 'rm -rf .venv || true'
        }
    }
}
