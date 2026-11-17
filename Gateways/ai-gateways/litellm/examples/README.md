# LiteLLM Examples

This directory contains example configuration and environment files, as well as shell scripts for integrating LiteLLM with various cloud providers and services.

## Files

- `env.example`:  
  Template environment file containing the required keys and configuration variables for AIRS, Azure, AWS, and LiteLLM admin access.

  **Important:**  
  - This is a template. **Do not use it directly.**
  - Copy `env.example` to `.env` and fill in your own credentials and configuration values.
  - Never commit your `.env` file to version control.

- Shell scripts (e.g., `test_aws_curl.sh`, `test_vertex_curl.sh`, etc.):  
  Example scripts for sending requests to LiteLLM integrations using different cloud providers.

## Environment Variables

The `env.example` file includes variables for:

- **AIRS**
  - `MY_AIRS_API_KEY`: Prisma AIRS API key

- **Azure**
  - `AZURE_OPENAI_API_KEY`: Azure OpenAI API key
  - `AZURE_RESOURCE`: Azure resource name
  - `AZURE_DEPLOYMENT`: Azure deployment ID
  - `AZURE_API_VERSION`: Azure API version

- **AWS**
  - `AWS_ACCESS_KEY_ID`: AWS access key ID
  - `AWS_SECRET_ACCESS_KEY`: AWS secret access key
  - `AWS_REGION`: AWS region

- **LiteLLM Admin**
  - `LITELLM_ADMIN_KEY`: LiteLLM admin key

## Usage

1. Copy `env.example` to `.env` in your working directory:

   ```zsh
   cp env.example .env
   ```

2. Edit `.env` and update the values with your own credentials and configuration.

3. Configuration for litellm is in one of the yaml files. All covers both AWS and Azure and includes the Prisma AIRS guardrails

4. Depending if you want to test Azure, AWS or both you will run the start_<option>.sh to configure the container (replace `podman` with `docker` in the files if you are using docker as your container mangement system)

5. Once the container is up and running, you can run the test scripts.
---

For more information, refer to the main [README.md](../README.md) in the `LiteLLM` directory.