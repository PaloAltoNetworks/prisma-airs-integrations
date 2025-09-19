# Portkey Examples

This directory contains example scripts for testing Portkey integrations.

## `test_curl.sh`

This Bash script demonstrates how to send a test request to a local Portkey server using `curl` and connecting to an Azure Instance.

It configures input and output guardrails for PANW Prisma AIRS interception and passes relevant API keys and configuration via HTTP headers.

### Usage

1. **Set the required environment variables:**

   - `MY_AIRS_API_KEY`: Your Prisma AIRS API key.
   - `AZURE_OPENAI_API_KEY`: Your Azure OpenAI API key.
   - `AZURE_RESOURCE`: The Azure resource name.
   - `AZURE_DEPLOYMENT`: The Azure deployment ID.
   - `AZURE_API_VERSION`: The Azure API version.

2. **Run the script:**

   ```zsh
   ./test_azure_curl.sh
   ```

   The script will send a sample chat completion request to `http://127.0.0.1:8787/v1/chat/completions` and print the JSON response.

### Notes

- The script uses `jq` to format JSON output. Make sure `jq` is installed on your system.
- You can modify the request payload or headers as needed for your testing scenarios.

## `test_pyton.py`

This Python script provides an example of how to interact with the Portkey API programmatically. It demonstrates sending a chat completion request, similar to the Bash script, but using Python's HTTP libraries.

### Usage

1. **Install dependencies:**

   If required, install dependencies listed in `requirements.txt`:

   ```zsh
   pip install -r requirements.txt
   ```

2. **Set the required environment variables:**

   You can set the variables directly in your shell, or use a `.env` file for convenience.  
   Example `.env` file:

   ```
   MY_AIRS_API_KEY=your_airs_api_key
   AZURE_OPENAI_API_KEY=your_azure_openai_api_key
   AZURE_RESOURCE=your_azure_resource_name
   AZURE_DEPLOYMENT=your_azure_deployment_id
   AZURE_API_VERSION=your_azure_api_version
   ```

   To use a `.env` file, ensure you have the `python-dotenv` package installed (included in `requirements.txt` if needed), and the script will automatically load variables from `.env`.

3. **Run the script:**

   ```zsh
   python test_azure_pyton.py
   ```

   The script will send a chat completion request to the local Portkey server and print the response.

### Notes

- You can modify the script to change the request payload, headers, or endpoint as needed for your testing.
- Ensure all required environment variables are set, either in your shell or in a `.env` file, before running the script.

## Other Files

- `requirements.txt`: Lists Python dependencies for the example scripts.

---

For more information, see the main [README.md](../README.md) in the `Portkey` directory.