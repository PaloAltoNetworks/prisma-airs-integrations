# Portkey Examples

This directory contains example scripts for testing Portkey integrations.

## `test_<CSP>curl.sh`

These Bash scripts demonstrates how to send a test request to a local Portkey server using `curl`

There is one for Azure, AWS and GCP (Vertex)

The request is defined as an argument to the scripts

The script configures input and output guardrails for PANW Prisma AIRS interception and passes relevant API keys and configuration via HTTP headers.

### Usage

1. **Set the required environment variables:**

Examples of these are in the env.example file

2. **Run the script:**

    For example Azure would be:
   ```zsh
   ./test_azure_curl.sh Hi
   ```

   The script will send a sample chat completion request to `http://127.0.0.1:8787/v1/chat/completions` and print the JSON response.

### Notes

- The script uses `jq` to format JSON output. Make sure `jq` is installed on your system.
- You can modify the request payload or headers as needed for your testing scenarios.

## `test_<CSP>_pyton.py`

This Python script provides an example of how to interact with the Portkey API programmatically. It demonstrates sending a chat completion request, similar to the Bash script, but using Python's HTTP libraries.

### Usage

1. **Install dependencies:**

   If required, install dependencies listed in `requirements.txt`:

   ```zsh
   pip install -r requirements.txt
   ```

2. **Set the required environment variables:**

   You can set the variables directly in your shell, or use a `.env` file for convenience.  
   `env.example` contains an example, only enter the details for the CSP you want to test.

   To use a `.env` file, ensure you have the `python-dotenv` package installed (included in `requirements.txt` if needed), and the script will automatically load variables from `.env`.

3. **Run the script:**

   For example Azure would be:
   ```zsh
   python test_azure_pyton.py Hi
   ```

   The script will send a chat completion based on the arguments to the local Portkey server and print the response.

### Notes

- You can modify the script to change the request payload, headers, or endpoint as needed for your testing.
- Ensure all required environment variables are set, either in your shell or in a `.env` file, before running the script.

## Other Files

- `requirements.txt`: Lists Python dependencies for the example scripts.

---

For more information, see the main [README.md](../README.md) in the `Portkey` directory.