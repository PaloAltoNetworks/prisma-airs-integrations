# Contributing to Prisma AIRS Integrations

Thank you for your interest in contributing to the Prisma AIRS Integrations repository! This document provides guidelines for contributing integration documentation, code samples, and improvements.

## 🎯 Types of Contributions

We welcome the following types of contributions:

### 1. **New Integration Guides**
- Documentation for integrating Prisma AIRS with additional platforms
- Step-by-step setup instructions
- Configuration examples
- Verification procedures

### 2. **Documentation Improvements**
- Fixing typos, broken links, or unclear instructions
- Adding diagrams or visual aids
- Improving code examples
- Translating documentation

### 3. **Code Examples & Templates**
- Sample configurations (YAML, JSON, Lua scripts, etc.)
- Automation scripts for setup/deployment
- Test suites and validation scripts
- Example payloads and responses

### 4. **Bug Fixes**
- Correcting errors in existing configurations
- Fixing broken examples or outdated instructions
- Security improvements

## 📋 Contribution Process

### Before You Start

1. **Check existing issues** - Search for similar work or discussions
2. **Open an issue first** (for major changes) - Discuss your approach with maintainers
3. **Review existing integrations** - Follow the established patterns and structure

### Submission Steps

1. **Fork the repository**
   ```bash
   gh repo fork PaloAltoNetworks/prisma-airs-integrations
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-integration-name
   ```

3. **Make your changes**
   - Follow the integration template structure (see below)
   - Test all instructions and code examples
   - Update the main README.md if adding a new integration

4. **Commit your changes**
   ```bash
   git commit -m "docs: add [Platform Name] integration guide"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-integration-name
   ```

6. **Create a Pull Request**
   - Provide a clear description of changes
   - Reference any related issues
   - Include screenshots or examples if applicable

## 📁 Integration Template Structure

When adding a new integration, follow this structure:

```
PlatformName/
├── README.md                 # Main integration guide
├── config/                   # Optional: Configuration files
│   ├── example-config.yaml
│   └── example-settings.json
├── scripts/                  # Optional: Setup/deployment scripts
│   └── setup.sh
└── examples/                 # Optional: Working examples
    └── sample-request.json
```

### README.md Template

Your integration README should include:

```markdown
# [Platform Name] Integration with Prisma AIRS

Brief description of what this integration does.

---

## Prerequisites

* Requirement 1
* Requirement 2
* Access to Strata Cloud Manager
* A configured Security Profile
* A Prisma AIRS API Key

---

## Configuration Steps

### Step 1: [First Major Step]

Clear, numbered instructions...

### Step 2: [Second Major Step]

More instructions with code examples...

```yaml
# Example configuration
key: value
```

---

## Validation

Include unit/fucntional tests and instructions on how to execute in the `/scripts`, `/examples` or `/test` directories. 

---

## Technical Requirements

1. Integrations **MUST** indicate the integration using the `app_name` field in the AIRS request. Ideally, allow users to **append** their business-specific application name to the integration. (E.g. `LiteLLM` becomes `LiteLLM-HR-Chatbot`).
2. If applicable, override tr_id with any available unique identifiers from integration platform.


```
{
  "tr_id": "string", # If applicable, leverage tr_id to pass unique ID from integration platform
  "session_id": "string",
  "ai_profile": {
    "profile_name": "string"
  },
  "metadata": {
    "app_name": "<VENDOR_NAME>-<CUSTOMER_APP>", # Requirement
    }
  },
  "contents": [
    {
      "prompt": "string",
      "response": "string",
    }
  ]
}

```

---

## Troubleshooting (Optional)

Common issues and solutions...
```

## ✅ Quality Guidelines

### Documentation
- **Clarity**: Write for users who may be unfamiliar with the platform
- **Completeness**: Include all required steps and prerequisites
- **Accuracy**: Test all instructions before submitting
- **Formatting**: Use consistent markdown formatting
- **Links**: Verify all URLs and cross-references work

### Code Examples
- **Working**: All code samples must be tested and functional
- **Commented**: Include inline comments explaining complex sections
- **Secure**: Never include actual API keys or credentials
- **Current**: Use current API versions and best practices

### Configuration Files
- **Templates**: Provide example configurations with placeholder values
- **Validation**: Ensure configurations are syntactically correct
- **Documentation**: Comment complex configuration options

## 🔒 Security Considerations

- **Never commit real credentials** - Use placeholders like `YOUR_API_KEY_HERE`
- **Sanitize examples** - Remove any production data from examples
- **Review security impact** - Consider security implications of configurations
- **Follow least privilege** - Recommend minimal required permissions

## 🧪 Testing Your Changes

Before submitting:

1. **Spell check** - Run a spell checker on documentation
2. **Link validation** - Verify all links are accessible
3. **Code testing** - Test all code examples in a clean environment
4. **Markdown rendering** - Preview how your markdown renders on GitHub

## 📝 Commit Message Guidelines

Follow conventional commit format:

- `docs:` - Documentation changes
- `feat:` - New integration or feature
- `fix:` - Bug fixes or corrections
- `chore:` - Maintenance tasks
- `test:` - Adding tests or examples

Examples:
```
docs: add LangChain integration guide
fix: correct Kong plugin configuration syntax
feat: add automated setup script for Portkey
```

## 🤝 Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what's best for the community
- Help others learn and grow

## 💬 Getting Help

- **Questions?** Open a GitHub issue with the `question` label
- **Discussions** Use GitHub Discussions for general topics
- **Prisma AIRS Docs** https://pan.dev/airs/
- **Palo Alto Networks Support** For product-specific issues

## 📜 License

By contributing, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).

---

**Thank you for helping make Prisma AIRS integrations better for everyone!**
