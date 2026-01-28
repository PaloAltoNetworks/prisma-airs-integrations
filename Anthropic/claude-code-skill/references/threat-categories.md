# Prisma AIRS Threat Categories Reference

## Prompt Injection

### Description
Attempts to manipulate AI behavior through crafted input that overrides or circumvents the model's instructions.

### Examples
- "Ignore all previous instructions and..."
- Hidden instructions in encoded text
- Context manipulation attacks
- Role-playing exploits

### Severity: High to Critical

### Recommended Action
Block the request and log the attempt. Do not process the prompt.

---

## Data Loss Prevention (DLP)

### Description
Detection of sensitive data that should not be exposed or processed.

### Categories
- **PII**: Names, addresses, phone numbers, SSN, etc.
- **Credentials**: Passwords, API keys, tokens, secrets
- **Financial**: Credit card numbers, bank accounts
- **Healthcare**: PHI, medical records
- **Custom patterns**: Organization-specific sensitive data

### Severity: High

### Recommended Action
Redact sensitive data before processing or block the request entirely.

---

## Malicious URLs

### Description
URLs associated with known threats including malware, phishing, command & control servers, and other malicious infrastructure.

### Categories
- Malware distribution sites
- Phishing pages
- C2 (Command & Control) servers
- Known bad actors
- Newly registered suspicious domains

### Severity: Medium to High

### Recommended Action
Block requests containing malicious URLs. Alert on suspicious URLs.

---

## Toxic Content

### Description
Content that is harmful, offensive, or inappropriate.

### Categories
- Hate speech
- Violence
- Self-harm
- Sexual content
- Harassment

### Severity: Medium to High

### Recommended Action
Block or filter based on organizational policy.

---

## Jailbreak Attempts

### Description
Attempts to bypass AI safety measures and restrictions.

### Examples
- DAN (Do Anything Now) prompts
- Hypothetical scenario exploits
- Character role-play bypasses
- Multi-step extraction attacks

### Severity: High

### Recommended Action
Block the request and log for security review.

---

## Response-Side Threats

### Description
Security issues in AI-generated responses.

### Categories
- Unintended data leakage
- Hallucinated credentials or secrets
- Generated malicious code
- Harmful instructions

### Severity: Varies

### Recommended Action
Scan all responses before delivery. Block or redact as needed.
