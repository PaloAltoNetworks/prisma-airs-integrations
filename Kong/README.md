# Kong Integrations for Prisma AIRS

Integrations between Kong Gateway and Palo Alto Networks Prisma AI Runtime Security (AIRS).

## Available Integrations

| Integration | Description | Documentation |
|-------------|-------------|---------------|
| **Custom Plugin** | Full Lua plugin with dual-phase scanning (prompt + response) | [custom-plugin/](custom-plugin/) |
| **Request Callout** | Native request-callout plugin for prompt scanning | [request-callout/](request-callout/) |

## Choosing an Integration

| Feature | Custom Plugin | Request Callout |
|---------|:-------------:|:---------------:|
| Prompt scanning | ✅ | ✅ |
| Response scanning | ✅ | ❌ |
| Deployment | Custom plugin files | Native Kong plugin |
| Best for | Full coverage | Kong Konnect SaaS |

## Prerequisites

- Kong Gateway 3.4+ or Kong Konnect account
- Prisma AIRS license and API key from Strata Cloud Manager
- Configured Security Profile in Strata Cloud Manager
- Network access to Prisma AIRS API endpoints

## Resources

- [Prisma AIRS Documentation](https://pan.dev/airs/)
- [Kong Gateway Documentation](https://docs.konghq.com/gateway/latest/)
- [Kong Plugin Hub - Prisma AIRS](https://developer.konghq.com/plugins/prisma-airs-intercept/)
