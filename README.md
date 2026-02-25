# 🔐 Secret Rotator - Automated Secret Rotation System

> **Universal secret rotation tool for AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, and more**

---

## 🎯 Problem Solved

Secret management is **critical but complex**:
- **Manual rotation** is error-prone and often forgotten
- **Different systems** have different rotation requirements
- **Application updates** require coordination across multiple services
- **Zero downtime** rotation is challenging
- **Audit trails** are often incomplete

**Secret Rotator solves this by automating the entire rotation lifecycle.**

---

## ✨ Features

### 🔄 Core Capabilities

#### Multi-Manager Support
- **AWS Secrets Manager** - Automatic rotation with Lambda
- **HashiCorp Vault** - Dynamic secret rotation
- **Azure Key Vault** - Certificate and secret management
- **Google Cloud Secret Manager** - Secret lifecycle management
- **Database Credentials** - MySQL, PostgreSQL, MongoDB
- **API Keys** - Third-party service API keys
- **Certificates** - SSL/TLS certificate rotation

#### Smart Rotation Policies
- **Monthly** - Standard rotation frequency
- **Quarterly** - Less frequent rotation
- **Annually** - Annual rotation schedule
- **Max Age** - Rotate based on age threshold
- **On-Demand** - Manual rotation trigger
- **Grace Period** - Controlled rollout window

#### Zero-Downtime Deployment
- **Blue-Green** - Seamless secret switching
- **Rolling** - Gradual deployment
- **Validation** - Verify before cutover
- **Rollback** - Automatic on failure

### 🛡️ Security Features

- **Audit Logging** - Complete rotation history
- **Compliance** - SOC2, HIPAA, PCI-DSS ready
- **Encryption** - Secrets encrypted at rest
- **Access Control** - RBAC integration
- **Validation** - Pre-rotation checks
- **Notifications** - Alert on events

---

## 🛠️ Installation

### Build from Source

```bash
cd secret-rotator
go mod download
go build -o secret-rotator cmd/secret-rotator/main.go
```

### Install Globally

```bash
go install -o /usr/local/bin/secret-rotator ./cmd/secret-rotator
```

---

## 🚀 Usage

### Basic Usage

```bash
# Discover and rotate secrets (dry-run)
./secret-rotator --discover=/path/to/configs --dry-run

# Force rotation of all secrets
./secret-rotator --discover=/path/to/configs --force=true

# Load configuration from file
./secret-rotator --config=rotation-config.json
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--config` | Path to rotation configuration file | - |
| `--discover` | Comma-separated paths to discover secrets | - |
| `--dry-run` | Preview rotation without changes | `true` |
| `--force` | Force rotation of all secrets | `false` |
| `--verbose` | Verbose output | `false` |
| `--fail-on-errors` | Exit with error on failures | `true` |
| `--help` | Show help message | `false` |

### Examples

#### Discover and Rotate Secrets

```bash
# Scan directories for secrets and rotate
./secret-rotator --discover=/app/configs,/k8s/secrets --force=true

# Dry-run first to preview changes
./secret-rotator --discover=/app/configs --dry-run=true
```

#### Load Configuration File

```bash
# Create rotation configuration
cat > rotation-config.json << EOF
{
  "secrets": [
    {
      "id": "db-password",
      "name": "Database Password",
      "type": "database",
      "manager": "vault",
      "location": "vault/database",
      "application_ids": ["app-1", "app-2"],
      "rotation_policy": "monthly",
      "status": "active"
    }
  ],
  "max_age_days": 90,
  "audit_enabled": true
}
EOF

# Run rotation with configuration
./secret-rotator --config=rotation-config.json --force=true
```

#### Force Rotation

```bash
# Force immediate rotation of all secrets
./secret-rotator --discover=/secrets --force=true --dry-run=false

# Rotate specific secret type
./secret-rotator --discover=/aws-secrets --force=true --type=aws
```

---

## 📋 Configuration File

### Complete Example

```json
{
  "secrets": [
    {
      "id": "aws-db-credentials",
      "name": "AWS Database Credentials",
      "type": "database",
      "manager": "aws",
      "location": "aws-secrets-manager/prod/db",
      "application_ids": ["web-app", "api-service"],
      "last_rotated": "2026-01-15T10:00:00Z",
      "next_rotation": "2026-02-15T10:00:00Z",
      "rotation_policy": "monthly",
      "status": "active"
    },
    {
      "id": "vault-api-token",
      "name": "Vault API Token",
      "type": "apikey",
      "manager": "vault",
      "location": "vault/auth/token",
      "application_ids": ["infrastructure"],
      "last_rotated": "2026-01-01T00:00:00Z",
      "next_rotation": "2026-07-01T00:00:00Z",
      "rotation_policy": "quarterly",
      "status": "active"
    }
  ],
  "default_policy": "monthly",
  "max_age_days": 90,
  "grace_period_hours": 24,
  "audit_enabled": true,
  "notifications": {
    "email": ["security@example.com", "ops@example.com"],
    "slack_webhook": "https://hooks.slack.com/services/xxx",
    "pagerduty": "your-pagerduty-key"
  }
}
```

---

## 📊 Rotation Report Example

```
================================================================================
📊 SECRET ROTATION REPORT
================================================================================
✅ Total secrets discovered: 15
✅ Total secrets processed: 12
✅ Successfully rotated:     10
⚠️  Partially rotated:       1
❌ Failed to rotate:        0
⏭️  Skipped (no rotation):   3

================================================================================

🔍 DETAILED RESULTS:

✅ aws-db-credentials
    ID: db-config.json:15
    Status: success
    Rotated at: 2026-02-27 10:30:45

✅ vault-api-token
    ID: vault-config.json:22
    Status: success
    Rotated at: 2026-02-27 10:30:46

⚠️  s3-bucket-policy
    ID: s3-config.json:8
    Status: partial
    Rotated at: 2026-02-27 10:30:47
    Error: Failed to update application app-3

✅ github-token
    ID: github-config.json:5
    Status: success
    Rotated at: 2026-02-27 10:30:48

================================================================================

✅ Rotation complete!
```

---

## 🔧 Secret Manager Integration

### AWS Secrets Manager

```bash
# Example rotation with AWS
./secret-rotator \
  --config=aws-config.json \
  --dry-run=false \
  --force=true
```

AWS configuration:
```json
{
  "secrets": [{
    "id": "prod-db-password",
    "manager": "aws",
    "location": "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/db/password",
    "rotation_policy": "monthly"
  }]
}
```

### HashiCorp Vault

```bash
# Example rotation with Vault
./secret-rotator \
  --config=vault-config.json \
  --dry-run=false
```

Vault configuration:
```json
{
  "secrets": [{
    "id": "database-creds",
    "manager": "vault",
    "location": "database/creds/readonly",
    "rotation_policy": "max-age",
    "max_age_days": 30
  }]
}
```

### Azure Key Vault

```bash
# Example rotation with Azure
./secret-rotator \
  --config=azure-config.json \
  --dry-run=false
```

---

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: Secret Rotation
on:
  schedule:
    - cron: '0 0 1 * *'  # Monthly
  workflow_dispatch:

jobs:
  rotate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install secret-rotator
        run: |
          go build -o secret-rotator ./cmd/secret-rotator
      
      - name: Rotate secrets
        run: |
          ./secret-rotator \
            --config=rotation-config.json \
            --force=true \
            --fail-on-errors=true
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}
          VAULT_TOKEN: ${{ secrets.VAULT_TOKEN }}
```

### GitLab CI

```yaml
secret-rotation:
  stage: security
  variables:
    SECRET_ROTATOR_CONFIG: "rotation-config.json"
  script:
    - go build -o secret-rotator ./cmd/secret-rotator
    - ./secret-rotator --config=$SECRET_ROTATOR_CONFIG --force=true
```

---

## 📝 Audit Trail

All rotations are logged:

```json
{
  "timestamp": "2026-02-27T10:30:45Z",
  "event": "secret_rotated",
  "secret_id": "aws-db-credentials",
  "secret_name": "AWS Database Credentials",
  "previous_secret_hash": "abc123...",
  "new_secret_hash": "def456...",
  "rotated_by": "secret-rotator",
  "rotation_policy": "monthly",
  "duration_ms": 1250,
  "status": "success"
}
```

---

## 🧪 Testing

### Create Test Secrets

```bash
# Create test configuration
cat > test-config.json << EOF
{
  "secrets": [
    {
      "id": "test-secret-1",
      "name": "Test Secret 1",
      "type": "generic",
      "manager": "generic",
      "location": "/test/secret1",
      "rotation_policy": "on-demand",
      "status": "active"
    }
  ]
}
EOF

# Run rotation in dry-run mode
./secret-rotator --config=test-config.json --dry-run=true --verbose
```

---

## 🚧 Roadmap

- [ ] Automated application restart integration
- [ ] Kubernetes secret operator
- [ ] Service mesh integration (Istio, Linkerd)
- [ ] Multi-region rotation
- [ ] Secret rotation approval workflow
- [ ] Compliance reporting dashboard
- [ ] Secret rotation metrics and alerts

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Add new secret manager support
4. Submit a pull request

---

## 📄 License

MIT License - Free for commercial and personal use

---

## 🙏 Acknowledgments

Built with GPU for secure secret management.

---

**Version:** 1.0.0  
**Author:** @hallucinaut  
**Last Updated:** February 25, 2026