# 🌐 Cloudflare WAF & Rate Limiting with Terraform

It is a modular Terraform-based solution for managing **Web Application Firewall (WAF)** and **Rate Limiting** rules for **multiple Cloudflare zones**.  
It supports **environment isolation using workspaces**, and includes a **CI/CD pipeline** that automatically applies rules on a pull request to a main branch based on the branch name.

---

## 📋 Table of Contents

1. [Directory Structure](#1-directory-structure)
2. [Features](#2-features)  
3. [Prerequisites](#3-prerequisites)
4. [How It Works](#4-how-it-works)
   - [Zone-Specific Branch Naming](#1-zone-specific-branch-naming)
   - [Rule Definitions](#rule-definitions)
5. [Local Development Guide](#5-local-development-guide)
6. [CI/CD Workflow (GitHub Actions)](#6-cicd-workflow-github-actions)
7. [Adding a New Zone](#7-adding-a-new-zone)
8. [Managing WAF & Rate Limiting Rules](#8-managing-waf--rate-limiting-rules)
9. [State Management](#9-state-management)

---

## 1. Directory Structure

```plaintext
cloudflare/
├── backend.tf
├── main.tf
├── modules/
│   ├── ratelimit/
│   │   ├── main.tf
│   │   ├── outputs.tf
│   │   ├── provider.tf
│   │   └── variables.tf
│   └── waf/
│       ├── main.tf
│       ├── outputs.tf
│       ├── provider.tf
│       └── variables.tf
├── provider.tf
├── variables.tf
├── README.md
└── zones/
    ├── appointy_ai/
    │   └── appointy_ai.tfvars
    └── appointy_com/
        └── appointy_com.tfvars
```

---

## 2. Features

* 🔒 **WAF Ruleset**: Block/challenge threats like SQL injection, path traversal, etc.
* 🚦 **Rate Limiting**: Throttle abusive traffic based on URI, headers, and IP.
* 🧱 **Modular Design**: Define rules cleanly in isolated modules.
* 🌍 **Multi-Zone Support**: Configure rules for multiple Cloudflare zones.
* 🔁 **Workspaces**: Separate state and logic per zone via Terraform workspaces.
* 🤖 **CI/CD Pipeline**: Automatically plans & applies changes on pull requests.

---

## 3. Prerequisites

* [Terraform](https://developer.hashicorp.com/terraform/downloads) v1.1.2 or higher
* Cloudflare Pro Plan or above
* Cloudflare API Token with:
  * Zone: Read
  * Zone Settings: Read
  * Zone Rulesets: Edit
  * WAF / Rate Limiting: Edit
* GitHub Secrets:
  * `CLOUDFLARE_API_TOKEN`
  * One secret per zone: `CLOUDFLARE_ZONE_ID_<ZONE_NAME_IN_UPPERCASE>`
    e.g., `CLOUDFLARE_ZONE_ID_APPOINTY_AI`

---

## 4. How It Works

### 1. Zone-Specific Branch Naming

When creating a PR, name your branch like this:

```
<feature>-<zone-name>
e.g., waf-update-appointy_ai
```

The CI pipeline extracts `appointy_ai` and uses it to:

* Select the matching workspace (`appointy_ai`)
* Load `zones/appointy_ai/appointy_ai.tfvars`
* Set `cloudflare_zone_id` automatically via the secret `CLOUDFLARE_ZONE_ID_APPOINTY_AI`

No manual code or config changes needed for switching zones.

### Rule Definitions

**WAF Rule Object Structure (`baseline_waf_rules`):**

```hcl
{
  action      = "block" | "challenge" | "skip" | "managed_challenge"
  description = string
  enabled     = optional(bool, true)
  expression  = string
  action_parameters = optional(object({
    ruleset  = optional(string)
    phases   = optional(list(string))
    products = optional(list(string))
  }), null)
  logging = optional(object({
    enabled = bool
  }), null)
}
```

**Rate Limiting Rule Object Structure (`ratelimit_rules`):**

```hcl
{
  name                       = string
  description                = string
  match_request_uri_path     = string
  expression_override        = string
  characteristics            = list(string)
  period_seconds             = number
  requests_per_period        = number
  mitigation_timeout_seconds = number
  action                     = "block" | "challenge"
  enabled                    = optional(bool, true)
}
```

Refer to [Cloudflare Docs](https://developers.cloudflare.com/ruleset-engine/) for updated syntax and field capabilities.

---

## 5. Local Development Guide

### Step 1: Setup

```bash
cd cloudflare/

# Export credentials (for local testing)
export TF_VAR_cloudflare_api_token="YOUR_TOKEN"
export TF_VAR_cloudflare_zone_id="YOUR_ZONE_ID"
```

### Step 2: Initialize Terraform

```bash
terraform init
```

### Step 3: Select or Create Workspace

```bash
terraform workspace list
terraform workspace new appointy_ai   # if first time
terraform workspace select appointy_ai
```

### Step 4: Plan & Apply

```bash
terraform plan -var-file=zones/appointy_ai/appointy_ai.tfvars
terraform apply -var-file=zones/appointy_ai/appointy_ai.tfvars
```

> 💡 Modify rules directly in the relevant `*.tfvars` file.

---

## 6. CI/CD Workflow (GitHub Actions)

Located at: `.github/workflows/terraform-cloudflare.yml`

### 🔁 What It Does

* Triggered **on pull requests** to `main`
* Extracts zone name from the branch (e.g., `feature-appointy_ai`)
* Sets:
  * `terraform workspace` = `appointy_ai`
  * `TF_VAR_cloudflare_zone_id` = From `CLOUDFLARE_ZONE_ID_APPOINTY_AI`
  * Loads `zones/appointy_ai/appointy_ai.tfvars`
* Runs:
  * `terraform init`
  * `terraform validate`
  * `terraform plan`
  * `terraform apply`

---

## 7. Adding a New Zone

1. **Create a zone tfvars file** under `zones/`:

   ```bash
   mkdir -p zones/mydomain_com
   touch zones/mydomain_com/mydomain_com.tfvars
   ```

2. **Add `baseline_waf_rules` and/or `ratelimit_rules`** in that file.

3. **Add the zone ID as a GitHub secret**:

   ```
   CLOUDFLARE_ZONE_ID_MYDOMAIN_COM
   ```

4. **Create a PR with a branch named like `feature-mydomain-com`**

---

## 8. Managing WAF & Rate Limiting Rules

> You can easily add, update, or delete rules by modifying the zone-specific `*.tfvars` files.

### 🔒 WAF Rules (`baseline_waf_rules`)

* **Add**: Append a new rule object to the `baseline_waf_rules` list.

  **Example:**

  ```hcl
  {
    action      = "challenge",
    description = "WAF Test: Apply challenge to /suspicious",
    enabled     = true,
    expression  = <<EOT
      (http.host eq "waf-test.appointy.ai") and 
      (http.request.uri.path eq "/suspicious")
    EOT
    action_parameters = null
  }
  ```

* **Update**: Modify fields like `expression`, `action`, or `description`.

* **Delete**: Remove the object from the list.

### 🚦 Rate Limiting Rules (`ratelimit_rules`)

* **Add**: Append a new rule object to the list similar to WAF but with different parameters.
* **Update/Delete**: Modify or remove as needed.

✅ After any changes:

```bash
terraform plan
terraform apply
```

> 💡 **Tip**: Use meaningful descriptions and test expressions carefully.

---

## 9. State Management

Terraform stores infrastructure mappings in a state file (`terraform.tfstate`).

### Local State (Default)

* Suitable for solo development
* Add `terraform.tfstate` to `.gitignore`

### Remote Backend (Recommended)

* Enables locking, collaboration, and versioning
* Example using Google Cloud Storage:

```hcl
terraform {
  backend "gcs" {
    bucket = "cloudshield-ai-terraform-state"
    prefix = "cloudflare-infra/appointy/state"
  }
}
```

Run `terraform init` to initialize or migrate the state backend.

---