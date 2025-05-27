variable "cloudflare_api_token" {
  description = "Cloudflare API Token (set via TF_VAR environment variable)"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID for your domain."
  type        = string
}

variable "waf_rules" {
  description = "A list of WAF rules definitions for the http_request_firewall_custom ruleset."
  type = list(object({
    action      = string
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
  }))
  default = [] // Default to an empty list. Values will come from .tfvars
}

variable "ratelimit_rules" {
  description = "A list of Rate Limiting rules to create"
  type = list(object({
    name                       = string
    description                = string
    match_request_uri_path     = string
    expression_override        = string // Now effectively mandatory, so no 'optional()' here for clarity
    match_response_headers     = optional(list(object({ name = string, op = string, value = string })), [])
    characteristics            = list(string)
    period_seconds             = number
    requests_per_period        = number
    mitigation_timeout_seconds = number
    action                     = string
    enabled                    = optional(bool, true)
  }))
  default = [] // Default to an empty list. Values will come from .tfvars
}