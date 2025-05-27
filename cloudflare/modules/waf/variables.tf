variable "zone_id" {
  description = "Cloudflare Zone ID for which the WAF rules will be applied."
  type        = string
}

variable "custom_waf_rules" {
  description = "List of custom WAF rules to create."
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
}

variable "ruleset_description" {
  description = "Optional description for the custom WAF ruleset."
  type        = string
  default     = "Custom WAF Ruleset"
}
