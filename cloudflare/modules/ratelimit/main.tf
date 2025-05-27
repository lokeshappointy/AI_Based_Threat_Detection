resource "cloudflare_ruleset" "rate_limiting_ruleset" {
  count       = length(var.custom_ratelimit_rules) > 0 ? 1 : 0
  zone_id     = var.zone_id
  name        = "Terraform Managed Rate Limiting"
  description = "Rate limiting rules deployed via Terraform."
  kind        = "zone"
  phase       = "http_ratelimit"

  dynamic "rules" {
    for_each = { for idx, rule in var.custom_ratelimit_rules : rule.name => rule }
    content {
      action      = rules.value.action
      description = rules.value.description
      enabled     = rules.value.enabled

      // MODIFIED: Directly access expression_override
      // This is now safe because the module's variable definition for 
      // custom_ratelimit_rules[*].expression_override is a non-optional string.
      // If the root module fails to provide it, Terraform will error out
      // during variable validation when passing to the module.
      expression = rules.value.expression_override

      ratelimit {
        characteristics     = rules.value.characteristics
        period              = rules.value.period_seconds
        requests_per_period = rules.value.requests_per_period
        mitigation_timeout  = rules.value.mitigation_timeout_seconds
      }
    }
  }
}
