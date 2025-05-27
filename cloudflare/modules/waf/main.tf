resource "cloudflare_ruleset" "custom_waf_ruleset" {
  zone_id     = var.zone_id
  name        = "default"
  description = var.ruleset_description
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  dynamic "rules" {
    for_each = { for idx, rule_def in var.custom_waf_rules : idx => rule_def }
    content {
      action      = rules.value.action
      expression  = rules.value.expression
      description = rules.value.description
      enabled     = rules.value.enabled

      dynamic "action_parameters" { // Keep this block as defined before
        for_each = rules.value.action_parameters != null ? [rules.value.action_parameters] : []
        content {
          ruleset  = lookup(action_parameters.value, "ruleset", null)
          phases   = lookup(action_parameters.value, "phases", null)
          products = lookup(action_parameters.value, "products", null)
        }
      }

      # ADDED dynamic "logging" block
      dynamic "logging" {
        # Iterate only if rules.value.logging is not null
        for_each = rules.value.logging != null ? [rules.value.logging] : []
        content {
          enabled = logging.value.enabled // Access enabled from the logging object
        }
      }
    }
  }
}
