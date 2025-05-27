output "waf_ruleset_id" {
  description = "The ID of the WAF custom ruleset"
  // value       = length(var.custom_waf_rules) > 0 ? cloudflare_ruleset.custom_waf_ruleset[0].id : "not_created"
  // Since we removed count, access directly:
  value = cloudflare_ruleset.custom_waf_ruleset.id
}

output "waf_custom_ruleset_name" { // Corrected output name to match root main.tf
  description = "The name of the WAF custom ruleset"
  // value       = length(var.custom_waf_rules) > 0 ? cloudflare_ruleset.custom_waf_ruleset[0].name : "not_created"
  value = cloudflare_ruleset.custom_waf_ruleset.name
}