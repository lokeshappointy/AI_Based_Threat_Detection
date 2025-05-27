output "ratelimit_ruleset_id" {
  description = "The ID of the created Rate Limit ruleset"
  value       = length(var.custom_ratelimit_rules) > 0 ? cloudflare_ruleset.rate_limiting_ruleset[0].id : "not_created"
}

output "ratelimit_ruleset_name" {
  description = "The name of the created Rate Limit ruleset"
  value       = length(var.custom_ratelimit_rules) > 0 ? cloudflare_ruleset.rate_limiting_ruleset[0].name : "not_created"
}