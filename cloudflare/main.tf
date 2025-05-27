# --- WAF Module Instance ---
module "waf_custom_rules" {
  source              = "./modules/waf"
  zone_id             = var.cloudflare_zone_id
  custom_waf_rules    = var.waf_rules
  ruleset_description = ""
}

# --- Rate Limit Module Instance ---
module "ratelimit_rules" {
  source                 = "./modules/ratelimit"
  zone_id                = var.cloudflare_zone_id
  custom_ratelimit_rules = var.ratelimit_rules
}