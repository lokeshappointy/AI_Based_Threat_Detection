// ============================================================================
// WAF Rules Configuration
// ============================================================================

waf_rules = [
// --------------------------------------------------------------------------
  // BEGIN: Existing Rules
  // --------------------------------------------------------------------------
  
  { action      = "skip",
    description = "[SKIP] GCP Infrastructure - CloudBuild",
    enabled     = true,
    expression  = "(ip.src.asnum eq 396982 and ip.src.country eq \"BE\" and http.user_agent eq \"app/1.0.0\")",
    action_parameters = {
      ruleset  = "current",
      phases   = ["http_ratelimit", "http_request_firewall_managed"],
      products = ["uaBlock"]
    },
    logging = { enabled = true }
  },

  {
    action      = "skip",
    description = "[SKIP] GCP Infrastructure - Belgium",
    enabled     = true,
    expression  = "(ip.src.asnum eq 396982 and ip.src.country eq \"BE\" and http.user_agent eq \"Go-http-client/2.0\")",
    action_parameters = {
      ruleset  = "current",
      phases   = ["http_ratelimit", "http_request_firewall_managed"],
      products = ["uaBlock"]
    },
    logging = { enabled = true }
  },

  {
    action      = "skip",
    description = "[SKIP] API - Meta",
    enabled     = true,
    expression  = "(http.user_agent eq \"facebookplatform/1.0 (+http://developers.facebook.com)\") or (http.user_agent eq \"Webhooks/1.0 (https://fb.me/webhooks)\") or (http.request.uri.path contains \"integration/v1/messages/webhook/instagram\")",
    action_parameters = {
      ruleset  = "current",
      phases   = ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"],
      products = ["bic", "rateLimit", "uaBlock", "waf"]
    },
    logging = { enabled = true }
  },

  {
    action      = "skip",
    description = "[SKIP] Appointy AI Auth",
    enabled     = true,
    expression  = "(http.host eq \"qa-api.appointy.ai\" and starts_with(http.request.uri.path, \"/auth/\") and ip.src eq 54.86.50.139)",
    action_parameters = {
      ruleset  = "current",
      phases   = ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"],
      products = ["bic", "rateLimit", "securityLevel", "uaBlock", "waf"]
    },
    logging = { enabled = true }
  },

  {
    action      = "skip",
    description = "[SKIP] Office IP Level 7",
    enabled     = true,
    expression  = "(ip.src eq 49.249.139.126)",
    action_parameters = {
      ruleset  = "current",
      phases   = ["http_request_firewall_managed"],
      products = null
    },
    logging = { enabled = true }
  },

  {
    action      = "skip",
    description = "[SKIP] Office IP Level 6",
    enabled     = true,
    expression  = "(ip.src eq 49.249.139.125 or ip.src eq 35.209.92.243)",
    action_parameters = {
      ruleset  = "current",
      phases   = ["http_request_firewall_managed"],
      products = null
    },
    logging = { enabled = true }
  },

  {
    action      = "skip",
    description = "[SKIP] Office IP Level 5",
    enabled     = true,
    expression  = "(ip.src eq 49.249.139.124)",
    action_parameters = {
      ruleset  = "current",
      phases   = ["http_request_firewall_managed"],
      products = null
    },
    logging = { enabled = true }
  },

  {
    action            = "block",
    description       = "[SKIP] Office IP Level 4",
    enabled           = true,
    expression        = "(ip.src ne 49.249.139.123)",
    action_parameters = null
  },

  // --------------------------------------------------------------------------
  // END: Existing Rules
  // --------------------------------------------------------------------------


  // --------------------------------------------------------------------------
  // BEGIN: NEW WAF Rules for waf-test.appointy.ai
  // --------------------------------------------------------------------------

  {
    action            = "block",
    description       = "WAF Test: Dictionary Attack on Login (waf-test.appointy.ai)",
    enabled           = true,
    expression        = <<EOT
      (http.host eq "waf-test.appointy.ai") and 
      (http.request.method eq "POST") and 
      (
        starts_with(http.request.uri.path, "/login") or
        starts_with(http.request.uri.path, "/signin") or
        starts_with(http.request.uri.path, "/admin") or
        starts_with(http.request.uri.path, "/administrator") or
        starts_with(http.request.uri.path, "/wp-login.php")
      )
    EOT
    action_parameters = null
  },

  {
    action            = "block",
    description       = "WAF Test: SQLi Attempt in Query String (waf-test.appointy.ai)",
    enabled           = true,
    expression        = "(http.host eq \"waf-test.appointy.ai\") and ((lower(http.request.uri.query) contains \"select\" and lower(http.request.uri.query) contains \"from\") or (lower(http.request.uri.query) contains \"union select\") or (lower(http.request.uri.query) contains \"drop table\"))",
    action_parameters = null
  },


  {
    action      = "skip",
    description = "WAF Test: Skip requests from internal IP",
    enabled     = true,
    expression  = <<EOT
      ip.src in {192.168.1.1}
    EOT
    action_parameters = {
      ruleset  = "current",
      phases   = ["http_request_firewall_managed"],
      products = null
    },
    logging = { enabled = true }
  },

  {
    action            = "block",
    description       = "WAF Test: Block access to /forbidden",
    enabled           = true,
    expression        = <<EOT
      (http.host eq "waf-test.appointy.ai") and 
      (http.request.uri.path eq "/forbidden")
    EOT
    action_parameters = null
  },

  {
    action            = "challenge",
    description       = "WAF Test: Apply  challenge to /suspicious_threat_bot",
    enabled           = true,
    expression        = <<EOT
      (http.host eq "waf-test.appointy.ai") and 
      (http.request.uri.path eq "/suspicious_threat_bot")
    EOT
    action_parameters = null
  }


  // --------------------------------------------------------------------------
  // END: NEW WAF Rules
  // --------------------------------------------------------------------------

]



// ============================================================================
// Rate Limiting Rules Configuration
// ============================================================================

ratelimit_rules = [

  // --------------------------------------------------------------------------
  // BEGIN: NEW Rate Limiting Rules for waf-test.appointy.ai
  // --------------------------------------------------------------------------

  {
    name                       = "RL General Site Limit waf-test",
    description                = "General rate limit for waf-test.appointy.ai",
    match_request_uri_path     = ".*",
    expression_override        = "(http.host eq \"waf-test.appointy.ai\") and (http.request.uri.path contains \"\")",
    characteristics            = ["ip.src", "cf.colo.id"],
    period_seconds             = 60,
    requests_per_period        = 20,
    mitigation_timeout_seconds = 60,
    action                     = "block",
    enabled                    = true
  },

  {
    name                       = "RL Login Attempts waf-test",
    description                = "Rate limit login attempts on waf-test.appointy.ai",
    match_request_uri_path     = "^/(login|signin|admin|administrator|wp-login\\.php)$",
    expression_override        = <<EOT
      (http.host eq "waf-test.appointy.ai") and 
      (
        starts_with(http.request.uri.path, "/login") or
        starts_with(http.request.uri.path, "/signin") or
        starts_with(http.request.uri.path, "/admin") or
        starts_with(http.request.uri.path, "/administrator") or
        starts_with(http.request.uri.path, "/wp-login.php")
      )
    EOT
    characteristics            = ["ip.src", "cf.colo.id"],
    period_seconds             = 60,
    requests_per_period        = 10,
    mitigation_timeout_seconds = 60,
    action                     = "block",
    enabled                    = true
  }

  // --------------------------------------------------------------------------
  // END: NEW Rate Limiting Rules
  // --------------------------------------------------------------------------

]
