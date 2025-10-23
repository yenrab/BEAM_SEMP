-define(DEFAULT_PORT, 6469).
-define(DEFAULT_TOKEN_TTL_SEC, 1200). %% 20 minutes
-define(DEFAULT_SUSPICION_LIMIT, 3).
-define(TOKEN_CACHE_TAB, trust_client_token_cache).

-record(cfg, {
  port = ?DEFAULT_PORT :: inet:port_number(),
  alpn = <<"trust/1">> :: binary(),
  tls_opts = [] :: list(),
  token_ttl = ?DEFAULT_TOKEN_TTL_SEC :: non_neg_integer(),
  suspicion_limit = ?DEFAULT_SUSPICION_LIMIT :: non_neg_integer(),
  unsafe = false :: boolean(),
  unsafe_cookie = undefined :: binary() | undefined
}).
