%% @private
%% @doc
%% Purpose:
%% Provides opaque, per-fingerprint, expiring tokens for the TRUST system.
%% Tokens are issued, stored, validated, and revoked with strict TTL enforcement.
%%
%% Main Responsibilities:
%% - Issue one token per fingerprint; re-issuing overwrites the previous token.
%% - Store tokens in an ETS table for fast lookup and validation.
%% - Ensure ETS is initialized on demand; tokens are stateful and cleared on restart.
%%   (Restarting the system invalidates all tokens — this is intentional.)
%% - Validate tokens against expiration and fingerprint binding.
%% - Support token revocation and garbage collection of expired entries.
%% - Perform constant-time equality checks to resist timing attacks.
%% - Read configuration keys (TTL, byte length, secret) from the application `trust`.
%%
%% Author: Lee Barney
%% Version: 0.1
%% Last Modified: 2025-09-02
%%
-module(trust_token).

-export([
    ensure/0,
    table/0,
    issue/1,             %% issue(FP) -> {Token, ExpSec}
    issue/2,             %% issue(FP, TTLsec) -> {Token, ExpSec}
    token_for/1,         %% retrieve and validate token(FP) -> Token | fail
    validate/2,          %% validate(Token, FP) -> ok | {error, Reason}
    revoke_fp/1,         %% revoke_fp(FP) -> ok
    gc_expired/0         %% returns DeletedCount
]).

-define(TOK_TAB, trust_tokens).

-doc "Purpose:\n"
     "Retrieves the configured number of random bytes to use when generating tokens. "
     "If not set, defaults to 48 bytes.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `Bytes :: integer()` — the number of token bytes.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec token_bytes() -> integer().
token_bytes()   -> application:get_env(trust, token_bytes,   48).    %% 32–64 is good; 


-doc "Purpose:\n"
     "Retrieves the configured token time-to-live (TTL) in seconds. "
     "If not set, defaults to 120 seconds.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `TTL :: integer()` — the token expiration time in seconds.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec token_ttl_sec() -> integer().
token_ttl_sec() -> application:get_env(trust, token_ttl_sec, 120).  


-doc "Purpose:\n"
     "Ensures that the ETS table for storing tokens exists. If the table does not exist, "
     "creates it with concurrency options for read and write access. If the table already "
     "exists, no action is taken.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the table exists or was created successfully.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec ensure() -> ok.
%% Table holds: {FP, Token, ExpSec, IatSec}
ensure() ->
    case ets:info(?TOK_TAB) of
        undefined ->
            try ets:new(?TOK_TAB, [named_table, set, public,
                                   {read_concurrency, true},
                                   {write_concurrency, true}])
            catch error:badarg -> ok
            end,
            ok;
        _ -> ok
    end.



-doc "Purpose:\n"
     "Returns the ETS table identifier used for storing tokens.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `Tab :: atom()` — the ETS table name for token storage.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec table() -> atom().
table() ->
    ?TOK_TAB.


-doc "Purpose:\n"
     "Issues a new token for the given fingerprint using the default token TTL. "
     "Delegates to issue/2 with the configured TTL in seconds.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the fingerprint for which to issue the token.\n"
     "\n"
     "Return Value:\n"
     "- `true` — insertion succeeded.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec issue(binary()) -> true.
issue(FP) when is_binary(FP) ->
    issue(FP, token_ttl_sec()).

-doc "Purpose:\n"
     "Issues a new random token for the given fingerprint with a specified time-to-live (TTL). "
     "Stores the token in the ETS table, overwriting any existing entry for the same fingerprint.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the fingerprint for which to issue the token.\n"
     "- `TTL :: integer()` — the token time-to-live in seconds (must be > 0).\n"
     "\n"
     "Return Value:\n"
     "- `true` — insertion succeeded.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec issue(binary(), pos_integer()) -> true.
issue(FP, TTL) when is_binary(FP), is_integer(TTL), TTL > 0 ->
    ensure(),
    Now   = erlang:system_time(second),
    Exp   = Now + TTL,
    Token = crypto:strong_rand_bytes(token_bytes()),
    %% One token per FP: overwrite any existing entry for this FP
    ets:insert(?TOK_TAB, {FP, Token, Exp, Now}).



-doc "Purpose:\n"
     "Retrieves the token currently associated with a given fingerprint from the ETS table. "
     "If found, validates the token; only a valid token is returned. Expired or invalid tokens "
     "yield `error`.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the fingerprint key to look up.\n"
     "\n"
     "Return Value:\n"
     "- `Token :: binary()` — the valid token for the fingerprint.\n"
     "- `error` — if no token is stored or the token is invalid/expired.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-03\n".

-spec token_for(binary()) -> binary() | error.
token_for(FP) when is_binary(FP) ->
    ensure(),
    case ets:lookup(?TOK_TAB, FP) of
        [{FP, Token, _Exp, _Iat}] ->
            case validate(Token, FP) of
                ok            -> Token;
                {error, _Why} -> error
            end;
        [] ->
            error
    end.

-doc "Purpose:\n"
     "Validates a provided token against the stored entry for the given fingerprint. "
     "Checks for existence, expiration, and equality with the stored token.\n"
     "\n"
     "Parameters:\n"
     "- `Token :: binary()` — the token to validate.\n"
     "- `FP :: binary()` — the fingerprint associated with the token.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the token is valid and matches the stored entry.\n"
     "- `{error, unknown_peer}` — no token is stored for the given fingerprint.\n"
     "- `{error, expired}` — the stored token has expired.\n"
     "- `{error, token_mismatch}` — the provided token does not match the stored one.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec validate(binary(), binary()) ->
          ok
        | {error, unknown_peer}
        | {error, expired}
        | {error, token_mismatch}.
validate(Token, FP) when is_binary(Token), is_binary(FP) ->
    ensure(),
    Now = erlang:system_time(second),
    case ets:lookup(?TOK_TAB, FP) of
        [] ->
            {error, unknown_peer};
        [{FP, StoredTok, Exp, _Iat}] ->
            case Exp > Now of
                false ->
                    ets:delete(?TOK_TAB, FP),
                    {error, expired};
                true ->
                    case ct_eq(Token, StoredTok) of
                        true  -> ok;
                        false -> {error, token_mismatch}
                    end
            end
    end.





-doc "Purpose:\n"
     "Revokes any token associated with the given fingerprint by deleting its entry "
     "from the ETS token table.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the fingerprint whose token should be revoked.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the token entry was removed or did not exist.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec revoke_fp(binary()) -> ok.
revoke_fp(FP) when is_binary(FP) ->
    ensure(),
    ets:delete(?TOK_TAB, FP),
    ok.



-doc "Purpose:\n"
     "Performs garbage collection on the token table by removing all expired token entries. "
     "Compares each token's expiration timestamp against the current system time.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `Count :: non_neg_integer()` — the number of expired entries deleted.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec gc_expired() -> non_neg_integer().
gc_expired() ->
    ensure(),
    Now = erlang:system_time(second),
    ets:select_delete(?TOK_TAB,
        [{{'$FP', '_', '$Exp', '_'}, [{'=<' , '$Exp', Now}], [true]}]).



-doc "Purpose:\n"
     "Performs a constant-time equality check between two binaries to mitigate timing attacks. "
     "Compares size first, then delegates to ct_eq_loop/3 for byte-wise XOR comparison.\n"
     "\n"
     "Parameters:\n"
     "- `A :: binary()` — the first binary.\n"
     "- `B :: binary()` — the second binary.\n"
     "\n"
     "Return Value:\n"
     "- `true` — if the binaries are equal.\n"
     "- `false` — if the binaries differ in length or content.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec ct_eq(binary(), binary()) -> boolean().
ct_eq(A, B) when is_binary(A), is_binary(B) ->
    case byte_size(A) =:= byte_size(B) of
        false -> false;
        true  -> ct_eq_loop(A, B, 0) =:= 0
    end.



-doc "Purpose:\n"
     "Helper function for comparison of two binaries. Iterates byte by byte, "
     "accumulating XOR differences into an accumulator value to avoid timing side-channels.\n"
     "\n"
     "Parameters:\n"
     "- `A :: binary()` — the first binary (processed recursively).\n"
     "- `B :: binary()` — the second binary (processed recursively).\n"
     "- `Acc :: integer()` — the accumulator of XOR results, initially 0.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: integer()` — 0 if the binaries are equal; nonzero if they differ.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec ct_eq_loop(binary(), binary(), integer()) -> integer().
ct_eq_loop(<<>>, <<>>, Acc) -> Acc;
ct_eq_loop(<<X:8, RestA/binary>>, <<Y:8, RestB/binary>>, Acc) ->
    ct_eq_loop(RestA, RestB, Acc bor (X bxor Y)).
