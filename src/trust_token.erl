-module(trust_token).

%% @private
%% @doc
%% Purpose:
%% Implements identity token issuance, verification, and parsing for the TRUST system.
%% This module creates signed authentication tokens, verifies their integrity
%% and validity, and provides safe parsing utilities.
%%
%% Main Responsibilities:
%% - Issuing tokens with claims including fingerprint, issue time, expiration,
%%   and key identifier.
%% - Signing claims using HMAC-SHA512 with a configured application secret.
%% - Verifying token signatures and expiration status.
%% - Parsing tokens without verification for inspection or caching.
%% - Safely decoding binaries into Erlang terms.
%%
%% Author: Lee Barney
%% Version: 0.1
%% Last Modified: 2025-08-23
%%
%%
%%


-export([issue/1, verify/1, peek/1]).
-doc "Purpose:\n"
     "Issues a new authentication token for the given certificate fingerprint. Builds claims "
     "including subject, issue time, expiration, and key identifier, signs them, and returns "
     "the serialized token along with metadata.\n"
     "\n"
     "Parameters:\n"
     "- `Fingerprint :: binary()` — the client certificate fingerprint.\n"
     "\n"
     "Return Value:\n"
     "- `{Token :: binary(), Kid :: binary(), Exp :: integer()}` — the serialized token, "
     "its key identifier, and its expiration time in seconds.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec issue(binary()) -> {binary(), binary(), integer()}.
issue(Fingerprint) when is_binary(Fingerprint) ->
    Now = os:system_time(second),
    TTL = application:get_env(semp, token_ttl, 1200),
    Kid = application:get_env(semp, token_kid, <<"kid-1">>),
    Claims = #{ver => 1, sub => Fingerprint, iat => Now, exp => Now + TTL, kid => Kid},
    Sig = sign(Claims),
    {term_to_binary(#{claims => Claims, sig => Sig}), Kid, Now + TTL}.



-doc "Purpose:\n"
     "Verifies a serialized authentication token by checking its signature and expiration. "
     "If valid, returns the claims contained in the token.\n"
     "\n"
     "Parameters:\n"
     "- `TokenBin :: binary()` — the serialized token binary.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, Claims :: map()}` — the token is valid and the claims are returned.\n"
     "- `{error, token_expired}` — the token has expired.\n"
     "- `{error, token_invalid_sig}` — the token signature is invalid.\n"
     "- `{error, bad_token}` — the binary could not be parsed into a valid token structure.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec verify(binary()) -> {ok, map()} | {error, token_expired} | {error, token_invalid_sig} | {error, bad_token}.
verify(TokenBin) when is_binary(TokenBin) ->
    case safe_term(TokenBin) of
        #{claims := Claims, sig := Sig} ->
            case trust_util:constant_time_eq(Sig, sign(Claims)) of
                true ->
                    Now = os:system_time(second),
                    case maps:get(exp, Claims, 0) > Now of
                        true  -> {ok, Claims};
                        false -> {error, token_expired}
                    end;
                false -> {error, token_invalid_sig}
            end;
        _ -> {error, bad_token}
    end.


-doc "Purpose:\n"
     "Parses a serialized authentication token without verifying its signature or expiration. "
     "Returns the embedded claims if the token is well-formed.\n"
     "\n"
     "Parameters:\n"
     "- `TokenBin :: binary()` — the serialized token binary.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, Claims :: map()}` — the claims contained in the token.\n"
     "- `{error, bad_token}` — the binary could not be parsed into a valid token structure.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec peek(binary()) -> {ok, map()} | {error, bad_token}.
peek(TokenBin) ->
    case safe_term(TokenBin) of
        #{claims := Claims} -> {ok, Claims};
        _ -> {error, bad_token}
    end.



-doc "Purpose:\n"
     "Generates an HMAC-SHA512 signature for the given token claims using the configured "
     "application secret. This is used when generating a token to be used for the rapid "
     "identity proof after completing the full identity proof algorithm.\n"
     "\n"
     "Parameters:\n"
     "- `Claims :: map()` — the claims to be signed.\n"
     "\n"
     "Return Value:\n"
     "- `Sig :: binary()` — the computed HMAC-SHA512 signature.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec sign(map()) -> binary().
sign(Claims) ->
    Secret = token_secret(),
    crypto:mac(hmac, sha512, Secret, term_to_binary(Claims)).


-doc "Purpose:\n"
     "Retrieves the application token secret for signing/verifying tokens used in the rapid identification"
     "algorithm. Accepts a binary\n"
     "secret (>= 32 bytes) or converts a string to binary. In unsafe mode without a configured\n"
     "secret, uses a development default and logs a warning; otherwise exits with an error.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `Secret :: binary()` — the token secret.\n"
     "- exits: `missing_token_secret` — when no secret is configured and unsafe mode is disabled.\n"
     "- exits: `bad_token_secret` — when a configured secret is invalid.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec token_secret() -> binary().
token_secret() ->
    case application:get_env(semp, token_secret) of
        {ok, S} when is_binary(S), byte_size(S) >= 32 -> S;
        {ok, S} when is_list(S) -> unicode:characters_to_binary(S);
        undefined ->
            case application:get_env(semp, unsafe, false) of
                true  -> logger:warning("UNSAFE: using dev token secret"), <<"dev-secret-change-me">>;
                false -> error(missing_token_secret)
            end;
        _ -> error(bad_token_secret)
    end.

-doc "Purpose:\n"
     "Safely decodes a binary into an Erlang term. If decoding fails or the binary is unsafe, "
     "returns the atom `bad` instead of raising an exception.\n"
     "\n"
     "Parameters:\n"
     "- `Bin :: binary()` — the binary to decode.\n"
     "\n"
     "Return Value:\n"
     "- `term()` — the decoded Erlang term.\n"
     "- `bad` — returned when the binary cannot be safely decoded.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec safe_term(binary()) -> term() | bad.
safe_term(Bin) ->
    try binary_to_term(Bin, [safe]) of T -> T catch _:_ -> bad end.
