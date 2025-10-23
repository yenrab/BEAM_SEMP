-module(trust_conn).
%% @private
%% @doc
%% Purpose:
%% Provides the server-side TLS connection handling logic for the TRUST system.
%% This module manages the lifecycle of an incoming TLS connection, including
%% performing the handshake, validating the peer certificate, issuing or verifying
%% authentication tokens, and processing client requests.
%%
%% Main Responsibilities:
%% - Performing TLS handshake on new sockets.
%% - Validating client certificates and checking whitelist membership.
%% - Exchanging authentication tokens (receiving or issuing as needed).
%% - Receiving and dispatching client requests to permitted MFAs.
%% - Enforcing permissions and updating suspicion metrics on invalid or denied activity.
%% - Closing connections cleanly after request handling or protocol violations.
%%
%% Author: Lee Barney
%% Version: 0.1
%% Last Modified: 2025-08-23
%%
%%

-export([start/1]).

-doc "Purpose:\n"
     "Starts handling a TLS connection by performing the handshake and, on success, "
     "delegating to after_tls/1 for post-handshake processing.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the accepted TLS socket.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — the success value returned by after_tls/1.\n"
     "- `ok` — if the connection is closed after a failed handshake.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-01\n".

-spec start(ssl:sslsocket()) -> term() | ok.
start(Sock) ->
    process_flag(trap_exit, true),
    logger:debug("trust_conn: starting TLS handshake on ~p.~n",[Sock]),
    HandshakeTimeOut = application:get_env(trust, client_handshake_timeout, 5000),
    Ssl = case ssl:handshake(Sock, HandshakeTimeOut) of
        ok                -> Sock;
	{ok, S2}          -> S2;
        {error, Reason}   -> ssl:close(Sock), 
			     exit({tls_handshake_failed, Reason})
    end,
    logger:debug("trust_conn: ssl handshake complete"),
    %% enforce ALPN selection
    case ssl:negotiated_protocol(Ssl) of
        {ok, <<"trust/1">>} -> ok;
        {ok, Other}         -> 
		    logger:debug("trust_conn: alpn missmatch ~p.~n",[Other]),
		    ssl:close(Ssl), exit({alpn_mismatch, Other});
        {error, R}          -> 
		    logger:debug("trust_con: alpn error: ~p~n",[R]),
		    ssl:close(Sock), exit({alpn_missing, R})
    end,
    logger:debug("trust_conn: ALPN passed"),
    ssl:setopts(Ssl, [{active, false}, {mode, binary}]),
    %% proceed: peercert -> fingerprint -> whitelist -> token/CALL -> close, etc.
    after_tls(Ssl).


-doc "Purpose:\n"
     "Performs server-side post-handshake validation on a TLS socket. Enforces ALPN, extracts "
     "the client certificate fingerprint, and applies authorization gates including whitelist "
     "membership and suspicion checks. If validation passes, delegates to "
     "maybe_recv_token_or_issue/2 to continue the protocol. Connections that fail any gate are "
     "closed and terminated with an appropriate exit reason.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket representing the client connection.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by maybe_recv_token_or_issue/2.\n"
     "- exits: `quarantined` — if the peer is quarantined by suspicion controls.\n"
     "- exits: `whitelist_reject` — if the peer is not whitelisted.\n"
     "- exits: `{peer_no_cert, Reason}` — if no peer certificate is provided or an error occurs.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-01\n".

-spec after_tls(ssl:sslsocket()) -> term() | no_return().
after_tls(Sock) ->
    %%this is the full handshake. How do we do the shorter version?
    %% mTLS identity -> SHA512(cert DER)
    case ssl:peercert(Sock) of
        {ok, CertDer} ->
            FP = semp_util:cert_fingerprint_sha512(CertDer),
	    logger:debug("trust_conn: generated from certDer, fp=~p", [FP]),
            %% Gate 1: whitelist
            case semp_whitelist:is_allowed(trust, FP) of
                true ->
		    logger:debug("trust_conn: remote is allowed fp=~p",[FP]),
                    %% Gate 2: suspicion/quarantine (no response to client on fail)
                    case trust_suspicion:is_trusted(FP) of
                        true  ->
			    logger:debug("trust_conn: fp: ~p~n is trusted",[FP]),
                            %% Proceed to your token/CALL path
                            maybe_recv_token_or_issue(Sock, FP);
                        false ->
                            %% Quarantined/suspicion exceeded: close silently
			    logger:warning("trust_conn: fp: ~p~n is quarantined",[FP]),
                            ssl:close(Sock), 
			    exit(quarantined)
                    end;

                false ->
                    %% Not whitelisted: close silently
		    logger:warning("trust_conn: whitelist_reject"),
                    ssl:close(Sock), exit(whitelist_reject)
            end;

        {error, Reason} ->
	    logger:warning("conn: peercert error ~p", [Reason]),
            ssl:close(Sock), exit({peer_no_cert, Reason})
    end.


-doc "Purpose:\n"
     "Handles the server-side first-frame protocol after TLS. Attempts to receive the initial "
     "frame, validates a presented token (fast path) or treats timeouts as first-time clients by "
     "issuing a token, then proceeds to await and execute a CALL. Protocol violations, invalid "
     "tokens, closed connections, or receive errors terminate the connection with explicit reasons.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the client TLS socket.\n"
     "- `FP :: binary()` — the client certificate fingerprint (peer identity).\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by `await_request_and_execute/2`.\n"
     "- exits: `token_reject` — token present but invalid.\n"
     "- exits: `protocol_error` — unexpected first frame.\n"
     "- exits: `peer_closed` — peer closed the connection.\n"
     "- exits: `{recv_failed, term()}` — transport receive error.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec maybe_recv_token_or_issue(ssl:sslsocket(), binary()) ->
          term()
        | no_return().
maybe_recv_token_or_issue(Sock, FP) ->
    FirstFrameTmo = application:get_env(trust, first_frame_timeout_ms, 2000),
    case semp_util:recv_frame(Sock, FirstFrameTmo) of
        {ok, Bin} ->
            case safe_term(Bin) of
                #{t := token_present, token := T} ->
                    case trust_token:validate(T, FP) of
                        ok ->
			    logger:debug("trust_token: presented token is valid ~p~n",[T]),
                            %% Fast path: token good; proceed straight to CALL.
                            await_request_and_execute(Sock, FP);
                        {error, Why} ->
				    logger:warning("trust_token: invalid token presented by ~p (~p)", [FP, Why]),
                            catch trust_suspicion:bump(FP, up),%catch any throw by bumping suspicion
                            ssl:close(Sock),
                            exit(token_reject)
                    end;

                %% Any other first frame is a protocol violation (don’t help attackers).
                Other ->
                    logger:warning("trust_conn: presented token not matching protocol. FP = ~p Token: ~p", [FP, Other]),
                    catch trust_suspicion:bump(FP, up),
                    ssl:close(Sock),
                    exit(protocol_error)
            end;

        {error, timeout} ->
            %% No token presented: treat as first-time client → issue token then await CALL
	    logger:debug("trust_conn: no client token presented for ~p~n",[FP]),
            trust_token:issue(FP),
	    GeneratedToken=case trust_token:token_for(FP) of
		    error -> 
			    ssl:close(Sock),
			    exit(token_error);
		    Token ->Token
	    end,
	    logger:debug("trust_conn: generated token. FP=~p Token: ~p~n",[FP,GeneratedToken]),
            ok = semp_util:send_frame(Sock, term_to_binary(#{t => token_issue, token => GeneratedToken})),
	    logger:debug("trust_conn: generated token sent. Awaiting request~n"),
            await_request_and_execute(Sock, FP);

        {error, closed} ->
            exit(peer_closed);

        {error, E} ->
            logger:warning("recv_failed ~p (~p)", [FP, E]),
            %% network/transport hiccup; optional suspicion bump is your policy call:
            %% catch trust_suspicion:bump(FP, up),
            exit({recv_failed, E})
    end.


-doc "Purpose:\n"
     "Waits for a client request frame after TLS/token processing, decodes it, and executes\n"
     "a CALL or CAST for the requested MFA. Protocol violations or transport errors result in\n"
     "suspicion handling and connection termination.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket connected to the client.\n"
     "- `FP :: binary()` — the client certificate fingerprint (peer identity).\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by handle_mfa/8 for CALL or CAST.\n"
     "- exits: `call_timeout` — no request arrived within the configured timeout.\n"
     "- exits: `peer_closed` — the peer closed the connection.\n"
     "- exits: `{recv_failed, term()}` — transport receive error.\n"
     "- exits: `protocol_error` — malformed or unexpected request frame.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec await_request_and_execute(ssl:sslsocket(), binary()) -> term() | no_return().
await_request_and_execute(Sock, FP) ->
    CallTmo = application:get_env(trust, call_timeout_ms, 5000),
    logger:debug("trust_conn: waiting for request frame"),
    case semp_util:recv_frame(Sock, CallTmo) of
        {ok, Bin} ->
            case safe_term(Bin) of
                %% CALL with req_id (required)
                #{t := call, req_id := ReqId, m := M, f := F, a := A, args := Args} = Map ->
                    logger:debug("trust_conn: got call request ~p~n",[ReqId]),
		    Opts = maps:get(opts, Map, #{}),
                    logger:debug("trust_conn got call request ~p, (~p, ~p), with options: ~p~n",[ReqId, {M,F,A}, Args, Opts]),
		    handle_mfa(Sock, FP, call, M, F, A, Args, ReqId);

                %% CAST with req_id (required)
                #{t := cast, req_id := ReqId, m := M, f := F, a := A, args := Args}
                    when is_atom(M), is_atom(F), is_integer(A), is_list(Args) ->
		    logger:debug("trust_conn: got cast request ~p~n",[ReqId]),
                    handle_mfa(Sock, FP, cast, M, F, A, Args, ReqId);

                %% Anything else is a protocol violation 
                Other ->
                    logger:warning("protocol_error: bad reqest format (~p): ~p", [Bin, Other]),
                    bump_up_maybe_quarantine_close(Sock, FP, protocol_error)
            end;

        {error, timeout} -> logger:debug("trust_conn: remote request timed out"),
			    ssl:close(Sock), exit(call_timeout);
        {error, closed}  -> logger:debug("trust_con: remote socket closed"),
			    exit(peer_closed);
        {error, E}       ->
            logger:warning("recv_failed ~p (~p)", [FP, E]),
            ssl:close(Sock), exit({recv_failed, E})
    end.
%% ---- helpers (private) --------------------------------------------

-doc "Purpose:\n"
     "Validates and executes a requested MFA call or cast from a client. Verifies arity, checks\n"
     "policy forbiddance and per-fingerprint permissions, adjusts suspicion counters, executes the\n"
     "MFA, and responds (for CALL) or not (for CAST). On errors or policy violations, bumps\n"
     "suspicion, may quarantine/revoke, closes the socket, and exits with an appropriate reason.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket connected to the client.\n"
     "- `FP :: binary()` — client certificate fingerprint.\n"
     "- `Type :: call | cast` — request type determining reply behavior.\n"
     "- `M :: module()` — target module.\n"
     "- `F :: atom()` — target function.\n"
     "- `A :: non_neg_integer()` — expected arity.\n"
     "- `Args :: [term()]` — arguments to pass; its length must equal `A`.\n"
     "- `ReqId :: term()` — request identifier (used for logging/trace; reply shape differs upstream).\n"
     "\n"
     "Return Value:\n"
     "- `ok` — on successful execution and socket close.\n"
     "- exits: `user_code_error` — target MFA raised an exception.\n"
     "- exits: `permission_denied` — arity mismatch, forbidden target, or not permitted.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec handle_mfa(
          ssl:sslsocket(),
          binary(),
          call | cast,
          module(),
          atom(),
          non_neg_integer(),
          [term()],
          term()
      ) -> ok | no_return().
handle_mfa(Sock, FP, Type, M, F, A, Args, ReqId) ->
    logger:debug("handlng MFA type ~p for id ~p~n",[Type,ReqId]),
    ArityOk  = (length(Args) =:= A),
    Forbidden = semp_policy:is_forbidden(M, F, A),
    Permitted = perm_ok(FP, {M, F, A}),
    case {ArityOk, Forbidden, Permitted} of
        {true, false, true} ->
            %% Allowed → heal suspicion, then execute
            catch trust_suspicion:bump(FP, down),
            try apply(M, F, Args) of
                Ret ->
                    case Type of
                        call ->
                            ok = semp_util:send_frame(
                                   Sock, term_to_binary(#{t => result, value => Ret})),
                            ssl:close(Sock), ok;
                        cast ->
			    logger:debug("trust_conn: closing cast.~n"),
                            %% No reply on cast (success)
                            ssl:close(Sock), ok
                    end
            catch
                Class:Reason:_Stack ->
                    %% Execution error → bump, maybe quarantine & revoke
                    catch trust_suspicion:bump(FP, up),
		    logger:warning("trust_conn: bumping suspicion for ~p~n",[FP]),
                    maybe_quarantine_and_revoke(FP),
                    case Type of
                        call ->
                            %% Send error for call, then close
                            ok = send_error_frame(Sock, Class, Reason),
                            ssl:close(Sock),
                            exit(user_code_error);
                        cast ->
				    io:format("error on cast~n"),
                            %% No reply on cast (error)
                            ssl:close(Sock),
                            exit(user_code_error)
                    end
            end;

        %% Any deny case (arity mismatch, forbidden module, not permitted)
        _ ->
            catch trust_suspicion:bump(FP, up),
	    logger:warning("trust_conn: bumping suspicion for ~p with id ~p~n",[FP,ReqId]),
            maybe_quarantine_and_revoke(FP),
            %% No reply for permission failures
            ssl:close(Sock),
            exit(permission_denied)
    end.

%% ---- helpers -------------------------------------------------------

-doc "Purpose:\n"
     "Checks the trust status of a fingerprint and revokes its token if it is no longer trusted. "
     "Used to enforce quarantine by invalidating tokens of suspicious or untrusted peers.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the fingerprint to check and potentially quarantine.\n"
     "\n"
     "Return Value:\n"
     "- `quarantined` — if the fingerprint is not trusted and its token was revoked.\n"
     "- `ok` — if the fingerprint is still trusted.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec maybe_quarantine_and_revoke(binary()) -> quarantined | ok.
maybe_quarantine_and_revoke(FP) ->
    case (catch trust_suspicion:is_trusted(FP)) of
        false ->
            catch trust_token:revoke_fp(FP),
            quarantined;
        _ -> ok
    end.


-doc "Purpose:\n"
     "Sends a compact error frame over the TLS socket to report user code execution failures. "
     "The error frame contains the error type and reason but omits the stacktrace for security "
     "and efficiency.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket to send the frame on.\n"
     "- `Class :: term()` — the error type (e.g., throw, error, exit).\n"
     "- `Reason :: term()` — the reason associated with the error.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — if the error frame was sent successfully.\n"
     "- `fail` — if sending the frame failed.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec send_error_frame(ssl:sslsocket(), term(), term()) -> ok | fail.
send_error_frame(Sock, Class, Reason) ->
    %% Keep the error payload compact; omit stacktrace on the wire.
    Frame = term_to_binary(#{t => error, kind => Class, reason => Reason}),
    semp_util:send_frame(Sock, Frame).



-doc "Purpose:\n"
     "Determines whether a given MFA (module, function, arity) is permitted for a client identified "
     "by its fingerprint. Looks up the fingerprint in the whitelist ETS table and checks if it is "
     "fully open (`any`) or if the specific MFA appears in its authorization spec.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the client certificate fingerprint.\n"
     "- `{M,F,A} :: {module(), atom(), integer()}` — the target module, function, and arity.\n"
     "\n"
     "Return Value:\n"
     "- `true` — if the fingerprint is whitelisted for the MFA.\n"
     "- `false` — if the fingerprint is not whitelisted or the MFA is not allowed.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec perm_ok(binary(), {module(), atom(), integer()}) -> boolean().
perm_ok(FP, {M,F,A}) when is_binary(FP), is_atom(M), is_atom(F), is_integer(A) ->
    Tab = semp_whitelist:table(trust),
    case ets:lookup(Tab, FP) of
        []              -> false;          %% not whitelisted
        [{_, any}]      -> true;           %% fully open for this FP
        [{_, Spec}]     -> mfa_in_spec(M, F, A, Spec);
        _               -> false
    end.


-doc "Purpose:\n"
     "Checks whether a given MFA (module, function, arity) is included in an authorization "
     "specification list. Supports full module allowance (`any`) or explicit MFA lists. "
     "Returns `false` if the module is not found or the spec is invalid.\n"
     "\n"
     "Parameters:\n"
     "- `M :: module()` — the target module.\n"
     "- `F :: atom()` — the target function.\n"
     "- `A :: integer()` — the target arity.\n"
     "- `Spec :: list()` — the authorization specification, mapping modules to `any` or lists of MFAs.\n"
     "\n"
     "Return Value:\n"
     "- `true` — if the MFA is explicitly allowed or the module is open (`any`).\n"
     "- `false` — if the MFA is not allowed or the specification is invalid.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec mfa_in_spec(module(), atom(), integer(), list()) -> boolean().
mfa_in_spec(M, F, A, Spec) when is_list(Spec) ->
    case lists:keyfind(M, 1, Spec) of
        false          -> false;
        {M, any}       -> true;
        {M, MFAs} when is_list(MFAs), MFAs =/= [] ->
            lists:member({F, A}, MFAs);
        _              -> false
    end;
mfa_in_spec(_, _, _, _) ->
    false.



-doc "Purpose:\n"
     "Handles denial scenarios by bumping suspicion for a fingerprint, possibly quarantining it, "
     "revoking its token, logging the event, and closing the socket. If the fingerprint is no "
     "longer trusted, it is quarantined; otherwise, the connection is terminated with the given reason.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket to close.\n"
     "- `FP :: binary()` — the client fingerprint.\n"
     "- `Reason :: term()` — the reason for denial or error.\n"
     "\n"
     "Return Value:\n"
     "- exits: `quarantined` — if the fingerprint is quarantined after suspicion bump.\n"
     "- exits: `Reason` — if the fingerprint is still trusted but denied.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec bump_up_maybe_quarantine_close(ssl:sslsocket(), binary(), term()) -> no_return().
bump_up_maybe_quarantine_close(Sock, FP, Reason) ->
    Res = catch trust_suspicion:bump(FP, up),
    case (catch trust_suspicion:is_trusted(FP)) of
        false ->
            %% Quarantined: kill any fast-path token and drop
            catch trust_token:revoke_fp(FP),
            logger:warning("quarantined ~p due to ~p (bump=~p)", [FP, Reason, Res]),
            ssl:close(Sock), exit(quarantined);
        true ->
            logger:warning("deny/bump ~p due to ~p (bump=~p)", [FP, Reason, Res]),
            ssl:close(Sock), exit(Reason);
        _ ->
            ssl:close(Sock), exit(Reason)
    end.






-doc "Purpose:\n"
     "Safely decodes a binary into an Erlang term. If decoding fails or the binary is unsafe, "
     "returns a sentinel map instead of raising an exception.\n"
     "This safety check fails when the binary contains atoms. This resolves the  atom injection / table exhaustion problem.\n"
     "\n"
     "Parameters:\n"
     "- `Bin :: binary()` — the binary to decode.\n"
     "\n"
     "Return Value:\n"
     "- `term()` — the decoded Erlang term.\n"
     "- `#{bad_term => true}` — returned when the binary cannot be safely decoded.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec safe_term(binary()) -> term() | #{bad_term => true}.
safe_term(Bin) ->
    try binary_to_term(Bin, [safe]) of T -> T catch _:_ -> #{bad_term => true} end.
