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
     "Last Modified: 2025-08-23\n".

-spec start(ssl:sslsocket()) -> term() | ok.
start(Sock) ->
    process_flag(trap_exit, true),
    case ssl:handshake(Sock, 5000) of
        ok -> after_tls(Sock);
        {error, _} -> ssl:close(Sock)
    end.




-doc "Purpose:\n"
     "Performs server-side post-handshake processing by validating the peer certificate "
     "and checking if the fingerprint is whitelisted. If allowed, either receives a token "
     "from the client or issues one. Otherwise, closes the connection.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the established TLS socket.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by maybe_recv_token_or_issue/2.\n"
     "- `ok` — if the connection is closed due to untrusted or missing peer certificate.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec after_tls(ssl:sslsocket()) -> term() | ok.
after_tls(Sock) ->
    case ssl:peercert(Sock) of
        {ok, CertBin} ->
            FP = trust_util:cert_fingerprint_sha512(CertBin),
	    case trust_whitelist:is_allowed(FP) andalso trust_suspicion:isTrusted(FP) of
                true -> maybe_recv_token_or_issue(Sock, FP);
                false -> ssl:close(Sock)
            end;
        _ -> ssl:close(Sock)
    end.



-doc "Purpose:\n"
     "Handles initial post-handshake communication with a client. Attempts to receive a frame "
     "from the socket and either validates a presented token, issues a new token, or handles "
     "an incoming call. If no frame is received within the timeout, a token is issued and the "
     "server waits for a request. Suspicious or invalid activity results in suspicion tracking "
     "and connection termination.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the established TLS socket.\n"
     "- `FP :: binary()` — the client certificate fingerprint.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by await_request/2 or handle_req/3.\n"
     "- `ok` — connection closed cleanly by the client.\n"
     "- `ok` — if the connection is closed due to invalid or untrusted behavior.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec maybe_recv_token_or_issue(ssl:sslsocket(), binary()) -> term() | ok.
maybe_recv_token_or_issue(Sock, FP) ->
    case trust_util:recv_frame(Sock, 1000) of
        {ok, Bin} ->
            case safe_term(Bin) of
                #{t := token_present, token := Token} ->
                    case trust_token:verify(Token) of
                        {ok, #{sub := FP}} -> await_request(Sock, FP);
                        _ -> trust_suspicion:bump(FP, up), ssl:close(Sock)
                    end;
                #{t := call} = Call ->
                    send_token(Sock, FP),
                    handle_req(Sock, FP, Call);
                _Other ->
                    trust_suspicion:bump(FP, up),
                    ssl:close(Sock)
            end;
        {error, timeout} ->
            send_token(Sock, FP),
            await_request(Sock, FP);
        {error, closed} ->
            ok;
        _ ->
            ssl:close(Sock)
    end.


-doc "Purpose:\n"
     "Issues a new authentication token for the given fingerprint and sends it to the client "
     "over the established TLS socket.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket to send the token through.\n"
     "- `FP :: binary()` — the fingerprint associated with the issued token.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — token frame successfully sent.\n"
     "- `{:error, term()}` — an error occurred while sending the frame.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec send_token(ssl:sslsocket(), binary()) -> ok | {error, term()}.
send_token(Sock, FP) ->
    {Token, _Kid, _Exp} = trust_token:issue(FP),
    Frame = term_to_binary(#{t => token_issue, token => Token}),
    trust_util:send_frame(Sock, Frame).


-doc "Purpose:\n"
     "Waits for the next request frame from the client after the handshake and token "
     "exchange. Decodes the received binary into a term and dispatches it for handling. "
     "If an error occurs or no frame is received, the connection is closed.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket connected to the client.\n"
     "- `FP :: binary()` — the client certificate fingerprint.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — the success value returned by handle_req/3.\n"
     "- `ok` — if the connection is closed due to error or termination.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec await_request(ssl:sslsocket(), binary()) -> term() | ok.
await_request(Sock, FP) ->
    case trust_util:recv_frame(Sock, 2000) of
        {ok, Bin} -> handle_req(Sock, FP, safe_term(Bin));
        {error, _} -> ssl:close(Sock)
    end.


-doc "Purpose:\n"
     "Handles an incoming client request. If the request is a valid call frame, verifies "
     "permissions and executes the specified Module, Function, and Arguments (MFA) with the provided arguments. Sends the "
     "result back to the client and closes the connection. If the client lacks permissions, "
     "sends nothing, increments suspicion, and closes the connection. Malformed or unexpected "
     "frames are also treated as suspicious and result in connection termination.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket connected to the client.\n"
     "- `FP :: binary()` — the client certificate fingerprint.\n"
     "- `Req :: map()` — the decoded client request frame.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the connection is closed after handling the request or suspicion bump.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec handle_req(ssl:sslsocket(), binary(), map()) -> ok.
handle_req(Sock, FP, #{t := call, m := M, f := F, a := A, args := Args} = Req) ->
    case trust_whitelist:check(FP, {M,F,A}) of
        allowed ->
            try
                Res = apply(M, F, Args),
                trust_util:send_frame(Sock, term_to_binary(#{t => result, req_id => maps:get(req_id, Req, <<>>), value => Res})),
                ssl:close(Sock),
		trust_suspicion:bump(FP, down)
            catch _:_ ->
                trust_suspicion:bump(FP, up),
                ssl:close(Sock)
            end;
        denied ->
            trust_suspicion:bump(FP, up),
            ssl:close(Sock)
    end;
handle_req(Sock, FP, _Other) ->
    trust_suspicion:bump(FP, up),
    ssl:close(Sock).






-doc "Purpose:\n"
     "Safely decodes a binary into an Erlang term. If decoding fails or the binary is unsafe, "
     "returns a sentinel map instead of raising an exception.\n"
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
