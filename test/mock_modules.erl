%%%-------------------------------------------------------------------
%% @doc Mock modules for unit testing.
%% @end
%%%-------------------------------------------------------------------

-module(mock_modules).
-export([
    mock_ssl/0,
    mock_semp_facades/0,
    mock_trust_token/0,
    mock_trust_suspicion/0,
    mock_semp_whitelist/0,
    mock_semp_policy/0,
    unmock_all/0
]).

%%--------------------------------------------------------------------
%% @doc Mocks SSL module for testing.
%% @end
%%--------------------------------------------------------------------
mock_ssl() ->
    case meck:validate(ssl) of
        false -> meck:new(ssl, [unstick, passthrough]);
        _ -> ok
    end,
    
    %% Mock SSL functions
    meck:expect(ssl, setopts, fun(_Socket, _Opts) -> ok end),
    meck:expect(ssl, peername, fun(_Socket) -> {ok, {{127,0,0,1}, 12345}} end),
    meck:expect(ssl, peercert, fun(_Socket) -> {ok, <<"test_certificate">>} end),
    meck:expect(ssl, send, fun(_Socket, _Data) -> ok end),
    meck:expect(ssl, recv, fun(_Socket, _Length, _Timeout) -> {ok, <<"test_data">>} end),
    meck:expect(ssl, controlling_process, fun(_Socket, _Pid) -> ok end),
    meck:expect(ssl, close, fun(_Socket) -> ok end),
    meck:expect(ssl, handshake, fun(_Socket, _Timeout) -> ok end),
    meck:expect(ssl, negotiated_protocol, fun(_Socket) -> {ok, <<"trust/1">>} end),
    meck:expect(ssl, listen, fun(_Port, _Opts) -> {ok, {test_socket, make_ref()}} end),
    meck:expect(ssl, connect, fun(_IP, _Port, _Opts, _Timeout) -> {ok, {test_socket, make_ref()}} end),
    meck:expect(ssl, transport_accept, fun(_Socket, _Timeout) -> 
        {ok, {test_socket, make_ref()}} 
    end),
    
    ok.

%%--------------------------------------------------------------------
%% @doc Mocks semp_facades module for testing.
%% @end
%%--------------------------------------------------------------------
mock_semp_facades() ->
    %% Check current validation status (safely)
    ValidationResult = case catch meck:validate(semp_facades) of
        {'EXIT', {not_mocked, _}} -> false;
        Result -> Result
    end,
    
    %% Try to create the mock without passthrough first
    case ValidationResult of
        false -> 
            case meck:new(semp_facades, [unstick]) of
                ok -> ok;
                {error, {already_started, _}} -> ok;
                {error, Reason} -> 
                    %% If that fails, try with passthrough
                    case meck:new(semp_facades, [unstick, passthrough]) of
                        ok -> ok;
                        {error, {already_started, _}} -> ok;
                        {error, _} -> 
                            error({mock_creation_failed, semp_facades, Reason})
                    end
            end;
        _ -> ok
    end,
    
    %% Mock SSL facade functions
    meck:expect(semp_facades, setopts, fun(_Socket, _Opts) -> ok end),
    meck:expect(semp_facades, peername, fun(_Socket) -> {ok, {{127,0,0,1}, 12345}} end),
    meck:expect(semp_facades, peercert, fun(_Socket) -> {ok, <<"test_certificate">>} end),
    meck:expect(semp_facades, send, fun(_Socket, _Data) -> ok end),
    meck:expect(semp_facades, recv, fun(_Socket, _Length, _Timeout) -> {ok, <<"test_data">>} end),
    meck:expect(semp_facades, controlling_process, fun(_Socket, _Pid) -> ok end),
    meck:expect(semp_facades, close, fun(_Socket) -> ok end),
    meck:expect(semp_facades, handshake, fun(_Socket, _Timeout) -> ok end),
    meck:expect(semp_facades, negotiated_protocol, fun(_Socket) -> {ok, <<"trust/1">>} end),
    meck:expect(semp_facades, listen, fun(_Port, _Opts) -> {ok, {test_socket, make_ref()}} end),
    meck:expect(semp_facades, connect, fun(_IP, _Port, _Opts, _Timeout) -> {ok, {test_socket, make_ref()}} end),
    meck:expect(semp_facades, transport_accept, fun(_Socket, _Timeout) -> 
        {ok, {test_socket, make_ref()}} 
    end),
    
    %% Note: semp_facades should NOT contain facade functions for internal semp/trust modules
    %% (trust_token, trust_suspicion, semp_whitelist, semp_policy). These should be mocked directly.
    %% Only external dependencies (SSL, inet, io, persistent_term) go through facades.
    
    ok.

%%--------------------------------------------------------------------
mock_trust_token() ->
    %% Safely determine if the module is already mocked
    ValidationResult = case catch meck:validate(trust_token) of
        {'EXIT', {not_mocked, _}} -> false;
        Result -> Result
    end,
    
    %% Create the mock (only if not already mocked)
    case ValidationResult of
        false ->
            case meck:new(trust_token, [unstick, passthrough]) of
                ok -> ok;
                {error, {already_started, _}} -> ok;
                {error, _Reason} ->
                    %% If that fails, try unloading first (but catch errors)
                    try meck:unload(trust_token) catch _:_ -> ok end,
                    case meck:new(trust_token, [unstick, passthrough]) of
                        ok -> ok;
                        {error, {already_started, _}} -> ok;
                        {error, Reason2} -> 
                            error({mock_creation_failed, trust_token, Reason2})
                    end
            end;
        _ -> 
            %% Already mocked, just update expectations
            ok
    end,
    
    %% Mock ensure/0 - just return ok (table should already exist)
    meck:expect(trust_token, ensure, fun() -> 
        ok
    end),
    
    %% Mock token validation - succeed for valid tokens, fail for invalid ones
    %% Note: trust_token:validate/2 returns ok on success, {error, Reason} on failure
    meck:expect(trust_token, validate, fun(Token, _FP) -> 
        case Token of
            <<"invalid_token">> -> {error, invalid_token};
            _ -> ok
        end
    end),
    
    %% Mock token issuance
    %% Note: trust_token:issue/1 returns true (from ets:insert/2)
    meck:expect(trust_token, issue, fun(_FP) -> 
        true
    end),
    
    %% Mock token retrieval
    meck:expect(trust_token, token_for, fun(_FP) -> 
        <<"test_token_", (integer_to_binary(erlang:system_time(microsecond)))/binary>>
    end),
    
    ok.

%%--------------------------------------------------------------------
%% @doc Mocks trust_suspicion module for testing.
%% @end
%%--------------------------------------------------------------------
mock_trust_suspicion() ->
    %% Safely determine if the module is already mocked
    ValidationResult = case catch meck:validate(trust_suspicion) of
        {'EXIT', {not_mocked, _}} -> false;
        Result -> Result
    end,
    
    %% Create the mock (prefer without passthrough; fall back if needed)
    case ValidationResult of
        false ->
            case meck:new(trust_suspicion, [unstick]) of
                ok -> ok;
                {error, {already_started, _}} -> ok;
                {error, _Reason} ->
                    %% Fall back to passthrough if plain mock creation fails
                    case meck:new(trust_suspicion, [unstick, passthrough]) of
                        ok -> ok;
                        {error, {already_started, _}} -> ok
                    end
            end;
        _ -> ok
    end,
    
    %% Mock API used throughout the codebase
    meck:expect(trust_suspicion, bump, fun(_ClientId, _Direction) -> ok end),
    meck:expect(trust_suspicion, is_trusted, fun(_ClientId) -> true end),
    
    %% Ensure integration setup paths do not touch real state
    meck:expect(trust_suspicion, ensure, fun() -> ok end),
    meck:expect(trust_suspicion, seed_from_whitelist, fun(_Tab) -> ok end),
    meck:expect(trust_suspicion, writePeer, fun(_ClientId) -> ok end),
    
    ok.

%%--------------------------------------------------------------------
%% @doc Mocks semp_whitelist module for testing.
%% @end
%%--------------------------------------------------------------------
mock_semp_whitelist() ->
    %% Safely determine if the module is already mocked
    ValidationResult = case catch meck:validate(semp_whitelist) of
        {'EXIT', {not_mocked, _}} -> false;
        Result -> Result
    end,
    
    %% Create the mock (prefer without passthrough; fall back if needed)
    case ValidationResult of
        false ->
            case meck:new(semp_whitelist, [unstick]) of
                ok -> ok;
                {error, {already_started, _}} -> ok;
                {error, _Reason} ->
                    %% Fall back to passthrough if plain mock creation fails
                    case meck:new(semp_whitelist, [unstick, passthrough]) of
                        ok -> ok;
                        {error, {already_started, _}} -> ok
                    end
            end;
        _ -> ok
    end,
    
    %% Mock whitelist checking
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> 
        true 
    end),
    
    %% Mock whitelist spec retrieval (allow all by default)
    meck:expect(semp_whitelist, spec, fun(_Type, _ClientId) -> 
        any 
    end),
    
    %% Mock whitelist table
    meck:expect(semp_whitelist, table, fun(_Type) -> 
        test_whitelist 
    end),
    
    ok.

%%--------------------------------------------------------------------
%% @doc Mocks semp_policy module for testing.
%% @end
%%--------------------------------------------------------------------
mock_semp_policy() ->
    %% Safely determine if the module is already mocked
    ValidationResult = case catch meck:validate(semp_policy) of
        {'EXIT', {not_mocked, _}} -> false;
        Result -> Result
    end,
    
    %% Create the mock (prefer without passthrough; fall back if needed)
    case ValidationResult of
        false ->
            case meck:new(semp_policy, [unstick]) of
                ok -> ok;
                {error, {already_started, _}} -> ok;
                {error, _Reason} ->
                    %% Fall back to passthrough if plain mock creation fails
                    case meck:new(semp_policy, [unstick, passthrough]) of
                        ok -> ok;
                        {error, {already_started, _}} -> ok
                    end
            end;
        _ -> ok
    end,
    
    %% Mock policy checking - allow most MFAs
    meck:expect(semp_policy, is_forbidden, fun(M, F, A) -> 
        %% Block dangerous functions
        case {M, F, A} of
            {os, cmd, _} -> true;
            {file, delete, _} -> true;
            {code, load_binary, _} -> true;
            _ -> false
        end
    end),
    
    ok.

%%--------------------------------------------------------------------
%% @doc Unmocks all modules.
%% @end
%%--------------------------------------------------------------------
unmock_all() ->
    meck:unload(),
    ok.
