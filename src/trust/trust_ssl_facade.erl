%% @doc SSL facade module for trust connections.
%% This module provides a stable interface to SSL operations that can be easily mocked in tests.
-module(trust_ssl_facade).
-export([
    setopts/2,
    peername/1,
    peercert/1,
    controlling_process/2,
    close/1,
    send/2,
    transport_accept/2
]).

%% @doc Set socket options (active, etc.)
-spec setopts(ssl:socket(), [ssl:ssloption()]) -> ok | {error, term()}.
setopts(Socket, Opts) ->
    ssl:setopts(Socket, Opts).

%% @doc Get peer name information
-spec peername(ssl:socket()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
peername(Socket) ->
    ssl:peername(Socket).

%% @doc Get peer certificate
-spec peercert(ssl:socket()) -> {ok, binary()} | {error, term()}.
peercert(Socket) ->
    ssl:peercert(Socket).

%% @doc Transfer socket ownership to another process
-spec controlling_process(ssl:socket(), pid()) -> ok | {error, term()}.
controlling_process(Socket, Pid) ->
    ssl:controlling_process(Socket, Pid).

%% @doc Close the SSL socket
-spec close(ssl:socket()) -> ok | {error, term()}.
close(Socket) ->
    ssl:close(Socket).

%% @doc Send data over SSL socket
-spec send(ssl:socket(), iodata()) -> ok | {error, term()}.
send(Socket, Data) ->
    ssl:send(Socket, Data).

%% @doc Accept transport connection
-spec transport_accept(ssl:socket(), timeout()) -> {ok, ssl:socket()} | {error, term()}.
transport_accept(LSocket, Timeout) ->
    ssl:transport_accept(LSocket, Timeout).

