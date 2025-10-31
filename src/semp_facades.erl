%%%-------------------------------------------------------------------
%% @doc semp_facades - Facade module for external dependencies only (SSL, inet, io, etc.).
%% This module provides a stable interface to external library operations
%% that can be easily mocked in tests.
%%
%% Note: Internal semp/trust modules (semp_whitelist, semp_policy, trust_token,
%% trust_suspicion) should NOT be wrapped in facades and should be mocked directly.
%% @end
%%%-------------------------------------------------------------------

-module(semp_facades).
-export([
    %% SSL socket operations
    setopts/2,
    peername/1,
    peercert/1,
    controlling_process/2,
    close/1,
    send/2,
    recv/3,
    
    %% SSL connection operations
    handshake/2,
    negotiated_protocol/1,
    listen/2,
    connect/4,
    transport_accept/2,
    
    %% inet operations (for DNS resolution)
    inet_parse_address/1,
    inet_getaddrs/2,
    
    %% io operations
    io_put_chars/2,
    
    %% persistent_term operations
    persistent_term_get/1
]).

%%--------------------------------------------------------------------
%% @doc Set socket options (active, mode, etc.)
%% @end
%%--------------------------------------------------------------------
-spec setopts(ssl:socket(), [ssl:ssloption()]) -> ok | {error, term()}.
setopts(Socket, Opts) ->
    ssl:setopts(Socket, Opts).

%%--------------------------------------------------------------------
%% @doc Get peer name information
%% @end
%%--------------------------------------------------------------------
-spec peername(ssl:socket()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
peername(Socket) ->
    ssl:peername(Socket).

%%--------------------------------------------------------------------
%% @doc Get peer certificate
%% @end
%%--------------------------------------------------------------------
-spec peercert(ssl:socket()) -> {ok, binary()} | {error, term()}.
peercert(Socket) ->
    ssl:peercert(Socket).

%%--------------------------------------------------------------------
%% @doc Transfer socket ownership to another process
%% @end
%%--------------------------------------------------------------------
-spec controlling_process(ssl:socket(), pid()) -> ok | {error, term()}.
controlling_process(Socket, Pid) ->
    ssl:controlling_process(Socket, Pid).

%%--------------------------------------------------------------------
%% @doc Close the SSL socket
%% @end
%%--------------------------------------------------------------------
-spec close(ssl:socket()) -> ok | {error, term()}.
close(Socket) ->
    ssl:close(Socket).

%%--------------------------------------------------------------------
%% @doc Send data over SSL socket
%% @end
%%--------------------------------------------------------------------
-spec send(ssl:socket(), iodata()) -> ok | {error, term()}.
send(Socket, Data) ->
    ssl:send(Socket, Data).

%%--------------------------------------------------------------------
%% @doc Receive data from SSL socket
%% @end
%%--------------------------------------------------------------------
-spec recv(ssl:socket(), integer(), timeout()) -> {ok, binary()} | {error, term()}.
recv(Socket, Length, Timeout) ->
    ssl:recv(Socket, Length, Timeout).

%%--------------------------------------------------------------------
%% @doc Perform SSL handshake
%% @end
%%--------------------------------------------------------------------
-spec handshake(ssl:socket(), timeout()) -> ok | {ok, ssl:socket()} | {error, term()}.
handshake(Socket, Timeout) ->
    ssl:handshake(Socket, Timeout).

%%--------------------------------------------------------------------
%% @doc Get negotiated protocol (ALPN)
%% @end
%%--------------------------------------------------------------------
-spec negotiated_protocol(ssl:socket()) -> {ok, binary()} | {error, term()}.
negotiated_protocol(Socket) ->
    ssl:negotiated_protocol(Socket).

%%--------------------------------------------------------------------
%% @doc Listen for SSL connections
%% @end
%%--------------------------------------------------------------------
-spec listen(inet:port_number(), [ssl:ssloption()]) -> {ok, ssl:socket()} | {error, term()}.
listen(Port, Options) ->
    ssl:listen(Port, Options).

%%--------------------------------------------------------------------
%% @doc Connect to SSL server
%% @end
%%--------------------------------------------------------------------
-spec connect(inet:ip_address(), inet:port_number(), [ssl:ssloption()], timeout()) -> 
    {ok, ssl:socket()} | {error, term()}.
connect(IP, Port, Options, Timeout) ->
    ssl:connect(IP, Port, Options, Timeout).

%%--------------------------------------------------------------------
%% @doc Accept transport connection
%% @end
%%--------------------------------------------------------------------
-spec transport_accept(ssl:socket(), timeout()) -> {ok, ssl:socket()} | {error, term()}.
transport_accept(LSocket, Timeout) ->
    ssl:transport_accept(LSocket, Timeout).

%%--------------------------------------------------------------------
%% @doc inet operations - facades for inet module
%% @end
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc Parse an IP address string
%% @end
%%--------------------------------------------------------------------
-spec inet_parse_address(string()) -> {ok, inet:ip_address()} | {error, term()}.
inet_parse_address(Host) ->
    inet:parse_address(Host).

%%--------------------------------------------------------------------
%% @doc Get address list for a hostname
%% @end
%%--------------------------------------------------------------------
-spec inet_getaddrs(string(), inet | inet6) -> {ok, [inet:ip_address()]} | {error, term()}.
inet_getaddrs(Host, Family) ->
    inet:getaddrs(Host, Family).

%%--------------------------------------------------------------------
%% @doc io operations - facades for io module
%% @end
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc Put characters to a device
%% @end
%%--------------------------------------------------------------------
-spec io_put_chars(io:device(), iodata()) -> ok | {error, term()}.
io_put_chars(Device, Chars) ->
    io:put_chars(Device, Chars).

%%--------------------------------------------------------------------
%% @doc persistent_term operations - facades for persistent_term module
%% @end
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc Get a value from persistent_term storage
%% @end
%%--------------------------------------------------------------------
-spec persistent_term_get(term()) -> term().
persistent_term_get(Key) ->
    persistent_term:get(Key).
