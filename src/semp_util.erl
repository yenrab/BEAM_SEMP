-module(semp_util).
-include_lib("public_key/include/public_key.hrl").
-export([send_frame/2, recv_frame/2,fp_hex/1,
         cert_fingerprint_sha512/1, constant_time_eq/2]).

-doc "Purpose:\n"
     "Sends a framed payload over a TLS socket. Prepends the payload with a 32-bit unsigned length "
     "header before transmitting. Logs and returns `fail` if the payload cannot be sent.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket to send data on.\n"
     "- `Payload :: binary()` — the binary payload to transmit.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the payload was successfully sent.\n"
     "- `fail` — the send operation failed (logged with details).\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec send_frame(ssl:sslsocket(), binary()) -> ok | fail.
send_frame(Sock, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    ok = ssl:send(Sock, <<Len:32/unsigned-big>>),
    case ssl:send(Sock, Payload) of
	    ok-> ok;
	    FailureReason -> logger:debug("Failed to send payload ~p~non socket ~p.~n Cause ~p~n",[Payload,Sock,FailureReason]),
			     fail
    end.




-doc "Purpose:\n"
     "Receives a framed payload from a TLS socket. Reads a 32-bit unsigned length prefix first, "
     "then attempts to read the specified number of bytes as the payload. Rejects frames larger "
     "than 8 MB or malformed headers.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket to receive data from.\n"
     "- `Timeout :: integer()` — timeout in milliseconds for each recv operation.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, Payload :: binary()}` — the payload was received successfully.\n"
     "- `{error, bad_frame}` — the frame header was invalid.\n"
     "- `{error, timeout}` — receive timed out.\n"
     "- `{error, closed}` — the socket was closed.\n"
     "- `Other :: term()` — any other error tuple from `ssl:recv/3`.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec recv_frame(ssl:sslsocket(), integer()) ->
          {ok, binary()}
        | {error, bad_frame}
        | {error, timeout}
        | {error, closed}
        | term().
recv_frame(Sock, Timeout) ->
    case ssl:recv(Sock, 4, Timeout) of
        {ok, <<Len:32/unsigned-big>>} when Len =< 8*1024*1024 ->
            ssl:recv(Sock, Len, Timeout);
        {ok, _Bad} ->
            {error, bad_frame};
        {error, timeout} ->
            {error, timeout};
        {error, closed} ->
            {error, closed};
        Other -> Other
    end.



-doc "Purpose:\n"
     "Computes a SHA-512 fingerprint of a DER-encoded certificate.\n"
     "\n"
     "Parameters:\n"
     "- `CertDer :: binary()` — the DER-encoded certificate binary.\n"
     "\n"
     "Return Value:\n"
     "- `FP :: binary()` — the 64-byte (512-bit) raw fingerprint.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-02\n".

-spec cert_fingerprint_sha512(binary()) -> binary().
cert_fingerprint_sha512(CertDer) when is_binary(CertDer) ->
    %% 64-byte (512-bit) raw fingerprint
    crypto:hash(sha512, CertDer).
%%helper for printing
fp_hex(FP) when is_binary(FP) ->
    list_to_binary([ io_lib:format("~2.16.0b", [B]) || <<B>> <= FP ]).


-doc "Purpose:\n"
     "Performs a constant-time equality check between two binaries to mitigate timing attacks. "
     "Compares each byte of both binaries regardless of differences, ensuring runtime depends "
     "only on input size.\n"
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

-spec constant_time_eq(binary(), binary()) -> boolean().
constant_time_eq(A, B) when is_binary(A), is_binary(B) ->
    SzA = byte_size(A), SzB = byte_size(B),
    Mask0 = SzA bxor SzB,
    Limit = erlang:min(SzA, SzB),
    Acc = lists:foldl(
            fun(I,Acc0) ->
                <<_:I/binary, BA:8, _/binary>> = A,
                <<_:I/binary, BB:8, _/binary>> = B,
                Acc0 bor (BA bxor BB)
            end, Mask0, lists:seq(0, Limit-1)),
    (Mask0 =:= 0) andalso (Acc =:= 0).
