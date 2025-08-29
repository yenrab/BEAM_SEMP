-module(semp_util).
-include_lib("public_key/include/public_key.hrl").
-export([send_frame/2, recv_frame/2,
         cert_fingerprint_sha512/1, constant_time_eq/2]).

send_frame(Sock, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    ok = ssl:send(Sock, <<Len:32/unsigned-big>>),
    ssl:send(Sock, Payload).

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

%% Prefer hashing TBSCertificate (stable identity); fallback to full DER on decode error.
cert_fingerprint_sha512(CertBin) ->
    try public_key:pkix_decode_cert(CertBin, otp) of
        #'OTPCertificate'{tbsCertificate = TBS} ->
            DER = public_key:pkix_encode('TBSCertificate', TBS, otp),
            bin_sha512_hex(DER)
    catch _:_ ->
            bin_sha512_hex(CertBin)
    end.

bin_sha512_hex(B) ->
    <<H:512/integer>> = crypto:hash(sha512, B),
    list_to_binary(io_lib:format("~64.16.0b", [H])).

%% Constant-time equality for same-length binaries; returns false for length mismatch.
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
