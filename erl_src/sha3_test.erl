%% Start of ./erl_src/sha3_test.erl
-module(sha3_test).
-export([run/0]).

%% FIPS 202 vectors: SHA3-256 of empty input and of "abc"
run() ->
    Empty = <<16#a7,16#ff,16#c6,16#f8,16#bf,16#1e,16#d7,16#66,
              16#51,16#c1,16#47,16#56,16#a0,16#61,16#d6,16#62,
              16#f5,16#80,16#ff,16#4d,16#e4,16#3b,16#49,16#fa,
              16#82,16#d8,16#0a,16#4b,16#80,16#f8,16#43,16#4a>>,
    Empty = sha3_nif:hash(<<>>, 136, 32, 16#06),
    Abc = crypto:hash(sha3_256, <<"abc">>),
    Abc = sha3_nif:hash(<<"abc">>, 136, 32, 16#06),
    Big = crypto:hash(sha3_512, binary:copy(<<"x">>, 1000000)),
    Big = sha3_nif:hash(binary:copy(<<"x">>, 1000000), 72, 64, 16#06),
    io:format("sha3_nif: all vectors pass~n").
%% End of ./erl_src/sha3_test.erl
