-module(crypto_sHA3@foreign).
-export([fromString/1, toHex/1, hashImpl/0]).

%% purerl String is a utf8 binary already.
fromString(S) -> S.

toHex(B) -> binary:encode_hex(B, lowercase).

%% PS type is `Fn4 Binary Int Int Int Binary` — zero arrows — so the
%% export is arity 0 and the *value* is an arity-4 fun, which is exactly
%% what runFn4 applies. Exporting hashImpl/4 instead makes purerl curry
%% it into fun(A) -> fun(B) -> ..., and runFn4 then badaritys.
hashImpl() -> fun sha3_nif:hash/4.