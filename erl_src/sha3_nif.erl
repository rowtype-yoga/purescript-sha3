-module(sha3_nif).
-export([hash/4]).
-on_load(init/0).

init() ->
    Path = case os:getenv("SHA3_NIF_SO") of
        false -> "priv/sha3_nif";
        P -> P
    end,
    erlang:load_nif(Path, 0).

%% hash(Input :: binary(), RateBytes, OutLenBytes, DomainSep) -> binary()
hash(_Input, _Rate, _OutLen, _Ds) ->
    erlang:nif_error(nif_not_loaded).