-module(sha3_nif).
-export([hash/4]).
-on_load(init/0).

init() ->
    Priv = case code:priv_dir(purescript_sha3) of
        {error, bad_name} -> "priv";
        Dir -> Dir
    end,
    erlang:load_nif(filename:join(Priv, "sha3_nif"), 0).

%% hash(Input :: binary(), RateBytes, OutLen, DomainSep) -> binary()
hash(_Input, _Rate, _OutLen, _Ds) ->
    erlang:nif_error(nif_not_loaded).
