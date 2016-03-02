-module(totp).

-export([cons/1, cons/2]).


-ifdef(TEST).
-export([tests_rfc6238/0]).
-endif.

cons(<<Secret/binary>>) -> cons(Secret, []).

cons(<<Secret/binary>>, Opts) ->
  HashAlgo = proplists:get_value(hash_algo, Opts, sha),
  Length   = proplists:get_value(length,    Opts, 8),
  TimeZero = proplists:get_value(time_zero, Opts, 0),
  TimeNow  = proplists:get_value(time_now,  Opts, time_now()),
  TimeStep = proplists:get_value(time_step, Opts, 30),
  Time     = time_interval(TimeZero, TimeNow, TimeStep),
  HOTPOpts = [ {hash_algo, HashAlgo}
             , {length,    Length}
             ],
  hotp:cons(Secret, Time, HOTPOpts).

time_interval(TimeZero, TimeNow, TimeStep) ->
  trunc((TimeNow - TimeZero) / TimeStep).

time_now() ->
  {MegaSeconds, Seconds, _} = os:timestamp(),
  MegaSeconds * 1000000 + Seconds.


%%%===================================================================
%%% Tests from RFC 6238 (https://tools.ietf.org/html/rfc6238#appendix-B)
%%%===================================================================

-ifdef(TEST).
-record(test_case,
        {secret      :: binary(),
         time_step   :: integer(),
         t0          :: integer(),
         time        :: integer(),
         t_in_hex    :: binary(),
         mode        :: hmac:hash_algo(),
         totp_digits :: integer(),
         totp_value  :: integer()}).

tests_rfc6238() ->
  lists:foreach(fun test_case_execute/1, test_cases_from_rfc6238()).

test_case_execute(#test_case
                  { secret      = Secret1
                  , time_step   = TimeStep
                  , t0          = TimeZero
                  , time        = TimeNow
                  , t_in_hex    = TimeHexPadded
                  , mode        = HashAlgo
                  , totp_digits = Length
                  , totp_value  = TOTPValue
                  }
                 ) ->
  Time          = time_interval(TimeZero, TimeNow, TimeStep),
  TimeHexPadded = t_to_padded_hex(Time),
  TOTPOpts      = [ {hash_algo, HashAlgo}
                  , {length,    Length}
                  , {time_zero, TimeZero}
                  , {time_now,  TimeNow}
                  , {time_step, TimeStep}
                  ],
  TOTPValue = cons(Secret1, TOTPOpts).

-spec t_to_padded_hex(integer()) -> binary().
t_to_padded_hex(T) ->
  THex    = integer_to_list(T, 16),
  THexPad = lists:duplicate(16 - length(THex), $0),
  list_to_binary([THexPad, THex]).

test_cases_from_rfc6238() ->
  Secret20 = <<"12345678901234567890">>,
  Secret32 = <<"12345678901234567890123456789012">>,
  Secret64 = <<"1234567890123456789012345678901234567890123456789012345678901234">>,
  TimeStep = 30,
  T0       = 0,
  [ #test_case{ secret      = Secret20
              , time_step   = TimeStep
              , t0          = T0
              , time        = 59
              , t_in_hex    = <<"0000000000000001">>
              , mode        = sha
              , totp_digits = 8
              , totp_value  = 94287082
              }
  , #test_case{ secret      = Secret32
              , time_step   = TimeStep
              , t0          = T0
              , time        = 59
              , t_in_hex    = <<"0000000000000001">>
              , mode        = sha256
              , totp_digits = 8
              , totp_value  = 46119246
              }
  , #test_case{ secret      = Secret64
              , time_step   = TimeStep
              , t0          = T0
              , time        = 59
              , t_in_hex    = <<"0000000000000001">>
              , mode        = sha512
              , totp_digits = 8
              , totp_value  = 90693936
              }
  , #test_case{ secret      = Secret20
              , time_step   = TimeStep
              , t0          = T0
              , time        = 1111111109
              , t_in_hex    = <<"00000000023523EC">>
              , mode        = sha
              , totp_digits = 8
              , totp_value  = 07081804
              }
  , #test_case{ secret      = Secret32
              , time_step   = TimeStep
              , t0          = T0
              , time        = 1111111109
              , t_in_hex    = <<"00000000023523EC">>
              , mode        = sha256
              , totp_digits = 8
              , totp_value  = 68084774
              }
  , #test_case{ secret      = Secret64
              , time_step   = TimeStep
              , t0          = T0
              , time        = 1111111109
              , t_in_hex    = <<"00000000023523EC">>
              , mode        = sha512
              , totp_digits = 8
              , totp_value  = 25091201
              }
  , #test_case{ secret      = Secret20
              , time_step   = TimeStep
              , t0          = T0
              , time        = 1111111111
              , t_in_hex    = <<"00000000023523ED">>
              , mode        = sha
              , totp_digits = 8
              , totp_value  = 14050471
              }
  , #test_case{ secret      = Secret32
              , time_step   = TimeStep
              , t0          = T0
              , time        = 1111111111
              , t_in_hex    = <<"00000000023523ED">>
              , mode        = sha256
              , totp_digits = 8
              , totp_value  = 67062674
              }
  , #test_case{ secret      = Secret64
              , time_step   = TimeStep
              , t0          = T0
              , time        = 1111111111
              , t_in_hex    = <<"00000000023523ED">>
              , mode        = sha512
              , totp_digits = 8
              , totp_value  = 99943326
              }
  , #test_case{ secret      = Secret20
              , time_step   = TimeStep
              , t0          = T0
              , time        = 1234567890
              , t_in_hex    = <<"000000000273EF07">>
              , mode        = sha
              , totp_digits = 8
              , totp_value  = 89005924
              }
  , #test_case{ secret      = Secret32
              , time_step   = TimeStep
              , t0          = T0
              , time        = 1234567890
              , t_in_hex    = <<"000000000273EF07">>
              , mode        = sha256
              , totp_digits = 8
              , totp_value  = 91819424
              }
  , #test_case{ secret      = Secret64
              , time_step   = TimeStep
              , t0          = T0
              , time        = 1234567890
              , t_in_hex    = <<"000000000273EF07">>
              , mode        = sha512
              , totp_digits = 8
              , totp_value  = 93441116
              }
  , #test_case{ secret      = Secret20
              , time_step   = TimeStep
              , t0          = T0
              , time        = 2000000000
              , t_in_hex    = <<"0000000003F940AA">>
              , mode        = sha
              , totp_digits = 8
              , totp_value  = 69279037
              }
  , #test_case{ secret      = Secret32
              , time_step   = TimeStep
              , t0          = T0
              , time        = 2000000000
              , t_in_hex    = <<"0000000003F940AA">>
              , mode        = sha256
              , totp_digits = 8
              , totp_value  = 90698825
              }
  , #test_case{ secret      = Secret64
              , time_step   = TimeStep
              , t0          = T0
              , time        = 2000000000
              , t_in_hex    = <<"0000000003F940AA">>
              , mode        = sha512
              , totp_digits = 8
              , totp_value  = 38618901
              }
  , #test_case{ secret      = Secret20
              , time_step   = TimeStep
              , t0          = T0
              , time        = 20000000000
              , t_in_hex    = <<"0000000027BC86AA">>
              , mode        = sha
              , totp_digits = 8
              , totp_value  = 65353130
              }
  , #test_case{ secret      = Secret32
              , time_step   = TimeStep
              , t0          = T0
              , time        = 20000000000
              , t_in_hex    = <<"0000000027BC86AA">>
              , mode        = sha256
              , totp_digits = 8
              , totp_value  = 77737706
              }
  , #test_case{ secret      = Secret64
              , time_step   = TimeStep
              , t0          = T0
              , time        = 20000000000
              , t_in_hex    = <<"0000000027BC86AA">>
              , mode        = sha512
              , totp_digits = 8
              , totp_value  = 47863826
              }
  ].
-endif.
