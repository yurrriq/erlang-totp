.PHONY: all, compile, clean, dialyze, test

all: travis_ci dialyze

travis_ci: clean test

compile: ; @rebar3 compile

clean: ; @rebar3 clean

dialyze:; ; @rebar3 dialyzer

test: ; @rebar3 ct
