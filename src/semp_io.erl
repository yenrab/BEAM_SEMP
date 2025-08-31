-module(semp_io).
-export([print_color/3]).



%% Map color names to ANSI codes
ansi(reset)  -> "\e[0m";
ansi(bold)   -> "\e[1m";
ansi(inv)    -> "\e[7m";
ansi(red)    -> "\e[31m";
ansi(yellow) -> "\e[33m";
ansi(green)  -> "\e[32m";
ansi(cyan)   -> "\e[36m";
ansi([])     -> "";
ansi(List) when is_list(List) ->
    lists:flatten([ansi(X) || X <- List]);
ansi(Other) ->
    ansi([Other]).  %% allow a single atom too

%% Print that works before logger is up; takes a ColorSpec
print_color(ColorSpec, Fmt, Args) ->
    Prefix = ansi(ColorSpec),
    Suffix = ansi(reset),
    Line   = [Prefix, io_lib:format(Fmt, Args), Suffix, $\n],
    put_line(Line).



%% Write once to stderr; fall back to user, then group leader only if needed.
put_line(IOData) ->
    Line = [IOData, $\n],
    case catch io:put_chars(standard_error, Line) of
        ok -> ok;
        {'EXIT', _} -> try_user(Line);
        {error, _}  -> try_user(Line)
    end.

try_user(Line) ->
    case catch io:put_chars(user, Line) of
        ok -> ok;
        _  -> try_gl(Line)
    end.

try_gl(Line) ->
    case catch io:put_chars(group_leader(), Line) of
        ok -> ok;
        _  -> ok
    end.
