-module(semp_events).

-export([emit/3]).


-doc "Purpose:\n"
     "Emits a SEMP event by delegating to `telemetry:execute/3`. This provides\n"
     "a thin wrapper for consistent instrumentation within the TRUST system.\n"
     "\n"
     "Parameters:\n"
     "- `Name :: telemetry:event_name()` — the event name, usually a list of atoms.\n"
     "- `Measurements :: map()` — numeric measurement values for the event.\n"
     "- `Metadata :: map()` — additional context data for the event.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — telemetry event was dispatched successfully.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-29\n".

-spec emit(telemetry:event_name(), map(), map()) -> ok.
emit(Name, Measurements, Metadata) ->
    %% thin shim over telemetry
    telemetry:execute(Name, Measurements, Metadata).

