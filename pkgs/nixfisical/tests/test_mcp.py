"""Offline tests for :mod:`nixfisical.mcp`.

Same criterion as the other suites: cover what fails *quietly*. For an MCP
server that is a narrow and unusual set, because the loud failures are already
loud -- a protocol bug closes the session and a wrong URL raises.

What is quiet here is:

- **A secret in the output.** Nothing crashes. The value goes into a transcript
  and stays there. The whitelist in :func:`nixfisical.mcp._secret_names` is the
  only thing standing between an API response and that, so it is tested against
  the shape of the failure rather than the shape of today's API object: an
  unknown field must not come through, because the field that leaks will be one
  nobody thought to blacklist.
- **A write from a read-only server.** A gate that is checked in the wrong
  place, or advertised in `tools/list` and refused at call time, looks like a
  working server right up until it is not.
- **A prune that nobody agreed to.** `confirmDeletions` has to be a count the
  caller can only have got from a diff, and a mismatch has to abort *before*
  anything is written.
- **A response to a notification.** Clients are not tracking that id. Some
  ignore it, some drop the connection; either way the bug is in this file and
  the symptom is somewhere else entirely.

Nothing here talks to a server. Every tool that would is exercised through its
gate, which is reached before the client is ever opened.
"""

import io
import json

import pytest

from nixfisical.mcp import (
    LATEST_PROTOCOL,
    Server,
    Session,
    ToolError,
    _secret_names,
    _t_sync_apply,
    serve,
)


@pytest.fixture
def session(tmp_path) -> Session:
    """A session pointed at nothing. No tool reached here gets as far as a socket."""
    return Session(url="http://127.0.0.1:1", admin_file=tmp_path / "admin.yaml")


def _request(method: str, params: dict | None = None, rid: int | None = 1) -> dict:
    message: dict = {"jsonrpc": "2.0", "method": method}
    if rid is not None:
        message["id"] = rid
    if params is not None:
        message["params"] = params
    return message


# -- redaction -------------------------------------------------------------
#
# The one test in this file that is about a value rather than a control flow.


def test_secret_values_are_never_returned() -> None:
    out = _secret_names(
        [{"secretKey": "DB_PASSWORD", "secretValue": "hunter2", "secretPath": "/"}]
    )
    assert out == [
        {"name": "DB_PASSWORD", "path": "/", "version": None, "updatedAt": None}
    ]
    assert "hunter2" not in json.dumps(out)


def test_unknown_fields_do_not_come_through() -> None:
    """The whole reason the implementation is a whitelist.

    A blacklist passes this suite today and fails the day Infisical adds a
    field -- and it fails by leaking, not by raising. `secretValueHidden` is a
    field that does not exist; that is the point of using it.
    """
    out = _secret_names(
        [
            {
                "secretKey": "API_KEY",
                "secretValue": "live-key",
                "secretComment": "rotate via vault entry 41",
                "secretValueHidden": "also-the-key",
                "secretMetadata": {"note": "still-the-key"},
            }
        ]
    )
    assert set(out[0]) == {"name", "path", "version", "updatedAt"}
    assert "key" not in json.dumps(out).replace("API_KEY", "")


def test_entries_without_a_name_are_dropped() -> None:
    """A nameless entry is an entry whose only content is its value."""
    assert _secret_names([{"secretValue": "orphan"}]) == []


def test_names_are_ordered_by_path_then_name() -> None:
    out = _secret_names(
        [
            {"secretKey": "B", "secretPath": "/app"},
            {"secretKey": "A", "secretPath": "/app"},
            {"secretKey": "Z", "secretPath": "/"},
        ]
    )
    assert [(e["path"], e["name"]) for e in out] == [("/", "Z"), ("/app", "A"), ("/app", "B")]


# -- the write gate --------------------------------------------------------


def test_read_only_server_does_not_list_the_mutating_tool(session: Session) -> None:
    names = [t["name"] for t in Server(session).handle(_request("tools/list"))["result"]["tools"]]
    assert "sync_diff" in names
    assert "sync_apply" not in names


def test_allow_writes_lists_it(session: Session) -> None:
    session.allow_writes = True
    names = [t["name"] for t in Server(session).handle(_request("tools/list"))["result"]["tools"]]
    assert "sync_apply" in names


def test_calling_an_unlisted_tool_is_refused(session: Session) -> None:
    """Not listed is not merely hidden. A client holding a stale tool list, or a
    model naming a tool it read about elsewhere, must not reach the handler."""
    response = Server(session).handle(
        _request("tools/call", {"name": "sync_apply", "arguments": {"manifest": "m.json"}})
    )
    assert response["result"]["isError"] is True
    assert "unknown tool" in response["result"]["content"][0]["text"]


def test_the_gate_is_in_the_handler_too(session: Session) -> None:
    """Belt and braces, deliberately. `available()` keeps the tool off the wire;
    this keeps it off even if some future caller reaches the handler directly."""
    with pytest.raises(ToolError, match="read-only"):
        _t_sync_apply(session, {"manifest": "m.json", "confirmDeletions": 0})


def test_apply_without_a_deletion_count_is_refused(session: Session) -> None:
    """Before the manifest is read, and long before the instance is touched."""
    session.allow_writes = True
    with pytest.raises(ToolError, match="confirmDeletions is required"):
        _t_sync_apply(session, {"manifest": "/nonexistent.json"})


def test_a_non_integer_count_is_refused(session: Session) -> None:
    session.allow_writes = True
    with pytest.raises(ToolError, match="must be an integer"):
        _t_sync_apply(session, {"manifest": "/nonexistent.json", "confirmDeletions": "all"})


# -- tool errors are results, not transport errors -------------------------


def test_a_failing_tool_is_an_error_result(session: Session) -> None:
    """`validate_manifest` on a path that is not there.

    The distinction under test: a model that receives a JSON-RPC error sees
    nothing (the client swallows it) and will do the same thing again. An error
    *result* is in the conversation and can be corrected for.
    """
    response = Server(session).handle(
        _request("tools/call", {"name": "validate_manifest", "arguments": {"manifest": "/nope.json"}})
    )
    assert "error" not in response
    assert response["result"]["isError"] is True
    assert "/nope.json" in response["result"]["content"][0]["text"]


def test_unknown_tool_name_is_also_a_result(session: Session) -> None:
    response = Server(session).handle(_request("tools/call", {"name": "rm_rf"}))
    assert "error" not in response
    assert response["result"]["isError"] is True


def test_an_unknown_method_is_a_transport_error(session: Session) -> None:
    """The other side of that line: a method that does not exist is the
    client's mistake, not the model's, and the model cannot fix it."""
    response = Server(session).handle(_request("resources/list"))
    assert response["error"]["code"] == -32601


# -- handshake -------------------------------------------------------------


def test_initialize_echoes_a_known_protocol(session: Session) -> None:
    result = Server(session).handle(
        _request("initialize", {"protocolVersion": "2024-11-05"})
    )["result"]
    assert result["protocolVersion"] == "2024-11-05"


def test_initialize_falls_back_for_an_unknown_one(session: Session) -> None:
    """The spec's instruction, and the reason this is not an error: a client
    asking for a version we do not have should be offered the newest we do."""
    result = Server(session).handle(
        _request("initialize", {"protocolVersion": "1999-01-01"})
    )["result"]
    assert result["protocolVersion"] == LATEST_PROTOCOL


def test_initialize_advertises_only_tools(session: Session) -> None:
    """No resources, no prompts. Claiming either brings a client's list request,
    which this server would answer with a method-not-found."""
    result = Server(session).handle(_request("initialize", {}))["result"]
    assert set(result["capabilities"]) == {"tools"}


def test_a_notification_gets_no_response(session: Session) -> None:
    assert Server(session).handle(_request("notifications/initialized", rid=None)) is None


def test_an_unknown_notification_gets_no_response(session: Session) -> None:
    """Silence, not a method-not-found. Nothing is waiting for either."""
    assert Server(session).handle(_request("some/future/notification", rid=None)) is None


# -- the transport ---------------------------------------------------------


def test_serve_writes_one_line_per_response(session: Session) -> None:
    """Framing. A response split over two lines, or two sharing one, is a parse
    error at the client -- and `json.dumps` of a nested payload is exactly the
    thing that would do it if anything here pretty-printed."""
    stdin = io.StringIO(
        "\n".join(
            [
                json.dumps(_request("initialize", {}, rid=1)),
                json.dumps(_request("notifications/initialized", rid=None)),
                json.dumps(_request("tools/list", rid=2)),
            ]
        )
        + "\n"
    )
    stdout = io.StringIO()
    serve(Server(session), stdin, stdout)

    lines = stdout.getvalue().splitlines()
    assert len(lines) == 2, "the notification was answered"
    assert [json.loads(line)["id"] for line in lines] == [1, 2]


def test_malformed_input_does_not_end_the_session(session: Session) -> None:
    """A client that sends one bad line still gets its next request served.

    Worth asserting because the tempting implementation -- let the exception
    out of the loop -- ends the session silently from the model's side, and the
    user sees a tool that stopped existing.
    """
    stdin = io.StringIO("not json\n\n" + json.dumps(_request("ping", rid=7)) + "\n")
    stdout = io.StringIO()
    serve(Server(session), stdin, stdout)

    responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert responses[0]["error"]["code"] == -32700
    assert responses[1]["id"] == 7 and responses[1]["result"] == {}


def test_every_tool_has_a_schema_and_a_description() -> None:
    """Both are what a model picks a tool by, and an empty one fails no build."""
    from nixfisical.mcp import TOOLS

    for tool in TOOLS:
        assert tool.description.strip(), tool.name
        assert tool.schema["type"] == "object", tool.name
        for name in tool.schema.get("required", []):
            assert name in tool.schema["properties"], f"{tool.name}: {name}"
