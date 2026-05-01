"""Intent synthesis: tool-call dict -> ActionPacket."""

from __future__ import annotations

from govclaw import intent
from govclaw.schemas import ActionPacket


def test_mutating_tool_marks_state_change():
    p = intent.build(tool_name="write_file", args={"path": "/tmp/x"})
    assert isinstance(p, ActionPacket)
    assert p.proposed_action.state_change is True
    assert p.proposed_action.mutating is True


def test_idempotent_tool_marks_no_state_change():
    p = intent.build(tool_name="read_file", args={"path": "/etc/passwd"})
    assert p.proposed_action.state_change is False


def test_irreversible_send_message():
    p = intent.build(tool_name="send_message", args={"to": "x"})
    assert p.proposed_action.irreversible is True


def test_irreversible_terminal_rm():
    p = intent.build(tool_name="terminal", args={"command": "rm -rf /tmp/cache"})
    assert p.proposed_action.irreversible is True


def test_terminal_safe_command_is_reversible():
    p = intent.build(tool_name="terminal", args={"command": "ls -la"})
    assert p.proposed_action.irreversible is False


def test_packet_carries_session_and_task_ids():
    p = intent.build(
        tool_name="write_file",
        args={"path": "/tmp/y"},
        session_id="sess-1",
        task_id="task-9",
        tool_call_id="call-42",
    )
    assert p.actor["session_id"] == "sess-1"
    assert p.actor["task_id"] == "task-9"
    assert p.context["tool_call_id"] == "call-42"


def test_args_are_copied_not_aliased():
    """Mutating the source dict afterwards must not mutate the packet's view."""
    src = {"path": "/tmp/x"}
    p = intent.build(tool_name="write_file", args=src)
    src["path"] = "/etc/shadow"
    assert p.proposed_action.args["path"] == "/tmp/x"


def test_none_args_become_empty_dict():
    p = intent.build(tool_name="todo", args=None)
    assert p.proposed_action.args == {}


def test_user_task_lands_in_context():
    p = intent.build(
        tool_name="write_file",
        args={"path": "/tmp/x"},
        user_task="please write the file",
    )
    assert p.context["user_task"] == "please write the file"
