import json
from collections.abc import Mapping
from typing import Any

from werkzeug import Request

from dify_plugin.entities.trigger import Variables
from dify_plugin.interfaces.trigger import Event


class WeComMessageReceived(Event):
    """Return decrypted WeCom payload so workflows can branch as needed."""

    def _on_event(self, request: Request, parameters: Mapping[str, Any], payload: Mapping[str, Any]) -> Variables:
        if not isinstance(payload, Mapping) or not payload:
            raise ValueError("Empty WeCom payload")

        msg_type = str(payload.get("MsgType") or payload.get("msgtype") or "").lower()
        event_type = None
        if msg_type == "event":
            event_type = str(payload.get("Event") or payload.get("event") or "").lower() or None

        content = payload.get("Content") or payload.get("content")
        agent_id = payload.get("AgentID") or payload.get("agentid")

        variables = {
            "message_type": msg_type,
            "event_type": event_type,
            "agent_id": agent_id,
            "to_user_name": payload.get("ToUserName"),
            "from_user_name": payload.get("FromUserName"),
            "create_time": payload.get("CreateTime"),
            "content": content,
            "raw_payload": json.loads(json.dumps(payload)),
        }
        return Variables(variables=variables)
