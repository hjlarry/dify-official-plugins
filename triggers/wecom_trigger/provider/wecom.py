from __future__ import annotations

import base64
import hashlib
import json
import struct
from typing import Any, Mapping

from Cryptodome.Cipher import AES
from werkzeug import Request, Response

from dify_plugin.entities.trigger import EventDispatch, Subscription, UnsubscribeResult
from dify_plugin.entities.provider_config import CredentialType
from dify_plugin.errors.trigger import TriggerDispatchError, TriggerValidationError, TriggerProviderCredentialValidationError
from dify_plugin.interfaces.trigger import Trigger, TriggerSubscriptionConstructor


class WeComConfig:
    """Lightweight container for WeCom credentials."""

    def __init__(self, token: str, encoding_aes_key: str, receive_id: str):
        self.token = token
        self.encoding_aes_key = encoding_aes_key
        self.receive_id = receive_id


class WeComCryptor:
    """Implements the AES-CBC + SHA1 flow from WeCom callbacks."""

    def __init__(self, config: WeComConfig):
        key = base64.b64decode(config.encoding_aes_key + "=")
        if len(key) != 32:
            raise TriggerValidationError("Invalid EncodingAESKey length; expected 43 chars -> 32 bytes")
        self.token = config.token
        self.receive_id = config.receive_id
        self.key = key
        self.iv = key[:16]

    def decrypt(self, *, signature: str, timestamp: str, nonce: str, ciphertext: str) -> str:
        expected = self._signature(timestamp=timestamp, nonce=nonce, ciphertext=ciphertext)
        if signature != expected:
            raise TriggerValidationError("Invalid WeCom msg_signature")
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decoded = base64.b64decode(ciphertext)
            plain = cipher.decrypt(decoded)
        except Exception as exc:  # pragma: no cover - defensive
            raise TriggerDispatchError(f"Failed to decrypt WeCom payload: {exc}") from exc

        pad = plain[-1]
        if pad < 1 or pad > 32:
            raise TriggerDispatchError("Invalid PKCS#7 padding in WeCom payload")
        content = plain[16:-pad]
        if len(content) < 4:
            raise TriggerDispatchError("Malformed WeCom payload after padding removal")

        json_length = struct.unpack("!I", content[:4])[0]
        json_bytes = content[4 : 4 + json_length]
        receive_id = content[4 + json_length :].decode("utf-8", errors="ignore")
        if receive_id != self.receive_id:
            raise TriggerValidationError("ReceiveId mismatch in decrypted WeCom payload")
        try:
            return json_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TriggerDispatchError("Decoded WeCom payload is not valid UTF-8") from exc

    def decrypt_echostr(self, *, signature: str, timestamp: str, nonce: str, echostr: str) -> str:
        return self.decrypt(signature=signature, timestamp=timestamp, nonce=nonce, ciphertext=echostr)

    def _signature(self, *, timestamp: str, nonce: str, ciphertext: str) -> str:
        parts = [self.token, str(timestamp), str(nonce), ciphertext]
        parts.sort()
        sha = hashlib.sha1()
        sha.update("".join(parts).encode("utf-8"))
        return sha.hexdigest()


class WeComTrigger(Trigger):
    """Handle Enterprise WeChat encrypted callbacks."""

    _EVENT_NAME = "message_received"

    def _dispatch_event(self, subscription: Subscription, request: Request) -> EventDispatch:
        properties = subscription.properties or {}
        config = self._load_config(properties)
        cryptor = WeComCryptor(config=config)

        if request.method.upper() == "GET":
            return self._handle_verification(request=request, cryptor=cryptor)

        return self._handle_message(subscription=subscription, request=request, cryptor=cryptor)

    def _handle_verification(self, request: Request, cryptor: WeComCryptor) -> EventDispatch:
        args = request.args
        signature = args.get("msg_signature")
        timestamp = args.get("timestamp")
        nonce = args.get("nonce")
        echostr = args.get("echostr")
        if not all([signature, timestamp, nonce, echostr]):
            raise TriggerDispatchError("Missing verification parameters for WeCom callback")
        plain = cryptor.decrypt_echostr(signature=signature, timestamp=timestamp, nonce=nonce, echostr=echostr)
        response = Response(response=plain, status=200, mimetype="text/plain")
        return EventDispatch(events=[], response=response)

    def _handle_message(self, subscription: Subscription, request: Request, cryptor: WeComCryptor) -> EventDispatch:
        args = request.args
        signature = args.get("msg_signature")
        timestamp = args.get("timestamp")
        nonce = args.get("nonce")
        if not all([signature, timestamp, nonce]):
            raise TriggerDispatchError("Missing signature parameters in WeCom callback")

        try:
            body = request.get_json(force=True)
        except Exception as exc:
            raise TriggerDispatchError(f"Failed to parse WeCom request body: {exc}") from exc

        encrypted = body.get("encrypt") if isinstance(body, Mapping) else None
        if not encrypted:
            raise TriggerDispatchError("WeCom callback missing encrypt field")

        decrypted = cryptor.decrypt(signature=signature, timestamp=timestamp, nonce=nonce, ciphertext=encrypted)
        try:
            payload = json.loads(decrypted)
        except json.JSONDecodeError as exc:
            raise TriggerDispatchError(f"Decrypted WeCom payload is not JSON: {exc}") from exc

        if not isinstance(payload, Mapping):
            raise TriggerDispatchError("Decrypted WeCom payload must be JSON object")

        if self._should_ignore(subscription.properties or {}, payload):
            return EventDispatch(events=[], response=self._ok_response())

        response = self._ok_response()
        return EventDispatch(events=[self._EVENT_NAME], response=response, payload=payload)

    def _should_ignore(self, properties: Mapping[str, Any], payload: Mapping[str, Any]) -> bool:
        agent_filter = properties.get("agent_id")
        if agent_filter and str(payload.get("AgentID")) != str(agent_filter):
            return True

        allowed_raw = properties.get("message_types")
        allowed: list[str] = []
        if isinstance(allowed_raw, str):
            allowed = [item.strip().lower() for item in allowed_raw.split(",") if item.strip()]
        elif isinstance(allowed_raw, (list, tuple)):
            allowed = [str(item).lower() for item in allowed_raw]

        if allowed:
            msg_type = str(payload.get("MsgType") or payload.get("msgtype") or "").lower()
            normalized = msg_type if msg_type in {"text", "image", "voice", "video", "file", "event"} else "other"
            if normalized not in allowed:
                return True
        return False

    def _load_config(self, properties: Mapping[str, Any]) -> WeComConfig:
        token = properties.get("token")
        encoding_aes_key = properties.get("encoding_aes_key")
        if not all([token, encoding_aes_key]):
            raise TriggerDispatchError("WeCom subscription missing token / encoding key")
        return WeComConfig(token=str(token), encoding_aes_key=str(encoding_aes_key), receive_id="")

    def _ok_response(self) -> Response:
        return Response(response='{"status": "ok"}', status=200, mimetype="application/json")


class WeComSubscriptionConstructor(TriggerSubscriptionConstructor):
    """Pass-through constructor so the runtime can persist user-provided credentials."""

    def _validate_api_key(self, credentials: Mapping[str, Any]) -> None:
        token = credentials.get("token")
        encoding_aes_key = credentials.get("encoding_aes_key")
        receive_id = credentials.get("receive_id")

        missing: list[str] = []
        if not token:
            missing.append("token")
        if not encoding_aes_key:
            missing.append("encoding_aes_key")
        if not receive_id:
            missing.append("receive_id")

        if missing:
            joined = ", ".join(missing)
            raise TriggerProviderCredentialValidationError(f"WeCom credentials missing: {joined}")

        if len(str(encoding_aes_key)) != 43:
            raise TriggerProviderCredentialValidationError("EncodingAESKey must be 43 characters long")

        return None

    def _create_subscription(
        self,
        endpoint: str,
        parameters: Mapping[str, Any],
        credentials: Mapping[str, Any],
        credential_type: CredentialType,
    ) -> Subscription:
        # Just persist the parameters as properties; WeCom callbacks are configured manually on WeCom side.
        props = dict(parameters or {})
        props.update({key: value for key, value in (credentials or {}).items() if value is not None})
        return Subscription(endpoint=endpoint, parameters=parameters, properties=props)

    def _delete_subscription(
        self,
        subscription: Subscription,
        credentials: Mapping[str, Any],
        credential_type: CredentialType,
    ) -> UnsubscribeResult:
        # Nothing to delete remotely; returning success lets Dify clean up the record.
        return UnsubscribeResult(success=True, message="WeCom subscription removed")

    def _refresh_subscription(
        self,
        subscription: Subscription,
        credentials: Mapping[str, Any],
        credential_type: CredentialType,
    ) -> Subscription:
        # No remote state to refresh; return existing subscription.
        return Subscription(endpoint=subscription.endpoint, parameters=subscription.parameters, properties=subscription.properties)
