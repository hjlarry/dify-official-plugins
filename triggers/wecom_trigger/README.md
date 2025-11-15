# WeCom Trigger Plugin for Dify

Receive encrypted event callbacks from Enterprise WeChat (a.k.a. WeCom / 企业微信) and use them to kick off Dify workflows. This plugin mirrors the official callback specification in [doc 101027](https://developer.work.weixin.qq.com/document/path/101027): it validates the `msg_signature` header with SHA-1, decrypts the AES-CBC payload, and exposes the structured message to your automations.

## Features
- Handles both the initial URL verification `GET` (echostr) and subsequent `POST` callbacks.
- Built-in AES-SHA1 logic based on Tencent's sample (`WXBizJsonMsgCrypt`) but rewritten with `pycryptodomex` for modern environments.
- Single `message_received` event surfaces every field from the callback (agent id, user id, event type, content, attachments, etc.) so you can route inside workflows.
- Optional filtering parameters (message type whitelist) and signature enforcement are configured inside the subscription form.

## Usage
1. **Create or reuse a WeCom app.** Note the `Token`, `EncodingAESKey`, and `CorpID/ReceiveId` values from *App Management → Event Configuration*.
2. **Install this trigger plugin in Dify** and create a subscription. Provide the token, AES key, corp id, and (optionally) which message types you want to process.
3. **Copy the generated callback URL** from the subscription and paste it back into WeCom’s “Callback URL”. During verification WeCom issues a `GET` with `echostr`; the plugin responds with the decrypted string, completing the handshake.
4. **Publish events in WeCom.** Every encrypted `POST` (new message, menu click, member change, etc.) will be decrypted and routed to the `message_received` event for your workflow.

## Diagnostics
- Enable Dify plugin logs to inspect signature errors or malformed payloads.
- To replay or simulate events, use the official demo payload together with your token/AES key and send them to the webhook endpoint.

## Version history
- **1.0.0 (2025-02-10)**: Initial release with SHA-1 verification, AES decryption, URL handshake, and generic message event output.
