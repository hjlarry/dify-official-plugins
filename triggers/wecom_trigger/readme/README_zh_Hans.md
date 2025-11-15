# 企业微信 Trigger 插件

用于接收企业微信（WeCom）应用的回调事件。插件遵守官方文档 [101027](https://developer.work.weixin.qq.com/document/path/101027)，会自动进行 `msg_signature` 校验、AES-CBC 解密，并把解密后的消息作为 `message_received` 事件交给 Dify 工作流。

## 使用步骤
1. 在企业微信后台记录应用的 `Token`、`EncodingAESKey`、`CorpID`/`ReceiveId`。
2. 在 Dify 安装并创建此触发器订阅，填写上述参数，可选地填写需要监听的消息类型。
3. 复制订阅生成的回调 URL，粘贴到企业微信后台的“回调 URL”中完成验证（GET `echostr` 请求会自动返回解密结果）。
4. 之后所有加密的 POST 回调都会被解密并触发工作流。

## 版本
- **1.0.0 (2025-02-10)**：首发，支持 URL 验证、签名校验、AES 解密与通用消息事件。
