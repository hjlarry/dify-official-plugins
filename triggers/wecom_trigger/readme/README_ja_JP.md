# WeCom トリガープラグイン

企業微信 (WeCom) アプリの暗号化コールバックを受信し、Dify ワークフローを実行します。公式ドキュメント [101027](https://developer.work.weixin.qq.com/document/path/101027) に従い、`msg_signature` を SHA-1 で検証し、AES-CBC でメッセージを復号します。

## 手順
1. WeCom 管理画面でアプリの `Token` / `EncodingAESKey` / `CorpID` を取得します。
2. Dify 側で本トリガーのサブスクリプションを作成し、これらの値を入力します。
3. 生成されたコールバック URL を WeCom の「回调 URL」に設定すると、`echostr` 検証は自動で応答されます。
4. 以後のイベントは `message_received` イベントとしてワークフローに渡されます。

## バージョン
- **1.0.0 (2025-02-10)**: 初回リリース。署名検証・AES 復号・URL ハンドシェイクをサポート。
