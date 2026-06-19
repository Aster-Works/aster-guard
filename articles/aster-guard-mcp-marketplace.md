---
title: 'Aster Guard MCPをGitHub Marketplaceに公開しました'
emoji: '🛡️'
type: 'tech'
topics: ['mcp', 'security', 'githubactions', 'claudecode', 'npm']
published: false
---

Claude CodeやMCPを使うと、AIエージェントはファイル、コマンド、外部サービスにアクセスできるようになります。

便利な一方で、`.mcp.json` の設定内容を接続前に確認したい場面も増えてきました。

そこで、Aster Guard MCPをGitHub Marketplace Actionとして公開しました。

https://github.com/marketplace/actions/aster-guard-mcp

@[card](https://github.com/Aster-Works/aster-guard)

## Aster Guard MCPとは

Aster Guard MCPは、Claude Codeユーザー、MCPを使い始めた開発者、個人開発者・小規模チーム向けの、軽量な接続前セキュリティ診断ツールです。

役割はあえて小さくしています。

> MCPサーバーを接続する前に、その設定ファイルが安全そうかをローカルで確認する。

MCPサーバーは、AIツールに「外の世界」への手足を与えます。

たとえば、MCPによってAIエージェントは次のようなものにアクセスできるようになります。

- ファイル
- シェルコマンド
- データベース
- ブラウザ
- SaaS API
- ローカルの開発ツール

これはとても便利です。一方で、セキュリティ上の意味も大きく変わります。

たった1つの `.mcp.json` の設定が、次のようなリスクにつながることがあります。

- コマンドを実行する
- 環境変数やトークンを露出する
- 広すぎるファイルアクセスを許可する
- 不明なリモートエンドポイントに接続する
- ツール説明文の中に、エージェント向けの隠れた指示を含む

Aster Guardは、その一歩手前で使うための小さなチェックツールです。

## 何をチェックするのか

Aster Guardは、MCPやClaude Codeの設定ファイルを静的にスキャンします。

重要なのは、スキャン対象のMCPサーバーを起動しないことです。未知のMCPサーバーを実行する前に、まず設定だけを読み取って危険な兆候を探します。

検出する代表的なパターンは次の通りです。

- ツール説明文に隠されたエージェント向け指示
- ハードコードされた秘密情報
- `.ssh`、クラウド認証情報、`.env` など機微ファイルへのアクセス
- シェル実行や危険なインストールコマンド
- 破壊的なコマンド
- 広すぎるファイルシステムアクセス
- 不明なリモートMCPエンドポイント
- 既存ツール名をまねるツール名の衝突
- 難読化されたコマンドパターン

結果として、リスクスコア、評価、検出内容、推奨対応を日本語と英語で表示します。

## まず試す

ローカルで試す場合は、次のコマンドだけです。

```bash
npx -y @asterworks/aster-guard scan
```

特定の設定ファイルだけを見ることもできます。

```bash
npx -y @asterworks/aster-guard scan .mcp.json
```

## GitHub Actionsで使う

GitHub Marketplace Actionとして使う場合は、workflowに次のように追加できます。

```yaml
- uses: Aster-Works/aster-guard@v0.3.2
  with:
    path: .
    fail-on: high
```

SARIFを出してGitHub Securityタブに載せる場合は、次のように使えます。

```yaml
- uses: Aster-Works/aster-guard@v0.3.2
  with:
    path: .
    fail-on: high
    sarif: results.sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## 設計方針

Aster Guardは、スキャン対象より安全であることを重視しています。

- ローカル優先
- テレメトリなし
- スキャン対象のコマンドを実行しない
- 第三者のMCPサーバーを起動しない
- 出力時に秘密情報をマスクする
- 外部メタデータ確認は `--allow-network` を明示した場合のみ

Aster Guardは、ランタイムファイアウォール、アンチウイルス、SIEM、完全なサプライチェーン管理ツールではありません。

あくまで「MCP設定を接続する前の入口チェック」に特化しています。

## リンク

- GitHub Marketplace: https://github.com/marketplace/actions/aster-guard-mcp
- GitHub repository: https://github.com/Aster-Works/aster-guard
- npm: https://www.npmjs.com/package/@asterworks/aster-guard

実際のMCP設定で試していただけると嬉しいです。特に知りたいのは、検出内容が理解しやすいか、そして「次に何をすればよいか」が分かるかどうかです。
