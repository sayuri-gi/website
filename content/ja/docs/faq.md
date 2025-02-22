---
title: よくある質問 (FAQ)
linkTitle: よくある質問 (FAQ)
slug: faq
top_graphic: 1
date: 2017-07-06
lastmod: 2019-12-22
menu:
  main:
    weight: 30
    parent: about
show_lastmod: 1
---


よくある質問 (FAQ) は、以下の2つのセクションに分類されています。

* [一般的な質問](#general)
* [技術的な質問](#technical)

# <a id="general">一般的な質問</a>

## Let's Encrypt はどのようなサービスを提供しているのですか？

Let's Encrypt は世界的な認証局 (Certificate Authority; CA) です。私たちの目的は、世界中の人々と組織が SSL/TLS 証明書を取得・更新・管理できるようにすることです。私たちの証明書は、ウェブサイトなどで HTTPS コネクションをセキュアにするために利用できます。

Let's Encrypt はドメイン検証 (Domain Validation; DV) 型の証明書です。主に Organization Validation (OV) や Extended Validation (EV) は提供しません。このような種類の証明書の発行は自動化することができないからです。

Let's Encrypt を使い始めるには、[はじめる](/getting-started)のページを読んでください。

## Let's Encrypt を使用するためにかかる費用はいくらですか？ 本当に無料なのですか？

私たちは、証明書の発行に費用は請求しません。Let's Encrypt は非営利団体であり、私たちのミッションは、HTTPS の利用を広めることで、よりセキュアでプライバシーを尊重するウェブを作ることだからです。私たちのサービスは、無料で提供され、HTTPS をデプロイできるすべてのウェブサイトで簡単に利用できます。

私たちがサービスを世界中に提供し続けるためには、たくさんのスポンサー・助成金・個人からの支援が必要です。もしあなたが支援に興味を持ってくれたのなら、ぜひとも[寄付を行う](/donate)ことや[スポンサーになる](https://www.abetterinternet.org/sponsor)ことを検討してください。よろしくお願いします。

ホスティング・プロバイダなどのサービスを利用している場合、場合によっては、Let's Encrypt の証明書の提供にかかる管理コストが利用料金に含まれることがあります。

## どんなサポートが受けられますか？

Let's Encrypt は少人数のチームで運営されており、コストを削減するために自動化に頼っています。このような背景があるため、利用者に対して直接的なサポートを提供することはできません。しかし、以下のような優れたサポートオプションを提供します。

1. 私たちは非常に役に立つ[ドキュメント](/docs)を提供します。
2. 私たちには非常に活発で助け合いのある[コミュニティ・サポート・フォーラム](https://community.letsencrypt.org/)があります。私たちのコミュニティのメンバーはたくさんの質問に答えてくれており、よくある質問の大部分にはすでに回答が存在しています。

こちらは[私たちのお気に入りのビデオ](https://www.youtube.com/watch?v=Xe1TZaElTAs)です。コミュニティ・サポートの素晴らしい力について話されています。

## Let's Encrypt を使用しているウェブサイトが、フィッシング/マルウェア/詐欺などに使われてしまっています。何をすればよいでしょうか？

そのようなサイトは、Google Safe Browsing や Microsoft Smart Screen プログラムに報告することをおすすめしています。ユーザーをより効果的に守ることができるからです。Google の報告用 URL はこちらです。

[https://safebrowsing.google.com/safebrowsing/report_badware/](https://safebrowsing.google.com/safebrowsing/report_badware/)

私たちのポリシーとその論拠については、こちらの記事で詳しく説明しています。

https://letsencrypt.org/2015/10/29/phishing-and-malware.html

# <a id="technical">技術的な質問</a>

## Let's Encrypt から取得した証明書は、ブラウザに信頼されますか？

はい、ほとんどすべてのブラウザとオペレーティングシステムに信頼されます。詳しくは、[互換性リスト](/docs/cert-compat)を見てください。

## Let's Encrypt はウェブサイトのための SSL/TLS 証明書以外にも証明書を発行していますか？

Let's Encrypt の証明書は標準のドメイン検証 (Domain Validation) 型の証明書です。そのため、ドメイン名を使用するサーバーであれば、ウェブサーバー、メールサーバー、FTP サーバーなど、どんなサーバーでも利用できます。

ただし、電子メールの暗号化と署名を行うには、Let's Encrypt が発行していない別の種類の証明書が必要です。

## Let's Encrypt は、私の証明書のための秘密鍵を Let's Encrypt サーバー上で生成したり保存したりしますか？

いいえ。そのようなことは絶対にありません。

秘密鍵は必ずあなたのサーバー上で生成・管理されます。Let's Encrypt 認証局は秘密鍵を扱いません。

## Let's Encrypt の証明書の期限はどのくらいですか？ 有効な期間は何日間でしょうか？

私たちの証明書の有効期限は 90 日間です。この日数である理由については[こちらの記事](/2015/11/09/why-90-days.html)を読んでください。

この日数を変更する方法は存在せず、例外はありません。証明書を 60 日ごとに自動的に更新するように設定することをおすすめしています。

## Let's Encrypt が Organization Validation (OV) や Extended Validation (EV) 証明書を発行する予定はありますか？

OV や EV 証明書を発行する予定はありません。

## 複数ドメイン名のための証明書 (SAN 証明書や UCC 証明書) は取得できますか？

はい、できます。Subject Alternative Name (SAN) メカニズムを利用することで、1つの証明書に複数の異なるドメイン名を含めることができます。

## Let's Encrypt はワイルドカード証明書を発行していますか？

はい。ただし、ワイルドカード証明書の発行には DNS-01 を使用する ACMEv2 プロトコルでの認証が必要です。詳細な技術的な情報については、[この記事](https://community.letsencrypt.org/t/acme-v2-production-environment-wildcards/55578)を読んでください。

## 私が使っているオペレーティングシステムで使える Let's Encrypt (ACME) クライアントはありますか？

たくさんの [ACME クライアント](/docs/client-options)が利用可能なので、あなたのオペレーティングシステムでも動作するクライアントがある可能性は高いです。初めて利用する場合、私たちは [Certbot](https://certbot.eff.org/) を使うことをおすすめしています。

## 既存の秘密鍵や、証明書署名リクエスト (Certificate Signing Request; CSR) は使用できますか？

はい、可能です。ただし、すべてのクライアントがこの機能をサポートしているわけではないので注意してください。[Certbot](https://certbot.eff.org/) はサポートしています。

## 私のウェブサーバーを検証するために Let's Encrypt が利用する IP アドレスはどれですか？

私たちが検証に使用している IP アドレスリストは公開していません。また、この IP アドレスはいつでも変更する可能性があります。また、一度に複数の IP アドレスを利用して検証するようになる予定です。詳しくは[この記事](https://community.letsencrypt.org/t/validating-challenges-from-multiple-network-vantage-points)を読んでください。

## 証明書の更新には成功しましたが、検証のプロセスは発生しませんでした。このようなことはありえますか？

一度ドメインのチャレンジが成功すると、将来のリクエストのために、認証の結果があなたのアカウントにキャッシュされます。キャッシュされた認証は、検証が行われた時点から 30 日間保存されます。あなたがリクエストした証明書が認証に必要なすべてのキャッシュを持っていた場合、関係するキャッシュ済みの認証が期限切れにならない限り、再び検証が行われることはありません。
