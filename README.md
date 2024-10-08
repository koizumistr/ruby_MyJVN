# MyJVN API利用サンプル(Ruby)

RubyからMyJVN APIを利用するサンプルです。以下の例が含まれています。
* getVulnOverviewListを使って、指定されたキーワードに関連する脆弱性の一覧を取得する例(overview.rb)
* getVulnDetailInfoを使って、指定されたIDに対応する脆弱性の詳細情報を取得する例(detail.rb)

## 動作環境

Rubyの以下のバージョンで動作を確認しています。

* (2.2.4)
* (2.4.2)
* (2.7.4)
* 3.3.5

ちなみに、1.8.6でも動作させてみましたが、正規表現を使っている箇所で落ちます。その部分を書き換えれば1.8.6でも動作するような気がします。頑張りたい人はどうぞ。

HTTPSで通信しますので、その関係の設定が必要です。証明書は各自用意してください。[DigiCertのサイト](https://www.digicert.com/kb/digicert-root-certificates.htm)でダウンロードできます。

## 注意

ここにあるのはあくまでサンプルです。本格的に運用する場合には[MyJVN API 利用上の留意事項](https://jvndb.jvn.jp/apis/termsofuse.html)などをよく読み、IPAの提示する条件を守って使ってください。ざっと読む限り、MyJVN API により提供されたものである旨を表示すれば、それ以外はこういうサービスにはよくある条件かと。

## おまけ
overview-3.1.rb は旧 MyJVN API (3.1)に対応するものでした。MyJVN API (3.1)はもうとっくにEoLを迎えていますので、overview-3.1.rb は動作しません。（が、思い出として残してあります。）
