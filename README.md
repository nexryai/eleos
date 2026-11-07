## roscaelum Firewall

### これは何
nftablesをnetlink経由で直接操作する、軽量でシンプルかつセキュアでエッセンシャルなファイアウォール。  
開発中です。


### 設計原則

#### シンプルで使いやすい
設定は全てyamlで管理します。もう`ufw status`を連打する必要はありません！  
さらにシングルバイナリで動作し、`nft`コマンドにも依存しないためインストールも簡単です。

#### セキュア
不適切な設定には警告を表示します。またメモリセーフなGoで書かれています。

#### 数々の便利機能
特定のインターフェースでのみアクセスを許可したり、任意のIPからのアクセスを禁止するなど、よりサーバーをセキュアにするのに役立つ機能が搭載されています。  
ルーターを自作したいですか？ roscaelumには簡易的なホームルーターの構築を支援する機能が搭載されています！  

#### 完全オフライン動作
外部APIへの通信を必要としないため、ルールの生成・適用は全てオフラインで行えます。


### 使い方
注意: 使う前に既存のファイアウォールを無効化してください

```
wget https://raw.githubusercontent.com/nexryai/roscaelum/main/install.sh
sudo bash install.sh

# ルールを編集
sudo nano /etc/roscaelum.yml

# 適用
sudo rcfctl enable

# 起動時に適用されるようにする
sudo systemctl enable roscaelum
```
#### ソースからビルド
```
# ビルド
make

# インストール
sudo make install
```

### 既知の問題
#### RHEL系に入れたらsystemd経由で扱おうとするとPermissionで文句言われる
SELinuxのせいです。  
`sudo restorecon -R /usr/bin/rcfctl`で解決します。

#### Dockerと競合する
`allowAllFwd`をtrueにすれば回避できます。
