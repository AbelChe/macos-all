# macos-all
关于macos的实用内容。

* [macos-all](#macos-all)
   * [杀掉可恶的adobe进程](#杀掉可恶的adobe进程)
   * [重启vmware虚拟机的网络服务](#重启vmware虚拟机的网络服务)
   * [删除docker悬空镜像](#删除docker悬空镜像)
   * [java 程序命令行启动设置代理](#java-程序命令行启动设置代理)
   * [命令行多线程下载工具](#命令行多线程下载工具)
   * [nessus 破解](#nessus-破解)
   * [chrome系浏览器提示https打不开](#chrome系浏览器提示https打不开)
   * [一行命令解密VNC](#一行命令解密vnc)
   * [burpsuite 关闭http/2](#burpsuite-关闭http2)
   * [获取16进制字符串](#获取文件16进制字符串)
   * [生成md文档目录](#生成md文档目录)
   * [frp内网穿透配置](#frp内网穿透配置)
   * [搜索各种key的正则](#搜索各种key的正则)
   * [vim使用粘贴模式](#vim使用粘贴模式)
   * [python一行代码生成随机字符串](#python一行代码生成随机字符串)

## 杀掉可恶的adobe进程
```sh
#! /bin/bash
ps -efh | grep Adobe | awk 'NR>1{print p, p1}{p=$2;p1=$8}'
ps -efh | grep Adobe | awk 'NR>1{print p}{p=$2}' | xargs kill 
cd ~/Library/LaunchAgents && ls -l | grep com.adobe | awk '{print $9}' | xargs rm -rf
cd /Library/LaunchAgents && ls -l | grep com.adobe | awk '{print $9}' | xargs rm -rf
cd /Library/LaunchDaemons && ls -l | grep com.adobe | awk '{print $9}' | xargs rm -rf
rm -rf /Applications/Utilities/Adobe\ Creative\ Cloud/CCLibrary
rm -rf /Applications/Utilities/Adobe\ Creative\ Cloud/CCXProcess
rm -rf /Applications/Utilities/Adobe\ Creative\ Cloud/CoreSync
```

## 重启vmware虚拟机的网络服务
- 需要root权限
```sh
sudo /Applications/VMware\ Fusion.app/Contents/Library/vmnet-cli --stop
sudo /Applications/VMware\ Fusion.app/Contents/Library/vmnet-cli --start
```

## 删除docker悬空镜像
```sh
# fish shell
docker rmi (docker images -f "dangling=true" -q)
# bash shell
docker rmi $(docker images -f "dangling=true" -q)
```

## java 程序命令行启动设置代理
```sh
java -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8080 -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8080 -jar xxx.jar
```

## 命令行多线程下载工具
```sh
brew install axel

axel -n 20 http://xxxxxxxxxxxxxxxxxxxxxxxx
```

## nessus 破解
macos下脚本命名为 `patch.sh` 与 `all-2.0.tar.gz` `nessus-fetch.rc`一同放到`/Library/Nessus/run/sbin/`目录下
```sh
#!/bin/bash

# Check root
if [ "$(whoami)" != "root" ]
then
    echo "[!] Please use root, sudo ./patch.sh"
    exit
fi

cd /Library/Nessus/run/sbin
echo '[...] Now updating from package...'
./nessuscli update ./all-2.0.tar.gz > nessuspatch.log
cp nessus-fetch.rc /Library/Nessus/run/etc/nessus/nessus-fetch.rc
VERSION=$(cat nessuspatch.log | grep -Eo '\d{12}' | head -n 1)

echo "[+] Get version: $VERSION"

echo '[...] Please restart nessus by manual...'
flag=n
while [ "$flag" != "y" ] && [ "$flag" != "Y" ]
do
    read -r -p 'restart over?(y/n)> ' flag
done

VERSION=$(cat nessuspatch.log | grep -Eo '\d{12}' | head -n 1)
cat > /Library/Nessus/run/var/nessus/plugin_feed_info.inc <<EOF
PLUGIN_SET = "$VERSION";
PLUGIN_FEED = "ProfessionalFeed (Direct)";

PLUGIN_FEED_TRANSPORT = "Tenable Network Security Lightning";
EOF

echo '[+] Write to file success: /Library/Nessus/run/var/nessus/plugin_feed_info.inc'
cat /Library/Nessus/run/var/nessus/plugin_feed_info.inc

rm -rf /Library/Nessus/run/lib/nessus/plugins/plugin_feed_info.inc
echo '[+] Remove /Library/Nessus/run/lib/nessus/plugins/plugin_feed_info.inc success'

echo '[+] Patch Done, please restart nessus by manual...'
```

```sh
cd /Library/Nessus/run/sbin/
sudo chmod +x patch.sh
sudo ./patch.sh
```
macos的nessus没法通过shell脚本没法完全控制nessus服务启停，破解过程中需要手动重启一下nessus，注意脚本运行提示。

## chrome系浏览器提示https打不开

问题页面键盘直接敲`thisisunsafe`

## 一行命令解密VNC
`6bcf2a4b6e5aca0f` 解密: `sT333ve2`
```sh
echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d
```

## burpsuite 关闭http/2
Project options ==> HTTP ==> HTTP/2
取消勾选http2支持

## 获取16进制字符串
```sh
echo "test strxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx....." | xxd -c 1000000 -p -l 1000000
# 746573742073747278787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878782e2e2e2e2e0a
```

## 生成md文档目录
```sh
# 下载
curl https://raw.githubusercontent.com/ekalinin/github-markdown-toc/master/gh-md-toc -o gh-md-toc
chmod a+x gh-md-toc
# 使用
gh-md-toc file.md
gh-md-toc https://github.com/AbelChe/macos-all
```

## frp内网穿透配置
frps.ini
```ini
[common]
bind_port = 21234
bind_addr = 0.0.0.0
```

frpc.ini
```ini
[common]
server_addr = vpsip
server_port = 21234

[http_proxy]
type = tcp
remote_port = 7777
plugin = socks5
```
挂socks5://vpsip:7777

## 搜索各种key的正则
burp使用
```text
(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]
```

vscode使用
```text
((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-zA-Z\-_=]{8,64})['"]
```

## vim使用粘贴模式
当使用vim粘贴大段文字、代码的时候，很可能由于vim的缩进规则导致粘贴进来的文本格式错乱，这时我们可以使用粘贴模式进行输入
只需要使用如下指令，然后再次进入`INSERT`模式，可见到左下角的提示变更为`INSERT (paset)`，这时我们直接粘贴就可以保持原文格式了。
```
:set paste
```

## python一行代码生成随机字符串
```python
import string
import random
''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
```
