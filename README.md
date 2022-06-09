* [macos-all](#macos-all)
   * [杀掉可恶的adobe进程](#杀掉可恶的adobe进程)
   * [重启vmware虚拟机的网络服务](#重启vmware虚拟机的网络服务)
   * [删除docker悬空镜像](#删除docker悬空镜像)
   * [java 程序命令行启动设置代理](#java-程序命令行启动设置代理)
   * [命令行多线程下载工具](#命令行多线程下载工具)
   * [nessus 破解](#nessus-破解)
   * [chrome系浏览器提示https打不开](#chrome系浏览器提示https打不开)

# macos-all
关于macos的实用内容。

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
