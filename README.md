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
