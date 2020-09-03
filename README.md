# TSP & Trojan-Go / V2Ray 容器化管理部署脚本 deploy.sh

![GitHub](https://img.shields.io/github/license/h31105/trojan_v2_docker_onekey?style=flat)
![GitHub top language](https://img.shields.io/github/languages/top/h31105/trojan_v2_docker_onekey?style=flat)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/h31105/trojan_v2_docker_onekey?style=flat)
![GitHub forks](https://img.shields.io/github/forks/h31105/trojan_v2_docker_onekey?style=flat)
![Visitors](https://visitor-badge.glitch.me/badge?page_id=h31105.trojan_v2_docker_onekey)

基于 Docker 容器架构的 Trojan-Go/VLESS/VMess TLS 部署脚本
本方案采用 TSP 进行 TLS 前置分流，后端使用 Trojan-Go、V2Ray 容器与 WatchTower、Portainer 维护组件配合，实现快速部署、易用易维护的极致体验。

最新版：
```Bash
wget -N --no-check-certificate -q "https://cdn.jsdelivr.net/gh/h31105/trojan_v2_docker_onekey/deploy.sh" && \
chmod +x deploy.sh && bash deploy.sh
```
老版本：（不支持VLESS协议&Trojan-Go WebSocket配置）
```Bash
wget -N --no-check-certificate -q "https://cdn.jsdelivr.net/gh/h31105/trojan_v2_docker_onekey@1.00/deploy.sh" && \
chmod +x deploy.sh && bash deploy.sh
```
**提醒：** 由于 1.10 版本改动较多，使用 1.00 以前版本脚本部署的环境，**与新版脚本存在配置兼容性问题，请在脚本升级后，根据提示重新安装 TLS-Shunt-Proxy 来完成新版本的配置适配。**（更新内容详见 Release 页面）

    使用简介：
    ——————————————————————部署管理——————————————————————
    1.  安装 TLS-Shunt-Proxy（网站&自动管理证书）
    2.  安装 Trojan-Go TCP/WS 代理（容器）
    3.  安装 V2Ray TCP/WS 代理（容器）
    4.  安装 WatchTower（自动更新容器）
    5.  安装 Portainer（Web管理容器）
    ——————————————————————配置修改——————————————————————
    6.  修改 TLS 端口/域名
    7.  修改 Trojan-Go 代理配置
    8.  修改 V2Ray 代理配置
    ——————————————————————查看信息——————————————————————
    9.  查看配置信息
    ——————————————————————杂项管理——————————————————————
    10. 升级 TLS-Shunt-Proxy/Docker 基础平台
    11. 卸载 已安装的所有组件
    12. 安装 4合1 BBR 锐速脚本
    0.  退出脚本 
    ————————————————————————————————————————————————————
    
部署建议为：

- TLS-Shunt-Proxy 负责证书全自动管理和网站服务（HTTPS 默认443 HTTP 80 自动跳转）
- Trojan-Go 容器化部署 (可支持WebSocket)
- V2Ray 容器化部署（VLESS/VMess协议）
- 容器的镜像由 WatchTower 监控并自动更新（建议安装）
  *WatchTower 无需额外配置，已配置为自动更新容器并清理过期镜像）
- Portainer 基于 Web 的 Docker 管理服务（可选）
  *Portainer 安装后，请尽快访问管理地址：http://<server.domain.name>:9080，设置管理帐号和密码。
  
**注意：
本脚本为单用户配置，部署后可以自定义配置内容，但不要使用脚本菜单中的修改选项，修改选项会 重置 相关配置信息。部署后，请按需开启防火墙端口，例如 HTTP 80、9080 及 HTTPS 443 端口。**

配置文件位置：
- 静态网站路径：/home/wwwroot/
- TLS-Shunt-Proxy：/etc/tls-shunt-proxy/config.yaml
- Trojan-Go：/etc/trojan-go/config.json
- V2ray：/etc/v2ray/config.json

本脚本最初基于**wulabing**的优质脚本**V2Ray_ws-tls_bash_onekey**改写，脚本中使用的Docker镜像来自于**秋水逸冰（Teddysun）**，在此感谢！

其他参考：
- [V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)
- [teddysun@DockerHub](https://hub.docker.com/u/teddysun/)
- [Trojan-Go](https://github.com/p4gefau1t/trojan-go)
- [V2Ray](https://www.v2fly.org/)
- [TLS-Shunt-Proxy](https://github.com/liberal-boy/tls-shunt-proxy)
- [Dcoker](https://www.docker.com/)
- [WatchTower](https://github.com/containrrr/watchtower)
- [Portainer](https://github.com/portainer/portainer)

[![H31105's github stats](https://github-readme-stats.vercel.app/api?username=h31105&count_private=true&show_icons=true)](https://github.com/h31105)
