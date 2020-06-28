    # trojan_v2_docker_onekey
    ## 基于 Docker 容器架构的 Trojan-Go / V2Ray WS TLS 部署脚本

    ### 本脚本基于 wulabing大佬的优质脚本 V2Ray_ws-tls_bash_onekey 改写而成，
    ### 使用Docker容器化部署Trojan-Go和V2Ray，前端使用TLS-Shunt-Proxy进行TLS端口共用分流。
    ### 本脚本中使用的Docker镜像来自于 秋水大佬 在此感谢！

```Bash
wget -N --no-check-certificate -q "https://raw.githubusercontent.com/h31105/trojan_v2_docker_onekey/master/deploy.sh" && \
chmod +x deploy.sh && bash deploy.sh
```

    使用简介：
    ————————————————————部署管理————————————————————
    
    1.  安装 TLS-Shunt-Proxy（证书管理&网站伪装）
    2.  安装 Trojan-Go / V2Ray WS 
    3.  添加 WatchTower（容器自动更新）
    4.  添加 Portainer（容器管理）
    
    ————————————————————配置修改————————————————————
    
    5.  修改 Troan-Go 配置
    6.  修改 V2Ray WS 配置
    7.  修改 TLS端口 / 域名
    
    ————————————————————查看信息————————————————————
    
    8.  查看 Trojan-Go / V2Ray 配置信息
    
    ————————————————————杂项管理————————————————————
    
    9.  安装 4合1 BBR 锐速脚本
    10. 升级 Docker / TLS-Shunt-Proxy
    11. 卸载 已安装的组件
    0.  退出脚本
    
    ————————————————————————————————————————————————
    
    部署建议为：
    1 TLS-Shunt-Proxy 负责证书全自动管理和网站服务（HTTPS 默认443）
    2 Trojan-Go 和 V2Ray WS 容器化部署，可二选一，也可同时部署，并与网站共用TLS端口
    3 容器的镜像由 WatchTower 监控并自动更新 （建议安装）
    4 Portainer Docker的Web UI管理服务（HTTP 80）（可选）

    注意：
    本脚本为Trojan-Go/V2Ray单用户配置，部署后，可以自定义配置内容，
    但不要使用脚本菜单中的修改选项，修改选项会 重置 相关配置信息。
    ！部署后，请按需开启防火墙端口，例如 HTTP 80 HTTPS 443 端口

    配置文件位置：
    网站路径 /home/wwwroot/ 证书文件存放在 /etc/ssl 由TSP自动管理。其他配置文件位置如下：
    TLS-Shunt-Proxy : /etc/tls-shunt-proxy/config.yaml
    Trojan-Go ： /etc/trojan-go/config.json
    V2ray : /etc/v2ray/config.json

    其他参考：
    # https://github.com/wulabing/V2Ray_ws-tls_bash_onekey
    # https://hub.docker.com/u/teddysun/
    # https://github.com/p4gefau1t/trojan-go
    # https://www.v2ray.com/
    # https://github.com/liberal-boy/tls-shunt-proxy
    # https://www.docker.com/
    # https://github.com/containrrr/watchtower
    # https://github.com/portainer/portainer
