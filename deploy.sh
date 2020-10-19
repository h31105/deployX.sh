#!/bin/bash

#MIT License
#Copyright (c) 2020 h31105

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

#====================================================
# System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
# Author: Miroku/h31105
# Dscription: TLS-Shunt-Proxy&Trojan-Go&V2Ray Script
# Official document:
# https://www.v2ray.com/
# https://github.com/p4gefau1t/trojan-go
# https://github.com/liberal-boy/tls-shunt-proxy
# https://www.docker.com/
# https://github.com/containrrr/watchtower
# https://github.com/portainer/portainer
# https://github.com/wulabing/V2Ray_ws-tls_bash_onekey
#====================================================

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

#Fonts Color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;30m"
RedBG="\033[41;30m"
Font="\033[0m"

#Notification Information
OK="${Green}[OK]${Font}"
WARN="${Yellow}[警告]${Font}"
Error="${Red}[错误]${Font}"

#版本、初始化变量
shell_version="1.179.1"
tsp_cfg_version="0.61.1"
#install_mode="docker"
upgrade_mode="none"
github_branch="master"
version_cmp="/tmp/version_cmp.tmp"
tsp_conf_dir="/etc/tls-shunt-proxy"
trojan_conf_dir="/etc/trojan-go"
v2ray_conf_dir="/etc/v2ray"
tsp_conf="${tsp_conf_dir}/config.yaml"
tsp_cert_dir="/etc/ssl/tls-shunt-proxy/certificates/acme-v02.api.letsencrypt.org-directory"
trojan_conf="${trojan_conf_dir}/config.json"
v2ray_conf="${v2ray_conf_dir}/config.json"
web_dir="/home/wwwroot"
random_num=$((RANDOM % 3 + 7))

#shellcheck disable=SC1091
source '/etc/os-release'

#从VERSION中提取发行版系统的英文名称
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -eq 7 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum -y -q"
        yum install epel-release -y -q
    elif [[ "${ID}" == "centos" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="dnf -y"
        dnf install epel-release -y -q
        dnf config-manager --set-enabled PowerTools
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt -y -qq"
        $INS update
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt -y -qq"
        $INS update
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi

    $INS install dbus
    systemctl stop firewalld
    echo -e "${OK} ${GreenBG} Firewalld 已关闭 ${Font}"
    systemctl stop ufw
    echo -e "${OK} ${GreenBG} UFW 已关闭 ${Font}"
}

is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} 当前用户是root用户，继续执行 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}"
        exit 1
    fi
}

judge() {
    #shellcheck disable=SC2181
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败 ${Font}"
        exit 1
    fi
}

urlEncode() {
    jq -R -r @uri <<<"$1"
}

chrony_install() {
    ${INS} install chrony
    judge "安装 Chrony 时间同步服务"
    timedatectl set-ntp true
    if [[ "${ID}" == "centos" ]]; then
        systemctl enable chronyd && systemctl restart chronyd
    else
        systemctl enable chrony && systemctl restart chrony
    fi
    judge "Chrony 启动"
    timedatectl set-timezone Asia/Shanghai
    echo -e "${OK} ${GreenBG} 等待时间同步 ${Font}"
    sleep 10
    chronyc sourcestats -v
    chronyc tracking -v
    date
    read -rp "请确认时间是否准确，误差范围±3分钟 (Y/N) [Y]: " chrony_install
    [[ -z ${chrony_install} ]] && chrony_install="Y"
    case $chrony_install in
    [yY][eE][sS] | [yY])
        echo -e "${GreenBG} 继续执行 ${Font}"
        sleep 2
        ;;
    *)
        echo -e "${RedBG} 终止执行 ${Font}"
        exit 2
        ;;
    esac
}

dependency_install() {
    ${INS} install curl git lsof unzip
    judge "安装依赖包 curl git lsof unzip"
    ${INS} install haveged
    systemctl start haveged && systemctl enable haveged
    command -v bc >/dev/null 2>&1 || ${INS} install bc
    judge "安装依赖包 bc"
    command -v jq >/dev/null 2>&1 || ${INS} install jq
    judge "安装依赖包 jq"
    command -v sponge >/dev/null 2>&1 || ${INS} install moreutils
    judge "安装依赖包 moreutils"
    command -v qrencode >/dev/null 2>&1 || ${INS} install qrencode
    judge "安装依赖包 qrencode"
}

basic_optimization() {
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf
    # 关闭 Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi
}

config_exist_check() {
    if [[ -f "$1" ]]; then
        echo -e "${OK} ${GreenBG} 检测到旧配置文件，自动备份旧文件配置 ${Font}"
        cp "$1" "$1.$(date +%Y%m%d%H)"
        echo -e "${OK} ${GreenBG} 已备份旧配置 ${Font}"
    fi
}

domain_port_check() {
    read -rp "请输入TLS端口(默认443):" tspport
    [[ -z ${tspport} ]] && tspport="443"
    read -rp "请输入你的域名信息(例如:fk.gfw.com):" domain
    domain_ip=$(ping -q -c 1 -t 1 "${domain}" | grep PING | sed -e "s/).*//" | sed -e "s/.*(//")
    echo -e "${OK} ${GreenBG} 正在获取 公网ip 信息，请耐心等待 ${Font}"
    local_ip=$(curl -s https://api64.ipify.org)
    echo -e "域名DNS解析IP：${domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ "${local_ip}" = "${domain_ip}" ]]; then
        echo -e "${OK} ${GreenBG} 域名DNS解析IP 与 本机IP 匹配 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 请确保域名添加了正确的 A/AAAA 记录，否则将无法正常连接 ${Font}"
        echo -e "${Error} ${RedBG} 域名DNS解析IP 与 本机IP 不匹配 是否继续安装？（Y/N）[N]${Font}" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
            echo -e "${GreenBG} 继续安装 ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}"
            exit 2
            ;;
        esac
    fi
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    fi
}

service_status_check() {
    if systemctl is-active "$1" &>/dev/null; then
        echo -e "${OK} ${GreenBG} $1 已经启动 ${Font}"
        if systemctl is-enabled "$1" &>/dev/null; then
            echo -e "${OK} ${GreenBG} $1 是开机自启动项 ${Font}"
        else
            echo -e "${WARN} ${Yellow} $1 不是开机自启动项 ${Font}"
            systemctl enable "$1"
            judge "设置 $1 为开机自启动"
        fi
    else
        echo -e "${Error} ${RedBG} 检测到 $1 服务未启动，正在尝试启动... ${Font}"
        systemctl restart "$1" && systemctl enable "$1"
        judge "尝试启动 $1 "
        sleep 5
        if systemctl is-active "$1" &>/dev/null; then
            echo -e "${OK} ${GreenBG} $1 已经启动 ${Font}"
        else
            echo -e "${WARN} ${Yellow} 请尝试重新安装修复 $1 后再试 ${Font}"
            exit 4
        fi
    fi
}

prereqcheck() {
    service_status_check docker
    if [[ -f ${tsp_conf} ]]; then
        service_status_check tls-shunt-proxy
    else
        echo -e "${Error} ${RedBG} TLS-Shunt-Proxy 配置异常，请尝试重新安装 ${Font}"
        exit 4
    fi
}

trojan_reset() {
    config_exist_check ${trojan_conf}
    [[ -f ${trojan_conf} ]] && rm -rf ${trojan_conf}
    if [[ -f ${tsp_conf} ]]; then
        TSP_Domain=$(grep '#TSP_Domain' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') && echo -e "检测到TLS域名为: ${TSP_Domain}"
    else
        echo -e "${Error} ${RedBG} TLS-Shunt-Proxy 配置异常，无法检测到TLS域名信息，请重新安装后再试 ${Font}"
        exit 4
    fi
    read -rp "请输入密码(Trojan-Go)，默认随机 :" tjpasswd
    [[ -z ${tjpasswd} ]] && tjpasswd=$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})
    echo -e "${OK} ${GreenBG} Trojan-Go 密码: ${tjpasswd} ${Font}"
    read -rp "是否开启 WebSocket 模式支持 (Y/N) [N]:" trojan_ws_mode
    [[ -z ${trojan_ws_mode} ]] && trojan_ws_mode=false
    case $trojan_ws_mode in
    [yY][eE][sS] | [yY])
        tjwspath="/trojan/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"
        echo -e "${OK} ${GreenBG} Trojan-Go WebSocket 模式开启，WSPATH: ${tjwspath} ${Font}"
        trojan_ws_mode=true
        ;;
    *)
        trojan_ws_mode=false
        ;;
    esac
    trojan_tcp_mode=true
    tjport=$((RANDOM % 6666 + 10000)) && echo -e "${OK} ${GreenBG} Trojan-Go 监听端口为: $tjport ${Font}"
    mkdir -p $trojan_conf_dir
    cat >$trojan_conf <<-EOF
{
    "run_type": "server",
    "disable_http_check": true,
    "local_addr": "127.0.0.1",
    "local_port": ${tjport},
    "remote_addr": "1.1.1.1",
    "remote_port": 80,
    "fallback_addr": "1.1.1.1",
    "fallback_port": 443,
    "password": ["${tjpasswd}"],
    "transport_plugin": {
        "enabled": true,
        "type": "plaintext"
    },
    "websocket": {
        "enabled": ${trojan_ws_mode},
        "path": "${tjwspath}",
        "host": "${TSP_Domain}"
    }
}
EOF
    judge "Trojan-Go 配置生成"
    port_exist_check $tjport
    trojan_sync
    judge "同步 Trojan-Go 配置设置"
    systemctl restart tls-shunt-proxy && service_status_check tls-shunt-proxy
    judge "TLS-Shunt-Proxy 应用设置"
}

modify_trojan() {
    deployed_status_check
    echo -e "${WARN} ${Yellow} 修改 Trojan-Go 配置将重置现有的代理配置信息，是否继续 (Y/N) [N]? ${Font}"
    read -r modify_confirm
    [[ -z ${modify_confirm} ]] && modify_confirm="No"
    case $modify_confirm in
    [yY][eE][sS] | [yY])
        prereqcheck
        trojan_reset
        docker restart Trojan-Go
        ;;
    *) ;;
    esac
}

trojan_sync() {
    [[ -z $tjport ]] && tjport=40001
    [[ -z $tjwspath ]] && tjwspath=/trojan/none
    [[ -z $trojan_tcp_mode ]] && trojan_tcp_mode=none
    [[ -z $trojan_ws_mode ]] && trojan_ws_mode=none
    if [[ ${trojan_tcp_mode} = true ]]; then
        sed -i "/trojan: #Trojan_TCP/c \\    trojan: #Trojan_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_TCP/c \\      handler: proxyPass #Trojan_TCP" ${tsp_conf}
        sed -i "/#Trojan_TCP_Port/c \\      args: 127.0.0.1:${tjport} #Trojan_TCP_Port:${trojan_tcp_mode}" ${tsp_conf}
    else
        sed -i "/trojan: #Trojan_TCP/c \\    #trojan: #Trojan_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_TCP/c \\      #handler: proxyPass #Trojan_TCP" ${tsp_conf}
        sed -i "/#Trojan_TCP_Port/c \\      #args: 127.0.0.1:${tjport} #Trojan_TCP_Port:${trojan_tcp_mode}" ${tsp_conf}
    fi
    if [[ ${trojan_ws_mode} = true ]]; then
        sed -i "/#Trojan_WS_Path/c \\      - path: ${tjwspath} #Trojan_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_WS/c \\        handler: proxyPass #Trojan_WS" ${tsp_conf}
        sed -i "/#Trojan_WS_Port/c \\        args: 127.0.0.1:${tjport} #Trojan_WS_Port:${trojan_ws_mode}" ${tsp_conf}
    else
        sed -i "/#Trojan_WS_Path/c \\      #- path: ${tjwspath} #Trojan_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_WS/c \\        #handler: proxyPass #Trojan_WS" ${tsp_conf}
        sed -i "/#Trojan_WS_Port/c \\        #args: 127.0.0.1:${tjport} #Trojan_WS_Port:${trojan_ws_mode}" ${tsp_conf}
    fi
}

v2ray_mode_type() {
    read -rp "请选择 V2Ray TCP 模式协议类型：VMess(M)/VLESS(L)，默认跳过，(M/L) [Skip]:" v2ray_tcp_mode
    [[ -z ${v2ray_tcp_mode} ]] && v2ray_tcp_mode="none"
    case $v2ray_tcp_mode in
    [mM])
        echo -e "${GreenBG} 已选择 TCP 模式协议 VMess ${Font}"
        v2ray_tcp_mode="vmess"
        ;;
    [lL])
        echo -e "${GreenBG} 已选择 TCP 模式协议 VLESS ${Font}"
        v2ray_tcp_mode="vless"
        ;;
    none)
        echo -e "${GreenBG} 跳过 TCP 模式 部署 ${Font}"
        v2ray_tcp_mode="none"
        ;;
    *)
        echo -e "${RedBG} 请输入正确的字母 (M/L) ${Font}"
        ;;
    esac
    read -rp "请选择 V2Ray WebSocket 模式协议类型：VMess(M)/VLESS(L)，默认跳过，(M/L) [Skip]:" v2ray_ws_mode
    [[ -z ${v2ray_ws_mode} ]] && v2ray_ws_mode="none"
    case $v2ray_ws_mode in
    [mM])
        echo -e "${GreenBG} 已选择 WS 模式 VMess ${Font}"
        v2ray_ws_mode="vmess"
        ;;
    [lL])
        echo -e "${GreenBG} 已选择 WS 模式 VLESS ${Font}"
        v2ray_ws_mode="vless"
        ;;
    none)
        echo -e "${GreenBG} 跳过 WS 模式 部署 ${Font}"
        v2ray_ws_mode="none"
        ;;
    *)
        echo -e "${RedBG} 请输入正确的字母 (M/L) ${Font}"
        ;;
    esac
}

v2ray_reset() {
    config_exist_check ${v2ray_conf}
    [[ -f ${v2ray_conf} ]] && rm -rf ${v2ray_conf}
    mkdir -p $v2ray_conf_dir
    cat >$v2ray_conf <<-EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds":[
    ], 
    "outbounds": [
      {
        "protocol": "freedom", 
        "settings": {}, 
        "tag": "direct"
      }, 
      {
        "protocol": "blackhole", 
        "settings": {}, 
        "tag": "blocked"
      }
    ], 
    "dns": {
      "servers": [
        "https+local://1.1.1.1/dns-query",
	    "1.1.1.1",
	    "1.0.0.1",
	    "8.8.8.8",
	    "8.8.4.4",
	    "localhost"
      ]
    },
    "routing": {
      "rules": [
        {
            "ip": [
            "geoip:private"
            ],
            "outboundTag": "blocked",
            "type": "field"
        },
        {
          "type": "field",
          "outboundTag": "blocked",
          "protocol": ["bittorrent"]
        },
        {
          "type": "field",
          "inboundTag": [
          ],
          "outboundTag": "direct"
        }
      ]
    }
}
EOF
    if [[ "${v2ray_ws_mode}" = v*ess ]]; then
        UUID=$(cat /proc/sys/kernel/random/uuid)
        echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
        v2wspath="/v2ray/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"
        echo -e "${OK} ${GreenBG} 开启V2Ray WS模式，WSPATH: ${v2wspath} ${Font}"
        v2wsport=$((RANDOM % 6666 + 30000))
        echo -e "${OK} ${GreenBG} V2Ray WS 监听端口为 ${v2wsport} ${Font}"
        if [[ "${v2ray_ws_mode}" = "vmess" ]]; then
            #read -rp "请输入 WS 模式 AlterID（默认:10 仅允许填非0数字）:" alterID
            [[ -z ${alterID} ]] && alterID="10"
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2wsport}',"listen":"127.0.0.1","tag":"vmess-ws-in","protocol":"vmess","settings":{"clients":[{"id":"'"${UUID}"'","alterId":'${alterID}'}]},"streamSettings":{"network":"ws","wsSettings":{"acceptProxyProtocol":true,"path":"'"${v2wspath}"'"}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vmess-ws-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VMess WS配置生成"
        fi
        if [[ "${v2ray_ws_mode}" = "vless" ]]; then
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2wsport}',"listen":"127.0.0.1","tag":"vless-ws-in","protocol":"vless","settings":{"clients":[{"id":"'"${UUID}"'","level":0}],"decryption":"none"},"streamSettings":{"network":"ws","wsSettings":{"acceptProxyProtocol":true,"path":"'"${v2wspath}"'"}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vless-ws-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VLESS WS配置生成"
        fi
        port_exist_check ${v2wsport}
    fi
    if [[ "${v2ray_tcp_mode}" = v*ess ]]; then
        UUID=$(cat /proc/sys/kernel/random/uuid)
        echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
        v2port=$((RANDOM % 6666 + 20000))
        echo -e "${OK} ${GreenBG} V2Ray TCP 监听端口为 ${v2port} ${Font}"
        if [[ "${v2ray_tcp_mode}" = "vmess" ]]; then
            #read -rp "请输入 TCP 模式 AlterID（默认:10 仅允许填非0数字）:" alterID
            [[ -z ${alterID} ]] && alterID="10"
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2port}',"listen":"127.0.0.1","tag":"vmess-tcp-in","protocol":"vmess","settings":{"clients":[{"id":"'"${UUID}"'","alterId":'${alterID}'}]},"streamSettings":{"network":"tcp","tcpSettings":{"acceptProxyProtocol":true}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vmess-tcp-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VMess TCP配置生成"
        fi
        if [[ "${v2ray_tcp_mode}" = "vless" ]]; then
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2port}',"listen":"127.0.0.1","tag":"vless-tcp-in","protocol":"vless","settings":{"clients":[{"id":"'"${UUID}"'","level":0}],"decryption":"none"},"streamSettings":{"network":"tcp","tcpSettings":{"acceptProxyProtocol":true}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vless-tcp-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VLESS TCP配置生成"
        fi
        port_exist_check ${v2port}
    fi
    if [[ -f ${tsp_conf} ]]; then
        v2ray_sync
        judge "同步 V2Ray 配置"
        systemctl restart tls-shunt-proxy && service_status_check tls-shunt-proxy
        judge "TLS-Shunt-Proxy 应用设置"
    else
        echo -e "${Error} ${RedBG} TLS-Shunt-Proxy 配置异常，请重新安装后再试 ${Font}"
        exit 4
    fi
}

modify_v2ray() {
    deployed_status_check
    echo -e "${WARN} ${Yellow} 修改 V2Ray 配置将重置现有的代理配置信息，是否继续 (Y/N) [N]? ${Font}"
    read -r modify_confirm
    [[ -z ${modify_confirm} ]] && modify_confirm="No"
    case $modify_confirm in
    [yY][eE][sS] | [yY])
        prereqcheck
        v2ray_mode_type
        [[ $v2ray_tcp_mode != "none" || $v2ray_ws_mode != "none" ]] && v2ray_reset
        docker restart V2Ray
        ;;
    *) ;;
    esac
}

v2ray_sync() {
    [[ -z $v2port ]] && v2port=40003
    [[ -z $v2wsport ]] && v2wsport=40002
    [[ -z $v2wspath ]] && v2wspath=/v2ray/none
    [[ -z $v2ray_tcp_mode ]] && v2ray_tcp_mode=none
    [[ -z $v2ray_ws_mode ]] && v2ray_ws_mode=none
    if [[ ${v2ray_tcp_mode} = v*ess ]]; then
        sed -i "/default: #V2Ray_TCP/c \\    default: #V2Ray_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_TCP/c \\      handler: proxyPass #V2Ray_TCP" ${tsp_conf}
        sed -i "/#V2Ray_TCP_Port/c \\      args: 127.0.0.1:${v2port};proxyProtocol #V2Ray_TCP_Port:${v2ray_tcp_mode}" ${tsp_conf}
    else
        sed -i "/default: #V2Ray_TCP/c \\    #default: #V2Ray_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_TCP/c \\      #handler: proxyPass #V2Ray_TCP" ${tsp_conf}
        sed -i "/#V2Ray_TCP_Port/c \\      #args: 127.0.0.1:${v2port};proxyProtocol #V2Ray_TCP_Port:${v2ray_tcp_mode}" ${tsp_conf}
    fi
    if [[ ${v2ray_ws_mode} = v*ess ]]; then
        sed -i "/#V2Ray_WS_Path/c \\      - path: ${v2wspath} #V2Ray_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_WS/c \\        handler: proxyPass #V2Ray_WS" ${tsp_conf}
        sed -i "/#V2Ray_WS_Port/c \\        args: 127.0.0.1:${v2wsport};proxyProtocol #V2Ray_WS_Port:${v2ray_ws_mode}" ${tsp_conf}
    else
        sed -i "/#V2Ray_WS_Path/c \\      #- path: ${v2wspath} #V2Ray_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_WS/c \\        #handler: proxyPass #V2Ray_WS" ${tsp_conf}
        sed -i "/#V2Ray_WS_Port/c \\        #args: 127.0.0.1:${v2wsport};proxyProtocol #V2Ray_WS_Port:${v2ray_ws_mode}" ${tsp_conf}
    fi
}

web_camouflage() {
    ##请注意 这里和LNMP脚本的默认路径冲突，千万不要在安装了LNMP的环境下使用本脚本，否则后果自负
    rm -rf $web_dir
    mkdir -p $web_dir
    cd $web_dir || exit
    websites[0]="https://github.com/h31105/LodeRunner_TotalRecall.git"
    websites[1]="https://github.com/h31105/adarkroom.git"
    websites[2]="https://github.com/h31105/webosu"
    selectedwebsite=${websites[$RANDOM % ${#websites[@]}]}
    git clone ${selectedwebsite} web_camouflage
    judge "WebSite 伪装"
}

install_docker() {
    echo -e "${GreenBG} 开始安装 Docker 最新版本 ... ${Font}"
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    judge "安装 Docker "
    systemctl daemon-reload
    systemctl enable docker && systemctl restart docker
    judge "Docker 启动"
}

install_tsp() {
    bash <(curl -L -s https://raw.githubusercontent.com/liberal-boy/tls-shunt-proxy/master/dist/install.sh)
    judge "安装 TLS-Shunt-Proxy"
    chown -R tls-shunt-proxy:tls-shunt-proxy /etc/ssl/tls-shunt-proxy
    command -v setcap >/dev/null 2>&1 && setcap "cap_net_bind_service=+ep" /usr/local/bin/tls-shunt-proxy
    config_exist_check ${tsp_conf}
    [[ -f ${tsp_conf} ]] && rm -rf ${tsp_conf}
    mkdir -p $tsp_conf_dir
    cat >$tsp_conf <<-EOF
#TSP_CFG_Ver:${tsp_cfg_version}
listen: 0.0.0.0:${tspport} #TSP_Port
redirecthttps: 0.0.0.0:80
inboundbuffersize: 4
outboundbuffersize: 32
vhosts:
  - name: ${domain} #TSP_Domain
    tlsoffloading: true
    managedcert: true
    keytype: p256
    alpn: h2,http/1.1
    protocols: tls12,tls13
    http:
      paths:
      #- path: /trojan/none #Trojan_WS_Path
        #handler: proxyPass #Trojan_WS
        #args: 127.0.0.1:40000 #Trojan_WS_Port:${trojan_ws_mode}
      #- path: /v2ray/none #V2Ray_WS_Path
        #handler: proxyPass #V2Ray_WS
        #args: 127.0.0.1:40002;proxyProtocol #V2Ray_WS_Port:${v2ray_ws_mode}
      handler: fileServer
      args: ${web_dir}/web_camouflage #Website_camouflage
    #trojan: #Trojan_TCP
      #handler: proxyPass #Trojan_TCP
      #args: 127.0.0.1:40001 #Trojan_TCP_Port:${trojan_tcp_mode}
    #default: #V2Ray_TCP
      #handler: proxyPass #V2Ray_TCP
      #args: 127.0.0.1:40003;proxyProtocol #V2Ray_TCP_Port:${v2ray_tcp_mode}
EOF
    judge "配置 TLS-Shunt-Proxy"
    systemctl daemon-reload && systemctl reset-failed
    systemctl enable tls-shunt-proxy && systemctl restart tls-shunt-proxy
    judge "启动 TLS-Shunt-Proxy"
}

modify_tsp() {
    domain_port_check
    sed -i "/#TSP_Port/c \\listen: 0.0.0.0:${tspport} #TSP_Port" ${tsp_conf}
    sed -i "/#TSP_Domain/c \\  - name: ${domain} #TSP_Domain" ${tsp_conf}
    tsp_sync
}

tsp_sync() {
    echo -e "${OK} ${GreenBG} 检测并同步现有代理配置... ${Font}"
    if [[ $trojan_stat = "installed" && -f ${trojan_conf} ]]; then
        tjport="$(grep '"local_port"' ${trojan_conf} | sed -r 's/.*: (.*),.*/\1/')" && trojan_tcp_mode=true &&
            tjwspath="$(grep '"path":' ${trojan_conf} | awk -F '"' '{print $4}')" && trojan_ws_mode="$(jq -r '.websocket.enabled' ${trojan_conf})"
        judge "检测 Trojan-Go 配置"
        [[ -z $tjport ]] && trojan_tcp_mode=false
        [[ $trojan_ws_mode = null ]] && trojan_ws_mode=false
        [[ -z $tjwspath ]] && tjwspath=/trojan/none
        echo -e "检测到：Trojan-Go 代理：TCP：${Green}${trojan_tcp_mode}${Font} / WebSocket：${Green}${trojan_ws_mode}${Font} / 端口：${Green}${tjport}${Font} / WebSocket Path：${Green}${tjwspath}${Font}"
    fi

    if [[ $v2ray_stat = "installed" && -f ${v2ray_conf} ]]; then
        sed -i '/\#\"/d' ${v2ray_conf}
        v2port="$(jq -r '[.inbounds[] | select(.streamSettings.network=="tcp") | .port][0]' ${v2ray_conf})" &&
            v2wsport="$(jq -r '[.inbounds[] | select(.streamSettings.network=="ws") | .port][0]' ${v2ray_conf})" &&
            v2ray_tcp_mode="$(jq -r '[.inbounds[] | select(.streamSettings.network=="tcp") | .protocol][0]' ${v2ray_conf})" &&
            v2ray_ws_mode="$(jq -r '[.inbounds[] | select(.streamSettings.network=="ws") | .protocol][0]' ${v2ray_conf})" &&
            v2wspath="$(jq -r '[.inbounds[] | select(.streamSettings.network=="ws") | .streamSettings.wsSettings.path][0]' ${v2ray_conf})"
        judge "检测 V2Ray 配置"
        [[ $v2port = null ]] && v2port=40003
        [[ $v2wsport = null ]] && v2wsport=40002
        [[ $v2ray_tcp_mode = null ]] && v2ray_tcp_mode=none
        [[ $v2ray_ws_mode = null ]] && v2ray_ws_mode=none
        [[ $v2wspath = null ]] && v2wspath=/v2ray/none
        echo -e "检测到：V2Ray 代理：TCP：${Green}${v2ray_tcp_mode}${Font} 端口：${Green}${v2port}${Font} / WebSocket：${Green}${v2ray_ws_mode}${Font} 端口：${Green}${v2wsport}${Font} / WebSocket Path：${Green}${v2wspath}${Font}"
    fi

    if [[ -f ${tsp_conf} ]]; then
        trojan_sync
        v2ray_sync
        tsp_config_stat="synchronized"
        systemctl restart tls-shunt-proxy
        judge "分流配置同步"
        menu_req_check tls-shunt-proxy
    else
        echo -e "${Error} ${RedBG} TLS-Shunt-Proxy 配置异常，请重新安装后再试 ${Font}"
        exit 4
    fi
}

install_trojan() {
    systemctl is-active "docker" &>/dev/null || install_docker
    prereqcheck
    trojan_reset
    docker pull teddysun/trojan-go
    docker run -d --network host --name Trojan-Go --restart=always -v /etc/trojan-go:/etc/trojan-go teddysun/trojan-go
    judge "Trojan-Go 容器安装"
}

install_v2ray() {
    systemctl is-active "docker" &>/dev/null || install_docker
    prereqcheck
    v2ray_mode_type
    [[ $v2ray_tcp_mode = "vmess" || $v2ray_ws_mode = "vmess" ]] && check_system && chrony_install
    if [[ $v2ray_tcp_mode != "none" || $v2ray_ws_mode != "none" ]]; then
        v2ray_reset
        docker pull teddysun/v2ray
        docker run -d --network host --name V2Ray --restart=always -v /etc/v2ray:/etc/v2ray teddysun/v2ray
        judge "V2Ray 容器安装"
    fi
}

install_watchtower() {
    docker pull containrrr/watchtower
    docker run -d --name WatchTower --restart=always -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --cleanup
    judge "WatchTower 容器安装"
}

install_portainer() {
    docker volume create portainer_data
    docker pull portainer/portainer-ce
    docker run -d -p 9080:9000 --name Portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce
    judge "Portainer 容器安装"
    echo -e "${OK} ${GreenBG} Portainer 管理地址为 http://$TSP_Domain:9080 请自行开启防火墙端口！ ${Font}"
}

install_tls_shunt_proxy() {
    check_system
    dependency_install
    basic_optimization
    domain_port_check
    port_exist_check "${tspport}"
    port_exist_check 80
    config_exist_check "${tsp_conf}"
    web_camouflage
    install_tsp
}

uninstall_all() {
    echo -e "${RedBG} !!!此操作将删除 TLS-Shunt-Proxy、Docker 平台和此脚本所安装的容器数据!!! ${Font}"
    read -rp "请在确认后，输入 YES（区分大小写）:" uninstall
    [[ -z ${uninstall} ]] && uninstall="No"
    case $uninstall in
    YES)
        echo -e "${GreenBG} 开始卸载 ${Font}"
        sleep 2
        ;;
    *)
        echo -e "${RedBG} 我再想想 ${Font}"
        exit 1
        ;;
    esac
    check_system
    uninstall_proxy_server
    uninstall_watchtower
    uninstall_portainer
    systemctl stop docker && systemctl disable docker
    if [[ "${ID}" == "centos" ]]; then
        ${INS} remove docker-ce docker-ce-cli containerd.io docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine
    else
        ${INS} remove docker-ce docker-ce-cli containerd.io docker docker-engine docker.io containerd runc
    fi
    #rm -rf /var/lib/docker #Removes all docker data
    rm -rf /etc/systemd/system/docker.service
    uninstall_tsp
    echo -e "${OK} ${GreenBG} 所有组件卸载完成，欢迎再次使用本脚本! ${Font}"
    exit 0
}

uninstall_tsp() {
    systemctl stop tls-shunt-proxy && systemctl disable tls-shunt-proxy
    rm -rf /etc/systemd/system/tls-shunt-proxy.service
    rm -rf /usr/local/bin/tls-shunt-proxy
    rm -rf $tsp_conf_dir
    userdel -rf tls-shunt-proxy
    tsp_stat="none"
    rm -rf ${web_dir}/web_camouflage
    echo -e "${OK} ${GreenBG} TLS-Shunt-Proxy 卸载完成！${Font}"
    sleep 3
}

uninstall_proxy_server() {
    uninstall_trojan
    uninstall_v2ray
    echo -e "${OK} ${GreenBG} 卸载（Trojan-Go/V2Ray）TCP/WS 代理完成！ ${Font}"
    sleep 3
}

uninstall_trojan() {
    rm -rf $trojan_conf_dir
    trojan_ws_mode="none" && trojan_tcp_mode="none"
    [ -f ${tsp_conf} ] && trojan_sync
    systemctl start docker
    [[ $trojan_stat = "installed" ]] && docker stop Trojan-Go && docker rm -f Trojan-Go &&
        echo -e "${OK} ${GreenBG} 卸载 Trojan-Go TCP/WS 代理完成！ ${Font}"
}

uninstall_v2ray() {
    rm -rf $v2ray_conf_dir
    v2ray_ws_mode="none" && v2ray_tcp_mode="none"
    [ -f ${tsp_conf} ] && v2ray_sync
    systemctl start docker
    [[ $v2ray_stat = "installed" ]] && docker stop V2Ray && docker rm -f V2Ray &&
        echo -e "${OK} ${GreenBG} 卸载 V2Ray TCP/WS 代理完成！ ${Font}"
}
uninstall_watchtower() {
    docker stop WatchTower && docker rm -f WatchTower && watchtower_stat="none" &&
        echo -e "${OK} ${GreenBG} 卸载 WatchTower 完成！ ${Font}"
    sleep 3
}

uninstall_portainer() {
    docker stop Portainer && docker rm -fv Portainer && portainer_stat="none" &&
        echo -e "${OK} ${GreenBG} 卸载 Portainer 完成！ ${Font}"
    sleep 3
}

upgrade_tsp() {
    current_version="$(/usr/local/bin/tls-shunt-proxy --version 2>&1 | awk 'NR==1{gsub(/"/,"");print $3}')"
    echo -e "${GreenBG} TLS-Shunt-Proxy 当前版本: ${current_version}，开始检测最新版本... ${Font}"
    latest_version="$(wget --no-check-certificate -qO- https://api.github.com/repos/liberal-boy/tls-shunt-proxy/tags | grep 'name' | cut -d\" -f4 | head -1)"
    [[ -z ${latest_version} ]] && echo -e "${Error} 检测最新版本失败 ! ${Font}" && menu
    if [[ ${latest_version} != "${current_version}" ]]; then
        echo -e "${OK} ${GreenBG} 当前版本: ${current_version} 最新版本: ${latest_version}，是否更新 (Y/N) [N]? ${Font}"
        read -r update_confirm
        [[ -z ${update_confirm} ]] && update_confirm="No"
        case $update_confirm in
        [yY][eE][sS] | [yY])
            config_exist_check "${tsp_conf}"
            bash <(curl -L -s https://raw.githubusercontent.com/liberal-boy/tls-shunt-proxy/master/dist/install.sh)
            judge "TLS-Shunt-Proxy 更新"
            systemctl daemon-reload && systemctl reset-failed
            systemctl enable tls-shunt-proxy && systemctl restart tls-shunt-proxy
            judge "TLS-Shunt-Proxy 重新启动"
            ;;
        *) ;;
        esac
    else
        echo -e "${OK} ${GreenBG} 当前 TLS-Shunt-Proxy 已经为最新版本 ${current_version} ${Font}"
    fi
}

update_sh() {
    ol_version=$(curl -L -s https://raw.githubusercontent.com/h31105/trojan_v2_docker_onekey/${github_branch}/deploy.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
    echo "$ol_version" >$version_cmp
    echo "$shell_version" >>$version_cmp
    if [[ "$shell_version" < "$(sort -rV $version_cmp | head -1)" ]]; then
        echo -e "${OK} ${GreenBG} 更新内容：${Font}"
        echo -e "${Yellow}$(curl --silent https://api.github.com/repos/h31105/trojan_v2_docker_onekey/releases/latest | grep body | head -n 1 | awk -F '"' '{print $4}')${Font}"
        echo -e "${OK} ${GreenBG} 存在新版本，是否更新 (Y/N) [N]? ${Font}"
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            wget -N --no-check-certificate https://raw.githubusercontent.com/h31105/trojan_v2_docker_onekey/${github_branch}/deploy.sh
            echo -e "${OK} ${GreenBG} 更新完成，请重新运行脚本：\n#./deploy.sh ${Font}"
            exit 0
            ;;
        *) ;;
        esac
    else
        echo -e "${OK} ${GreenBG} 当前版本为最新版本 ${Font}"
    fi
}

list() {
    case $1 in
    uninstall)
        deployed_status_check
        uninstall_all
        ;;
    sync)
        deployed_status_check
        tsp_sync
        ;;
    debug)
        debug="enable"
        #set -xv
        menu
        ;;
    *)
        menu
        ;;
    esac
}

deployed_status_check() {
    tsp_stat="none" && trojan_stat="none" && v2ray_stat="none" && watchtower_stat="none" && portainer_stat="none"
    trojan_tcp_mode="none" && v2ray_tcp_mode="none" && trojan_ws_mode="none" && v2ray_ws_mode="none"
    tsp_config_stat="synchronized" && chrony_stat="none"

    echo -e "${OK} ${GreenBG} 检测分流配置信息... ${Font}"
    [[ -f ${tsp_conf} || -f '/usr/local/bin/tls-shunt-proxy' ]] &&
        tsp_template_version=$(grep '#TSP_CFG_Ver' ${tsp_conf} | sed -r 's/.*TSP_CFG_Ver:(.*) */\1/') && tsp_stat="installed" &&
        TSP_Port=$(grep '#TSP_Port' ${tsp_conf} | sed -r 's/.*0:(.*) #.*/\1/') && TSP_Domain=$(grep '#TSP_Domain' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') &&
        trojan_tcp_port=$(grep '#Trojan_TCP_Port' ${tsp_conf} | sed -r 's/.*:(.*) #.*/\1/') &&
        trojan_tcp_mode=$(grep '#Trojan_TCP_Port' ${tsp_conf} | sed -r 's/.*Trojan_TCP_Port:(.*) */\1/') &&
        trojan_ws_port=$(grep '#Trojan_WS_Port' ${tsp_conf} | sed -r 's/.*:(.*) #.*/\1/') &&
        trojan_ws_mode=$(grep '#Trojan_WS_Port' ${tsp_conf} | sed -r 's/.*Trojan_WS_Port:(.*) */\1/') &&
        trojan_ws_path=$(grep '#Trojan_WS_Path' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') &&
        v2ray_tcp_port=$(grep '#V2Ray_TCP_Port' ${tsp_conf} | sed -r 's/.*:(.*);.*/\1/') &&
        v2ray_tcp_mode=$(grep '#V2Ray_TCP_Port' ${tsp_conf} | sed -r 's/.*V2Ray_TCP_Port:(.*) */\1/') &&
        v2ray_ws_port=$(grep '#V2Ray_WS_Port' ${tsp_conf} | sed -r 's/.*:(.*);.*/\1/') &&
        v2ray_ws_mode=$(grep '#V2Ray_WS_Port' ${tsp_conf} | sed -r 's/.*V2Ray_WS_Port:(.*) */\1/') &&
        v2ray_ws_path=$(grep '#V2Ray_WS_Path' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') &&
        menu_req_check tls-shunt-proxy

    echo -e "${OK} ${GreenBG} 检测组件部署状态... ${Font}"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep Trojan-Go &>/dev/null && trojan_stat="installed"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep V2Ray &>/dev/null && v2ray_stat="installed"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep WatchTower &>/dev/null && watchtower_stat="installed"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep Portainer &>/dev/null && portainer_stat="installed"

    echo -e "${OK} ${GreenBG} 检测代理配置信息... ${Font}"

    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        tjport=$(grep '"local_port"' ${trojan_conf} | sed -r 's/.*: (.*),.*/\1/')
        tjpassword=$(grep '"password"' ${trojan_conf} | awk -F '"' '{print $4}')
        [[ $trojan_ws_mode = true ]] && tjwspath=$(grep '"path":' ${trojan_conf} | awk -F '"' '{print $4}') &&
            tjwshost=$(grep '"host":' ${trojan_conf} | awk -F '"' '{print $4}')
        [[ $trojan_tcp_mode = true && $tjport != "$trojan_tcp_port" ]] && echo -e "${Error} ${RedBG} 检测到 Trojan-Go TCP 端口分流配置异常 ${Font}" && tsp_config_stat="mismatched"
        [[ $trojan_ws_mode = true && $tjport != "$trojan_ws_port" ]] && echo -e "${Error} ${RedBG} 检测到 Trojan-Go WS 端口分流配置异常 ${Font}" && tsp_config_stat="mismatched"
        [[ $trojan_ws_mode = true && $tjwspath != "$trojan_ws_path" ]] && echo -e "${Error} ${RedBG} 检测到 Trojan-Go WS 路径分流配置异常 ${Font}" && tsp_config_stat="mismatched"
        [[ $tsp_config_stat = "mismatched" ]] && echo -e "${Error} ${RedBG} 检测到分流配置不一致，将尝试自动同步修复... ${Font}" && tsp_sync
    fi

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        [[ $v2ray_tcp_mode = "vmess" ]] &&
            v2port=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="tcp") | .port][0]' ${v2ray_conf}) &&
            VMTID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="tcp") | .settings.clients[].id][0]' ${v2ray_conf}) &&
            VMAID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="tcp") | .settings.clients[].alterId][0]' ${v2ray_conf})
        [[ $v2ray_tcp_mode = "vless" ]] &&
            v2port=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="tcp") | .port][0]' ${v2ray_conf}) &&
            VLTID=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="tcp") | .settings.clients[].id][0]' ${v2ray_conf})
        [[ $v2ray_ws_mode = "vmess" ]] &&
            v2wsport=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .port][0]' ${v2ray_conf}) &&
            v2wspath=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .streamSettings.wsSettings.path][0]' ${v2ray_conf}) &&
            VMWSID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .settings.clients[].id][0]' ${v2ray_conf}) &&
            VMWSAID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .settings.clients[].alterId][0]' ${v2ray_conf})
        [[ $v2ray_ws_mode = "vless" ]] &&
            v2wsport=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="ws") | .port][0]' ${v2ray_conf}) &&
            v2wspath=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="ws") | .streamSettings.wsSettings.path][0]' ${v2ray_conf}) &&
            VLWSID=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="ws") | .settings.clients[].id][0]' ${v2ray_conf})
        [[ $v2ray_tcp_mode = v*ess && $v2port != "$v2ray_tcp_port" ]] && echo -e "${Error} ${RedBG} 检测到 V2Ray TCP 端口分流配置异常 ${Font}" && tsp_config_stat="mismatched"
        [[ $v2ray_ws_mode = v*ess && $v2wsport != "$v2ray_ws_port" ]] && echo -e "${Error} ${RedBG} 检测到 V2Ray WS 端口分流配置异常 ${Font}" && tsp_config_stat="mismatched"
        [[ $v2ray_ws_mode = v*ess && $v2wspath != "$v2ray_ws_path" ]] && echo -e "${Error} ${RedBG} 检测到 V2Ray WS 路径分流配置异常 ${Font}" && tsp_config_stat="mismatched"
        [[ $tsp_config_stat = "mismatched" ]] && echo -e "${Error} ${RedBG} 检测到分流配置不一致，将尝试自动同步修复... ${Font}" && tsp_sync
        if [[ $v2ray_tcp_mode = "vmess" || $v2ray_ws_mode = "vmess" ]]; then
            if [[ "${ID}" == "centos" ]]; then
                systemctl is-active "chronyd" &>/dev/null || chrony_stat=inactive
            else
                systemctl is-active "chrony" &>/dev/null || chrony_stat=inactive
            fi
            if [[ $chrony_stat = inactive ]]; then
                echo -e "${Error} ${RedBG} 检测到 Chrony 时间同步服务未启动，若系统时间不准确将会严重影响 V2Ray VMess 协议的可用性 ${Font}\n${WARN} ${Yellow} 当前系统时间: $(date)，请确认时间是否准确，误差范围±3分钟内（Y）或 尝试修复时间同步服务（R）[R]: ${Font}"
                read -r chrony_confirm
                [[ -z ${chrony_confirm} ]] && chrony_confirm="R"
                case $chrony_confirm in
                [rR])
                    echo -e "${GreenBG} 安装 Chrony 时间同步服务 ${Font}"
                    check_system
                    chrony_install
                    ;;
                *) ;;
                esac
            fi
        fi
    fi

    [[ -f ${trojan_conf} || -f ${v2ray_conf} || $trojan_stat = "installed" || $v2ray_stat = "installed" ]] && menu_req_check docker
    [[ $trojan_stat = "installed" && ! -f $trojan_conf ]] && echo -e "\n${Error} ${RedBG} 检测到 Trojan-Go 代理配置异常，以下选项功能将被屏蔽，请尝试重装修复后重试... ${Font}" &&
        echo -e "${WARN} ${Yellow}[屏蔽] Trojan-Go 配置修改${Font}"
    [[ $v2ray_stat = "installed" && ! -f $v2ray_conf ]] && echo -e "\n${Error} ${RedBG} 检测到 V2Ray 代理配置异常，以下选项功能将被屏蔽，请尝试重装修复后重试... ${Font}" &&
        echo -e "${WARN} ${Yellow}[屏蔽] V2Ray 配置修改${Font}"

    if [[ $tsp_stat = "installed" && $tsp_template_version != "${tsp_cfg_version}" ]]; then
        echo -e "${WARN} ${Yellow}检测到 TLS-Shunt-Proxy 存在关键更新，为确保脚本正常运行，请确认立即执行更新操作（Y/N）[Y] ${Font}"
        read -r upgrade_confirm
        [[ -z ${upgrade_confirm} ]] && upgrade_confirm="Yes"
        case $upgrade_confirm in
        [yY][eE][sS] | [yY])
            uninstall_tsp
            install_tls_shunt_proxy
            tsp_sync
            deployed_status_check
            ;;
        *) ;;
        esac
    fi

    [[ $debug = "enable" ]] && echo -e "\n Trojan-Go 代理：TCP：${Green}${trojan_tcp_mode}${Font} / WebSocket：${Green}${trojan_ws_mode}${Font}\n     V2Ray 代理：TCP：${Green}${v2ray_tcp_mode}${Font} / WebSocket：${Green}${v2ray_ws_mode}${Font}" &&
        echo -e "\n 代理容器：Trojan-Go：${Green}${trojan_stat}${Font} / V2Ray：${Green}${v2ray_stat}${Font}" &&
        echo -e " 其他容器：WatchTower：${Green}${watchtower_stat}${Font} / Portainer：${Green}${portainer_stat}${Font}\n"
}

info_config() {
    deployed_status_check
    cert_stat_check tls-shunt-proxy
    echo -e "\n————————————————————分流配置信息————————————————————"
    if [ -f ${tsp_conf} ]; then
        echo -e "TLS-Shunt-Proxy $(/usr/local/bin/tls-shunt-proxy --version 2>&1 | awk 'NR==1{gsub(/"/,"");print $3}')" &&
            echo -e "服务器TLS端口: ${TSP_Port}" && echo -e "服务器TLS域名: ${TSP_Domain}"
        [[ $trojan_tcp_mode = true ]] && echo -e "Trojan-Go TCP 分流端口: $trojan_tcp_port" && echo -e "Trojan-Go 监听端口: $tjport"
        [[ $trojan_ws_mode = true ]] && echo -e "Trojan-Go WebSocket 分流端口: $trojan_ws_port" &&
            echo -e "Trojan-Go WebSocket 分流路径: $trojan_ws_path"
        [[ $v2ray_tcp_mode = v*ess ]] && echo -e "V2Ray TCP 分流端口: $v2ray_tcp_port" && echo -e "V2Ray TCP 监听端口: $v2port"
        [[ $v2ray_ws_mode = v*ess ]] && echo -e "V2Ray WebSocket 分流端口: $v2ray_ws_port" && echo -e "V2Ray WS 监听端口: $v2wsport" &&
            echo -e "V2Ray WebSocket 分流路径: $v2ray_ws_path"
    fi

    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        echo -e "—————————————————— Trojan-Go 配置 ——————————————————" &&
            echo -e "$(docker exec Trojan-Go sh -c 'trojan-go --version' 2>&1 | awk 'NR==1{gsub(/"/,"");print}')" &&
            echo -e "服务器端口: ${TSP_Port}" && echo -e "服务器地址: ${TSP_Domain}"
        [[ $trojan_tcp_mode = true ]] && echo -e "Trojan-Go 密码: ${tjpassword}"
        [[ $trojan_ws_mode = true ]] &&
            echo -e "Trojan-Go WebSocket Path: ${tjwspath}" && echo -e "Trojan-Go WebSocket Host: ${tjwshost}"
    fi

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        echo -e "\n———————————————————— V2Ray 配置 ————————————————————" &&
            echo -e "$(docker exec V2Ray sh -c 'v2ray --version' 2>&1 | awk 'NR==1{gsub(/"/,"");print}')" &&
            echo -e "服务器端口: ${TSP_Port}" && echo -e "服务器地址: ${TSP_Domain}"
        [[ $v2ray_tcp_mode = "vmess" ]] && echo -e "\nVMess TCP UUID: ${VMTID}" &&
            echo -e "VMess AlterID: ${VMAID}" && echo -e "VMess 加密方式: Auto" && echo -e "VMess Host: ${TSP_Domain}"
        [[ $v2ray_tcp_mode = "vless" ]] && echo -e "\nVLESS TCP UUID: ${VLTID}" &&
            echo -e "VLESS 加密方式: none" && echo -e "VLESS Host: ${TSP_Domain}"
        [[ $v2ray_ws_mode = "vmess" ]] && echo -e "\nVMess WS UUID: ${VMWSID}" && echo -e "VMess AlterID: $VMWSAID" &&
            echo -e "VMess 加密方式: Auto" && echo -e "VMess WebSocket Host: ${TSP_Domain}" && echo -e "VMess WebSocket Path: ${v2wspath}"
        [[ $v2ray_ws_mode = "vless" ]] && echo -e "\nVLESS WS UUID: ${VLWSID}" &&
            echo -e "VLESS 加密方式: none" && echo -e "VLESS WebSocket Host: ${TSP_Domain}" && echo -e "VLESS WebSocket Path: ${v2wspath}"
    fi

    echo -e "————————————————————————————————————————————————————\n"
    read -t 60 -n 1 -s -rp "按任意键继续（60s）..."
    clear
}

info_links() {
    deployed_status_check
    cert_stat_check tls-shunt-proxy
    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        echo -e "———————————————— Trojan-Go 分享链接 ————————————————" &&
            [[ $trojan_tcp_mode = true ]] && echo -e "\n Trojan-Go TCP TLS 分享链接：" &&
            echo -e " Trojan 客户端：\n trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&allowinsecure=0&mux=0#${HOSTNAME}-TCP" &&
            echo -e " Qv2ray 客户端（需安装 Trojan-Go 插件）：\n trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=original&host=${TSP_Domain}#${HOSTNAME}-TCP" &&
            echo -e " Shadowrocket 二维码：" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&peer=${TSP_Domain}&allowinsecure=0&mux=0#${HOSTNAME}-TCP"
        [[ $trojan_ws_mode = true ]] && echo -e "\n Trojan-Go WebSocket TLS 分享链接：" &&
            echo -e " Trojan-Qt5 客户端：\n trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&peer=${TSP_Domain}&allowinsecure=0&mux=1&ws=1&wspath=${tjwspath}&wshost=${TSP_Domain}#${HOSTNAME}-WS" &&
            echo -e " Qv2ray 客户端（需安装 Trojan-Go 插件）：\n trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=ws&host=${TSP_Domain}&path=${tjwspath}#${HOSTNAME}-WS" &&
            echo -e " Shadowrocket 二维码：" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?peer=${TSP_Domain}&mux=1&plugin=obfs-local;obfs=websocket;obfs-host=${TSP_Domain};obfs-uri=${tjwspath}#${HOSTNAME}-WS"
    fi
    read -t 60 -n 1 -s -rp "按任意键继续（60s）..."

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        echo -e "\n—————————————————— V2Ray 分享链接 ——————————————————" &&
            [[ $v2ray_tcp_mode = "vmess" ]] && echo -e "\n VMess TCP TLS 分享链接：" &&
            echo -e " V2RayN 格式：\n vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMTID}\",\"net\":\"tcp\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-TCP\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e " VMess 新版格式：\n vmess://tcp+tls:${VMTID}-0@${TSP_Domain}:${TSP_Port}/?tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-TCP")" &&
            echo -e " Shadowrocket 二维码：" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "vmess://$(echo "auto:${VMTID}@${TSP_Domain}:${TSP_Port}" | base64 -w 0)?tls=1&mux=1&peer=${TSP_Domain}&allowInsecure=0&tfo=0&remarks=${HOSTNAME}-TCP"
        [[ $v2ray_ws_mode = "vmess" ]] && echo -e "\n VMess WebSocket TLS 分享链接：" &&
            echo -e " V2RayN 格式：\n vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMWSID}\",\"net\":\"ws\",\"path\":\"${v2wspath}\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-WS\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e " VMess 新版格式：\n vmess://ws+tls:${VMWSID}-0@${TSP_Domain}:${TSP_Port}/?path=$(urlEncode "${v2wspath}")&host=${TSP_Domain}&tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-WS")" &&
            echo -e " Shadowrocket 二维码：" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "vmess://$(echo "auto:${VMWSID}@${TSP_Domain}:${TSP_Port}" | base64 -w 0)?tls=1&mux=1&peer=${TSP_Domain}&allowInsecure=0&tfo=0&remarks=${HOSTNAME}-WS&obfs=websocket&obfsParam=${TSP_Domain}&path=${v2wspath}"
        [[ $v2ray_tcp_mode = "vless" ]] && echo -e "\n VLESS TCP TLS 分享链接：暂未发布官方规范，请遵照代理配置信息配置客户端。"
        [[ $v2ray_ws_mode = "vless" ]] && echo -e "\n VLESS WebSocket TLS 分享链接：暂未发布官方规范，请遵照代理配置信息配置客户端。"
    fi
    read -t 60 -n 1 -s -rp "按任意键继续（60s）..."

    if [[ -f ${v2ray_conf} || -f ${trojan_conf} ]]; then
        echo -e "\n——————————————————— 订阅链接信息 ———————————————————"
        rm -rf "$(grep '#Website' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/')"/subscribe*
        cat >"$(grep '#Website' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/')"/robots.txt <<-EOF
User-agent: *
Disallow: /
EOF
        subscribe_file="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        subscribe_links | base64 -w 0 >"$(grep '#Website' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/')"/subscribe"${subscribe_file}"
        echo -e "订阅链接：\n https://${TSP_Domain}/subscribe${subscribe_file} \n${Yellow}请注意：脚本生成的订阅链接包含当前服务端部署的所有协议（VLESS 除外）代理配置信息，出于信息安全考虑，链接地址会在每次查看时随机刷新！\n另外，由于不同客户端对代理协议的兼容支持程度各不相同，请根据实际情况自行调整！${Font}"
    fi

    echo -e "————————————————————————————————————————————————————\n"
    read -t 60 -n 1 -s -rp "按任意键继续（60s）..."
    clear
}

subscribe_links() {
    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        [[ $trojan_tcp_mode = true ]] &&
            echo -e "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&peer=${TSP_Domain}&allowinsecure=0&mux=0#${HOSTNAME}-TCP" &&
            echo -e "trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=original&host=${TSP_Domain}#${HOSTNAME}-Trojan-Go-TCP"
        [[ $trojan_ws_mode = true ]] &&
            echo -e "trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=ws&host=${TSP_Domain}&path=${tjwspath}#${HOSTNAME}-Trojan-Go-WS" &&
            echo -e "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?peer=${TSP_Domain}&mux=1&plugin=obfs-local;obfs=websocket;obfs-host=${TSP_Domain};obfs-uri=${tjwspath}#${HOSTNAME}-Trojan-Go-WS"
    fi

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        [[ $v2ray_tcp_mode = "vmess" ]] &&
            echo -e "vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMTID}\",\"net\":\"tcp\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-TCP\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e "vmess://tcp+tls:${VMTID}-0@${TSP_Domain}:${TSP_Port}/?tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-新版格式-TCP")"
        [[ $v2ray_ws_mode = "vmess" ]] &&
            echo -e "vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMWSID}\",\"net\":\"ws\",\"path\":\"${v2wspath}\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-WS\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e "vmess://ws+tls:${VMWSID}-0@${TSP_Domain}:${TSP_Port}/?path=$(urlEncode "${v2wspath}")&host=${TSP_Domain}&tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-新版格式-WS")"
    fi
}

cert_stat_check() {
    echo -e "${OK} ${GreenBG} 检测证书状态信息... ${Font}"
    if systemctl is-active "$1" &>/dev/null; then
        [[ $1 = "tls-shunt-proxy" ]] && [[ ! -f ${tsp_cert_dir}/${TSP_Domain}/${TSP_Domain}.crt || ! -f ${tsp_cert_dir}/${TSP_Domain}/${TSP_Domain}.json || ! -f ${tsp_cert_dir}/${TSP_Domain}/${TSP_Domain}.key ]] &&
            echo -e "${Yellow}未检测到有效的 SSL 证书，请执行以下命令：\n#systemctl restart tls-shunt-proxy\n#journalctl -u tls-shunt-proxy.service\n检查日志，待证书完成申请后，重新运行脚本${Font}" && exit 4
    fi
}

menu_req_check() {
    if systemctl is-active "$1" &>/dev/null; then
        [[ $debug = "enable" ]] && echo -e "${OK} ${GreenBG} $1 已经启动 ${Font}"
    else
        echo -e "\n${Error} ${RedBG} 检测到 $1 服务未成功启动，根据依赖关系，以下选项将被屏蔽，请修复后再试... ${Font}"
        [[ $1 = "tls-shunt-proxy" ]] && echo -e "${Yellow}[屏蔽] 安装（Trojan-Go/V2Ray）TCP/WS 代理\n[屏蔽] （Trojan-Go/V2Ray）配置修改\n[屏蔽] 查看配置信息${Font}"
        [[ $1 = "docker" ]] && echo -e "${Yellow}[屏蔽] 安装/卸载 WatchTower（自动更新容器）\n[屏蔽] 安装/卸载 Portainer（Web管理容器）${Font}"
        read -t 60 -n 1 -s -rp "按任意键继续（60s）..."
    fi
}

menu() {
    deployed_status_check
    echo -e "\n${Green}     TSP & Trojan-Go/V2Ray 部署脚本 版本: ${shell_version} ${Font}"
    echo -e "${Yellow}       Telegram 交流群：https://t.me/trojanv2${Font}\n"
    echo -e "——————————————————————部署管理——————————————————————"
    if [[ $tsp_stat = "installed" ]]; then
        echo -e "${Green}1.${Font}  ${Yellow}卸载${Font} TLS-Shunt-Proxy（网站&自动管理证书）"
    else
        echo -e "${Green}1.${Font}  安装 TLS-Shunt-Proxy（网站&自动管理证书）"
    fi
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        if [[ $trojan_stat = "none" ]]; then
            echo -e "${Green}2.${Font}  安装 Trojan-Go TCP/WS 代理"
        else
            echo -e "${Green}2.${Font}  ${Yellow}卸载${Font} Trojan-Go TCP/WS 代理"
        fi
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        if [[ $v2ray_stat = "none" ]]; then
            echo -e "${Green}3.${Font}  安装 V2Ray TCP/WS 代理"
        else
            echo -e "${Green}3.${Font}  ${Yellow}卸载${Font} V2Ray TCP/WS 代理"
        fi
    systemctl is-active "docker" &>/dev/null &&
        if [[ $watchtower_stat = "none" ]]; then
            echo -e "${Green}4.${Font}  安装 WatchTower（自动更新容器）"
        else
            echo -e "${Green}4.${Font}  ${Yellow}卸载${Font} WatchTower（自动更新容器）"
        fi
    systemctl is-active "docker" &>/dev/null &&
        if [[ $portainer_stat = "none" ]]; then
            echo -e "${Green}5.${Font}  安装 Portainer（Web管理容器）"
        else
            echo -e "${Green}5.${Font}  ${Yellow}卸载${Font} Portainer（Web管理容器）"
        fi
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        echo -e "——————————————————————配置修改——————————————————————" &&
        echo -e "${Green}6.${Font}  修改 TLS 端口/域名" &&
        [[ $trojan_stat = "installed" && -f ${trojan_conf} ]] && echo -e "${Green}7.${Font}  修改 Trojan-Go 代理配置"
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        [[ $v2ray_stat = "installed" && -f ${v2ray_conf} ]] && echo -e "${Green}8.${Font}  修改 V2Ray 代理配置"
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        echo -e "——————————————————————查看信息——————————————————————" &&
        echo -e "${Green}9.${Font}  查看 配置信息" &&
        [[ $trojan_stat = "installed" || $v2ray_stat = "installed" ]] && echo -e "${Green}10.${Font} 查看 分享/订阅 链接"
    echo -e "——————————————————————杂项管理——————————————————————"
    [ -f ${tsp_conf} ] && echo -e "${Green}11.${Font} 升级 TLS-Shunt-Proxy/Docker 基础平台" &&
        echo -e "${Green}12.${Font} ${Yellow}卸载${Font} 已安装的所有组件"
    echo -e "${Green}13.${Font} 安装 4合1 BBR 锐速脚本"
    echo -e "${Green}14.${Font} 运行 SuperSpeed 测速脚本"
    echo -e "${Green}0.${Font}  退出脚本 "
    echo -e "————————————————————————————————————————————————————\n"
    read -rp "请输入数字：" menu_num
    case "$menu_num" in
    1)
        if [[ $tsp_stat = "installed" ]]; then
            uninstall_tsp
        else
            install_tls_shunt_proxy
            tsp_sync
        fi
        ;;
    2)
        systemctl is-active "tls-shunt-proxy" &>/dev/null &&
            if [[ $trojan_stat = "none" ]]; then
                install_trojan
            else
                uninstall_trojan
            fi
        ;;
    3)
        systemctl is-active "tls-shunt-proxy" &>/dev/null &&
            if [[ $v2ray_stat = "none" ]]; then
                install_v2ray
            else
                uninstall_v2ray
            fi
        ;;
    4)
        systemctl is-active "docker" &>/dev/null &&
            if [[ $watchtower_stat = "none" ]]; then
                install_watchtower
            else
                uninstall_watchtower
            fi
        ;;
    5)
        systemctl is-active "docker" &>/dev/null &&
            if [[ $portainer_stat = "none" ]]; then
                install_portainer
            else
                uninstall_portainer
            fi
        ;;
    6)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && modify_tsp
        ;;
    7)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && [[ -f ${trojan_conf} && $trojan_stat = "installed" ]] && modify_trojan
        ;;
    8)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]] && modify_v2ray
        ;;
    9)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && info_config
        ;;
    10)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && info_links
        ;;
    11)
        [ -f ${tsp_conf} ] && read -rp "请确认是否升级 TLS-Shunt-Proxy 分流组件，(Y/N) [N]:" upgrade_mode
        [[ -z ${upgrade_mode} ]] && upgrade_mode="none"
        case $upgrade_mode in
        [yY])
            echo -e "${GreenBG} 开始升级 TLS-Shunt-Proxy 分流组件 ${Font}"
            upgrade_mode="Tsp"
            sleep 1
            upgrade_tsp
            ;;
        *)
            echo -e "${GreenBG} 跳过升级 TLS-Shunt-Proxy 分流组件 ${Font}"
            ;;
        esac
        [ -f ${tsp_conf} ] && read -rp "请确认是否升级 Docker 平台组件，(Y/N) [N]:" upgrade_mode
        [[ -z ${upgrade_mode} ]] && upgrade_mode="none"
        case $upgrade_mode in
        [yY])
            echo -e "${GreenBG} 开始升级 Docker 平台组件 ${Font}"
            upgrade_mode="Docker"
            sleep 1
            install_docker
            ;;
        *)
            echo -e "${GreenBG} 跳过升级 Docker 平台组件 ${Font}"
            ;;
        esac
        ;;
    12)
        [ -f ${tsp_conf} ] && uninstall_all
        ;;
    13)
        kernel_change="YES"
        systemctl is-active "docker" &>/dev/null && echo -e "${RedBG} !!!由于 Docker 与系统内核关联紧密，更换系统内核可能导致 Docker 无法正常使用!!! ${Font}\n${WARN} ${Yellow} 如果内核更换后 Docker 无法正常启动，请尝试通过 脚本 <选项10:升级 Docker> 修复 或 <选项11:完全卸载> 后重新部署 ${Font}" &&
            read -rp "请在确认后，输入 YES（区分大小写）:" kernel_change
        [[ -z ${kernel_change} ]] && kernel_change="no"
        case $kernel_change in
        YES)
            [ -f "tcp.sh" ] && rm -rf ./tcp.sh
            wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh" && chmod +x tcpx.sh && ./tcpx.sh
            ;;
        *)
            echo -e "${RedBG} 我再想想 ${Font}"
            exit 0
            ;;
        esac
        ;;
    14)
        bash <(curl -Lso- https://git.io/superspeed)
        ;;
    0)
        exit 0
        ;;
    *)
        echo -e "${RedBG} 请输入正确的数字 ${Font}"
        sleep 3
        ;;
    esac
    menu
}

clear
is_root
update_sh
list "$1"
