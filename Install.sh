#!/bin/bash

# 定义颜色变量
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 安装依赖
function check_dependencies() {
    local packages=("wget" "socat" "jq" "openssl")
    
    if [[ -n $(command -v apt-get) ]]; then
        packages+=("uuid-runtime")
    elif [[ -n $(command -v yum) ]]; then
        packages+=("util-linux")
    else
        echo -e "${RED}无法确定系统包管理器，请手动安装依赖。${NC}"
        exit 1
    fi

    for package in "${packages[@]}"; do
        if ! command -v "$package" &> /dev/null; then
            echo "安装依赖: $package"
            if [[ -n $(command -v apt-get) ]]; then
                apt-get -y install "$package"
            elif [[ -n $(command -v yum) ]]; then
                yum -y install "$package"
            fi
        fi
    done
}

# 开启 BBR
function enable_bbr() {
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "开启 BBR..."
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}BBR 已开启${NC}"
    else
        echo -e "${YELLOW}BBR 已经开启，跳过配置。${NC}"
    fi
}

# 创建文件目录
function create_tuic_directory() {
    local tuic_directory="/usr/local/etc/tuic"
    local ssl_directory="/etc/ssl/private"
    
    if [[ ! -d "$tuic_directory" ]]; then
        mkdir -p "$tuic_directory"
    fi
    
    if [[ ! -d "$ssl_directory" ]]; then
        mkdir -p "$ssl_directory"
    fi
}

# 下载和安装tuic程序
function install_tuic() {
    local url=""
    
    if [[ $(arch) == "x86_64" ]]; then
        url="https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-x86_64-unknown-linux-gnu"
    elif [[ $(arch) == "aarch64" ]]; then
        url="https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-aarch64-unknown-linux-gnu"
    else
        echo -e "${RED}不支持的架构: $(arch)${NC}"
        exit 1
    fi
    
    echo "下载和安装tuic程序..."
    wget -qO /usr/bin/tuic "$url"
    chmod +x /usr/bin/tuic
}

# 配置tuic开机自启服务
function configure_tuic_service() {
    local service_file="/etc/systemd/system/tuic.service"
    local config_file="/usr/local/etc/tuic/config.json"
    
    echo "配置tuic开机自启服务..."
    echo "[Unit]
Description=tuic service
Documentation=https://github.com/EAimTY/tuic
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/usr/local/etc/tuic/
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/bin/tuic -c '$config_file'
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target" > "$service_file"
}

# 设置监听端口
function set_listen_port() {
    local default_port="443"

    while true; do
        read -p "请输入监听端口 (默认$default_port): " listen_port
        listen_port=${listen_port:-$default_port}

        if [[ $listen_port =~ ^[1-9][0-9]{0,4}$ && $listen_port -le 65535 ]]; then
            echo -e "${GREEN}监听端口设置成功：$listen_port${NC}"
            break
        else
            echo -e "${RED}错误：监听端口范围必须在1-65535之间，请重新输入。${NC}"
        fi
    done
}

# 自动生成UUID
function generate_uuid() {
    if [[ -n $(command -v uuidgen) ]]; then
        uuid=$(uuidgen)
    elif [[ -n $(command -v uuid) ]]; then
        uuid=$(uuid -v 4)
    else
        echo -e "${RED}错误：无法生成UUID，请手动设置。${NC}"
        exit 1
    fi
    echo -e "${GREEN}生成的UUID为：$uuid${NC}"
}

# 设置密码
function set_password() {
    read -p "请输入密码（默认随机生成）: " password

    # 如果密码为空，则随机生成一个密码
    if [[ -z "$password" ]]; then
        password=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 12 | head -n 1)
        echo -e "${GREEN}生成的密码为：$password${NC}"
    fi
}

# 添加多用户
function add_multiple_users() {
    while true; do
        read -p "是否继续添加用户？(Y/N): " add_multiple_users

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            # 自动生成UUID
            generate_uuid

            # 设置密码
            set_password

            # 将UUID和密码添加到用户列表中
            users+=",\n\"$uuid\": \"$password\""
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
        fi
    done
}

# 设置证书和私钥路径
function set_certificate_and_private_key() {
    while true; do
        read -p "请输入证书路径 (默认/etc/ssl/private/cert.crt): " certificate_path
        certificate_path=${certificate_path:-"/etc/ssl/private/cert.crt"}

        if [[ "$certificate_path" != "/etc/ssl/private/cert.crt" && ! -f "$certificate_path" ]]; then
            echo -e "${RED}错误：证书文件不存在，请重新输入。${NC}"
        else
            break
        fi
    done

    while true; do
        read -p "请输入私钥路径 (默认/etc/ssl/private/private.key): " private_key_path
        private_key_path=${private_key_path:-"/etc/ssl/private/private.key"}

        if [[ "$private_key_path" != "/etc/ssl/private/private.key" && ! -f "$private_key_path" ]]; then
            echo -e "${RED}错误：私钥文件不存在，请重新输入。${NC}"
        else
            break
        fi
    done
}

# 设置拥塞控制算法
function set_congestion_control() {
    local default_congestion_control="bbr"

    while true; do
        read -p "请选择拥塞控制算法 (默认$default_congestion_control):
 [1]. bbr
 [2]. cubic
 [3]. new_reno
请输入对应的数字: " congestion_control

        case $congestion_control in
            1)
                congestion_control="bbr"
                break
                ;;
            2)
                congestion_control="cubic"
                break
                ;;
            3)
                congestion_control="new_reno"
                break
                ;;
            "")
                congestion_control=$default_congestion_control
                break
                ;;
            *)
                echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
                ;;
        esac
    done
}

# 生成tuic的JSON配置文件
function generate_tuic_config() {
    local config_file="/usr/local/etc/tuic/config.json"
    local users=""
    local certificate=""
    local private_key=""
    
    echo "生成tuic的JSON配置文件..."

    # 设置监听端口
    set_listen_port

    # 自动生成UUID
    generate_uuid

    # 设置密码
    set_password

    # 将UUID和密码添加到用户列表中
    users="\"$uuid\": \"$password\""

    # 添加多用户
    add_multiple_users

    # 格式化用户列表
    users=$(echo -e "$users" | sed -e 's/^/        /')

    # 配置证书和私钥路径
    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"

    # 设置拥塞控制算法
    set_congestion_control

    # 生成tuic配置文件
    echo "{
    \"server\": \"[::]:$listen_port\",
    \"users\": {
$users
    },
    \"certificate\": \"$certificate_path\",
    \"private_key\": \"$private_key_path\",
    \"congestion_control\": \"$congestion_control\",
    \"alpn\": [\"h3\", \"spdy/3.1\"],
    \"udp_relay_ipv6\": true,
    \"zero_rtt_handshake\": false,
    \"dual_stack\": true,
    \"auth_timeout\": \"3s\",
    \"task_negotiation_timeout\": \"3s\",
    \"max_idle_time\": \"10s\",
    \"max_external_packet_size\": 1500,
    \"send_window\": 16777216,
    \"receive_window\": 8388608,
    \"gc_interval\": \"3s\",
    \"gc_lifetime\": \"15s\",
    \"log_level\": \"warn\"
}" > "$config_file"
}

# 询问证书来源选择
function ask_certificate_option() {
    while true; do
        read -p "请选择证书来源：
 [1]. 自动申请证书
 [2]. 自备证书
请输入对应的数字: " certificate_option

        case $certificate_option in
            1)
                echo "已选择自动申请证书。"
                apply_certificate
                break
                ;;
            2)
                echo "已选择自备证书。"
                break
                ;;

            *)
                echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
                ;;
        esac
    done
}

# 申请证书
function apply_certificate() {
    local domain

    # 验证域名
    while true; do
        read -p "请输入您的域名: " domain

        # 检查域名是否绑定本机IP
        if ping -c 1 "$domain" &>/dev/null; then
            break
        else
            echo -e "${RED}错误：域名未解析或输入错误，请重新输入。${NC}"
        fi
    done
    
    # 安装 acme
    echo "安装 acme..."
    curl https://get.acme.sh | sh 
    alias acme.sh=~/.acme.sh/acme.sh
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt 

    # 申请证书
    echo "申请证书..."
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --webroot /home/wwwroot/html 

    # 安装证书
    echo "安装证书..."
    certificate_path=$(~/.acme.sh/acme.sh --install-cert -d "$domain" --ecc --key-file "$private_key_path" --fullchain-file "$certificate_path")

    set_certificate_path="$certificate_path"
    set_private_key_path="$private_key_path"
}

# 检查防火墙配置
function check_firewall_configuration() {
    local os_name=$(uname -s)
    local firewall

    if [[ $os_name == "Linux" ]]; then
        if command -v ufw >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1; then
            firewall="ufw"
        elif command -v iptables >/dev/null 2>&1 && command -v firewalld >/dev/null 2>&1; then
            firewall="iptables-firewalld"
        fi
    fi

    if [[ -z $firewall ]]; then
        echo -e "${RED}无法检测到适用的防火墙配置工具，请手动配置防火墙。${NC}"
        return
    fi

    echo "检查防火墙配置..."

    case $firewall in
        ufw)
            if ! ufw status | grep -q "Status: active"; then
                ufw enable
            fi

            if ! ufw status | grep -q " $listen_port"; then
                ufw allow "$listen_port"
            fi

            if ! ufw status | grep -q " 80"; then
                ufw allow 80
            fi

            echo "防火墙配置已更新。"
            ;;
        iptables-firewalld)
            if command -v iptables >/dev/null 2>&1; then
                if ! iptables -C INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
                    iptables -A INPUT -p tcp --dport "$listen_port" -j ACCEPT
                fi

                if ! iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1; then
                    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
                fi

                iptables-save > /etc/sysconfig/iptables

                echo "iptables防火墙配置已更新。"
            fi

            if command -v firewalld >/dev/null 2>&1; then
                if ! firewall-cmd --state | grep -q "running"; then
                    systemctl start firewalld
                    systemctl enable firewalld
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/tcp"; then
                    firewall-cmd --zone=public --add-port="$listen_port/tcp" --permanent
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/udp"; then
                    firewall-cmd --zone=public --add-port="$listen_port/udp" --permanent
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "80/tcp"; then
                    firewall-cmd --zone=public --add-port=80/tcp --permanent
                fi

                firewall-cmd --reload

                echo "firewalld防火墙配置已更新。"
            fi
            ;;
    esac
}

# 显示 tuic 配置信息
function display_tuic_config() {
    local config_file="/usr/local/etc/tuic/config.json"
echo -e "${CYAN}TUIC节点配置信息：${NC}"    
echo -e "${CYAN}==================================================================${NC}" 
    echo "监听端口: $(jq -r '.server' "$config_file" | sed 's/\[::\]://')"
echo -e "${CYAN}------------------------------------------------------------------${NC}" 
    echo "UUID和密码列表:"
    jq -r '.users | to_entries[] | "UUID:\(.key)\t密码:\(.value)"' "$config_file"
echo -e "${CYAN}------------------------------------------------------------------${NC}" 
    echo "拥塞控制算法: $(jq -r '.congestion_control' "$config_file")"
echo -e "${CYAN}------------------------------------------------------------------${NC}" 
    echo "ALPN协议:$(jq -r '.alpn[] | select(. != "")' "$config_file" | sed ':a;N;$!ba;s/\n/, /g')"
echo -e "${CYAN}==================================================================${NC}"    
}

# 安装 TUIC
function install_tuic_Serve() {
    echo "安装 TUIC 服务..."

    #检查并安装依赖
    check_dependencies
    
    # 开启 BBR
    enable_bbr
    
    # 创建tuic配置文件目录
    create_tuic_directory    
    
    # 下载和安装tuic程序
    install_tuic

    # 生成tuic的JSON配置文件
    generate_tuic_config
    
    # 检查防火墙配置
    check_firewall_configuration
   
    # 配置证书
    ask_certificate_option

    # 配置tuic开机自启服务
    configure_tuic_service
     
    # 启动tuic
    start_tuic
       
    echo "TUIC 服务安装完成..." 
      
    # 显示配置信息
    display_tuic_config
}

# 启动 TUIC
function start_tuic() {
    systemctl daemon-reload
    systemctl enable tuic.service
    systemctl start tuic.service
    systemctl status tuic.service
}

# 重启 TUIC
function restart_tuic() {
    echo "重启 TUIC 服务..."
    systemctl restart tuic.service
    echo -e "${GREEN}TUIC 已重启...${NC}"
}

# 停止 TUIC
function stop_tuic() {
    echo "停止 TUIC 服务..."
    systemctl stop tuic.service
    echo -e "${GREEN}TUIC 服务 已停止...${NC}"
}

# 卸载 TUIC
function uninstall_tuic() {
    echo "卸载 TUIC 服务..."
    systemctl stop tuic.service
    systemctl disable tuic.service
    rm /etc/systemd/system/tuic.service
    rm /usr/local/etc/tuic/config.json
    rm /usr/bin/tuic
    echo -e "${GREEN}TUIC 服务已卸载...${NC}"
}

# 主函数
function main_menu() {
  echo -e "${CYAN}               ------------------------------------------------------------------------------------ ${NC}"
  echo -e "${CYAN}               |                          欢迎使用 TUIC 安装程序                                  |${NC}"
  echo -e "${CYAN}               |                      项目地址:https://github.com/TinrLin                         |${NC}"
  echo -e "${CYAN}               ------------------------------------------------------------------------------------${NC}"        
  echo -e "请选择要执行的操作:"
  echo -e "  ${CYAN}[1]. 安装 TUIC 服务${NC}"
  echo -e "  ${CYAN}[2]. 重启 TUIC 服务${NC}"
  echo -e "  ${CYAN}[3]. 停止 TUIC 服务${NC}"
  echo -e "  ${CYAN}[4]. 卸载 TUIC 服务${NC}"
  echo -e "  ${CYAN}[0]. 退出${NC}"

  read -p "请输入: " choice

  case $choice in
    1)
      install_tuic_Serve
      ;;
    2)
      restart_tuic
      ;;
    3)
      stop_tuic
      ;;
    4)
      uninstall_tuic
      ;;
    0)
      exit 0
      ;;
    *)
      echo -e "${RED}错误: 无效的选项，请重新输入...${NC}"
      main_menu
      ;;
  esac
}

main_menu
