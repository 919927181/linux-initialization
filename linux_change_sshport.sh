#!/bin/bash

# 用途：更改 linux 系统的ssh登陆端口
# 使用
# mkdir /tmp/shell
# sh /tmp/shell/change_sshport.sh


echo -e "\033[36m更改ssh默认端口，提高安全性!\033[0m"

SSH_PORT=40107

## 公共方法-全局Log信息打印函数
## 参数: $@
log_err() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[31mERROR: $@ \033[0m\n"
}
log_info() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[32mINFO: $@ \033[0m\n"
}
log_warning() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[33mWARNING: $@ \033[0m\n"
}


# 验证否为数字
function isValidNum() {

  local num=$1
  local ret=1

  if [ "$num" -gt 0 ] 2>/dev/null ;then 
    echo "$num is number." 
    ret=0
  else 
    echo "$num not a number!" 
    ret=1
  fi

  return $ret
}

# 输入ssh port 
function Input_SshPort() {
  while true; do   
	read -p "建议使用端口从40101开始，请输入 ssh 端口号：" SSH_PORT
    isValidNum ${SSH_PORT}  
    [ $? -eq 0 ] && break   
  done
  
}

## 名称: Os_Change_SShPort
## 用途: 更改ssh端口号，不输入参数则使用defaultport
## 参数: $1(端口号) 或 无
function Change_SShPort() {

  log_info "[-] 更改ssh默认端口，提高安全性..."
  
  # 判断是否输入了参数
  if [ -n "$1" ];then
    # echo "第一个参数$1"
    SSHPORT=${1}
  fi
  
  # 1. ssh配置文件去除原来的ssh登陆端口
  arr_port=$(cat /etc/ssh/sshd_config | grep ^Port.* | awk '{print $2}' )  
  for port in ${arr_port[@]} 
  do
      log_info "[-] 正在去除ssh端口：$port"
      firewall-cmd --zone=public --remove-port=${port}/tcp --permanent
	  sleep 2
      
  done  
  #这里注销掉所有以Port开头的。/d是删除所有以prot开头的行
  sed -i 's/^Port/#Port/g' /etc/ssh/sshd_config   
  #sed -i '/^Port/d' /etc/ssh/sshd_config
  
  # 2. ssh配置文件加入新端口
  sed -i "/#Port 22/a\Port ${SSH_PORT}" /etc/ssh/sshd_config
  
  # 3. 添加sshd服务20211端口到SELinux，已禁用了SELinux，就不用添加了
  #semanage port -m -t ssh_port_t -p tcp 20211
  
  # 4. 防火墙端口
  firewall-cmd --permanent --add-port=${SSH_PORT}/tcp
  firewall-cmd --zone=public --remove-port=22/tcp --permanent
  firewall-cmd --reload

  systemctl restart sshd

  log_info "[-] 设置完毕，请使用ssh端口 ${SSH_PORT} 登陆 "
  
}


function run() {

  read -r -p "Do you agree to change the SSH port to 40107? If not, please enter new port? [Y/n] " input
  case $input in
      [yY][eE][sS]|[yY])
          echo -e "\033[32mYes, continue...\033[0m"
          Change_SShPort
          ;; 
      [nN][oO]|[nN])
          Input_SshPort
		  Change_SShPort ${SSH_PORT}
          ;; 
      *)
          echo -e "\033[31merror! you input isn't yes or no.\n\033[0m"
          exit 1
          ;;
  esac

}

run
