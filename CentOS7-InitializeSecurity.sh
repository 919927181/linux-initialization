#!/bin/bash
#
# @Author: liyanjing，@E-mail: 284223249@qq.com, @wechat: Sd-LiYanJing
# @CreateTime:  2022-10-18 10:30 , @Last ModifiedTime: 2022-12-03 13:50
# @Github: https://github.com/919927181/linux-initialization.git
# @Version: 3.6
# @用途：适用于企业内部 CentOS7 系列服务器初始化、系统安全加固
# @参考：https://github.com/WeiyiGeek/SecOpsDev/tree/master/OS-%E6%93%8D%E4%BD%9C%E7%B3%BB%E7%BB%9F/Linux
# @问题：若设置了用户登陆超时，需要执行 source /etc/profile时，报错 -bash: TMOUT: readonly variable，解决 vi /etc/profile将#export TMOUT #readonly TMOUT 注释掉。 
## ----------------------------------------- ##
# @包含：
#
# [0]  创建SWAP交换分区(默认2G) 
# [1]  设置网卡静态IP和DNS(按引导输入ip\子网掩码\默认网关)
#      + <11> 全局配置DNS
#      + <12> 判断能不能上网
# [2]  在线设置国内yum源，在线yum安装常用软件（htop\ncdu比du性能强\...）
# [3]  系统优化、安全加固等一键设置：
#      + <31> 系统的最大文件打开数限制，系统内核参数优化(含关闭ipv6)
#      + <32> 时区设置为东8区
#      + <33> 禁用ctrl+alt+del重启系统、定义回收站目录等
#      + <  > 系统安全加固(等保三级-操作系统检查项)如下：
#              ++ <35> 用户口令策略(密码过期90天、到期前15天提示、密码长度至少15等)
#              ++ <36> GRUB 安全设置
#              ++ <37> ssh安全加固设置
#              ++ <38> 设置或恢复重要目录和文件的权限
#              ++ <39> 开启防火墙、禁用SELINUX等更多设置，然后重启主机
# [4]  更改ssh端口号(等保要求不使用22端口，缺省时改为40107)
# [5]  创建一个拥有管理权限的普通用户(uudocker)，执行sodu命令时需要输入密码
# [6]  禁止或允许root用户远程登陆(等保要求禁止root远程登陆,正解:普通用户登陆后su root）
# [7]  强制用户在下次登录时更改密码
# [8]  使用Chrony配置主机时间同步(根据环境需要，可选项)
# [9]  禁用与设置系统中的某些服务(根据环境需要，可选项)
# [10] 清空回收站内容 and 询问你删除回收站功能吗？（执行rm误删时，它可拯救你）
#
# 以下脚本，仅供参考：
#       Os_Kernel_Upgrade 推荐"离线升级系统内核"
#       disk_Lvsmanager 磁盘LVS逻辑卷添加与配置\033[32m
## --------------------------------------------- ##
#

## 全局变量定义
SSH_PORT=40107

# 创建拥有管理权限的普通用户名
user_name="uudocker"
# 用户密码，注意特殊字符问题，单引号中的任何字符都只当作是普通字符
user_passwd='zRM8B%Ka!5Fh%Out'
group_name="docker"

# [SNMP配置]
SNMP_user=liyanjing
SNMP_group=group_snmp
SNMP_view=view_snmp
# 密码 dont use public
SNMP_password='110.c0m'
SNMP_ip=127.0.0.1

# [备份目录]
BACKUPDIR=/data/back/system
if [ ! -d ${BACKUPDIR} ];then  mkdir -vp ${BACKUPDIR}; fi
# [记录目录]
HISDIR=/var/log/.history
if [ ! -d ${HISDIR} ];then  mkdir -vp ${HISDIR}; fi

EXEC_TIME=$(date +%Y%m%d-%m%S)

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
  sleep 5
}

## 公共方法-验证否为数字
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

## 公共方法-校验IP地址合法性
function isValidIp() {
	local ip=$1
	local ret=1
 
	if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.[0-9]{1,3}$ ]]; then
		ip=(${ip//\./ }) # 按.分割，转成数组，方便下面的判断
		[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
		ret=$?
	else   
        echo "IP format error!"   
        ret=1
	fi
	return $ret
}

## 公共方法-检查能否上网
function internetCheck()
{
    #超时时间
    local timeout=1

    #目标网站
    local target=www.baidu.com

    #获取响应状态码
    local ret_code=`curl -I -s --connect-timeout ${timeout} ${target} -w %{http_code} | tail -n1`

    if [ "x$ret_code" = "x200" ]; then
        #网络畅通
        return 1
    else
        #网络不畅通
        return 0
    fi

    return 0
}

## 公共方法-设置DNS
function setDNS()
{
  log_info "[-] DNS域名解析服务设置..."
  # DNS服务器地址
  DNSIP=("114.114.114.114" "223.5.5.5" "8.8.8.8" "8.8.4.4" )
  cp -a /etc/resolv.conf  ${BACKUPDIR}/resolv.conf.bak
  for dns in  ${DNSIP[@]};do 
    egrep -q "^nameserver .*${dns}$" /etc/resolv.conf && sed -ri "s/^nameserver.*${dns}$/nameserver ${dns}/" /etc/resolv.conf || echo "nameserver ${dns}" >> /etc/resolv.conf
  done

  log_info "[*] restarting Network........."
  service network restart && ip addr
  
  log_warning "\nDNS域名解析服务设置完毕，请ping下百度试试吧..."; 
}

## 名称: Os_Swap
## 用途: Liunx 系统创建SWAP交换分区(默认2G) ，无论物理内存多大，都统一设置成2G即可 - 请按需调用执行
## 参数: $1(几G)
Os_Swap() {

  # 创建虚拟分区文件
  if [ -e $1 ];then
    sudo dd if=/dev/zero of=/var/swap bs=1024 count=2048000     # 2G Swap 分区 1024 * 1024 , centos 以 1000 为标准
  else
    number=$(echo "${1}*1024*1024"|bc)
    sudo dd if=/dev/zero of=/swapfile bs=1024 count=${number}
  fi
  
  # 启用swap
  sudo mkswap /var/swap && mkswap -f /var/swap && sudo swapon /var/swap
  
  # 设置swap文件永久有效
  if [ $(grep -c "/var/swap" /etc/fstab) -eq 0 ];then
    sudo tee -a /etc/fstab <<'EOF'
/var/swap swap swap default 0 0
EOF
  fi

  sudo swapon --show && sudo free -h
}


## 名称: Os_YumSource_Aliyun
## 用途: 设置yum阿里源。设置yum源的三种方式：本地源、阿里云在线yum源和远程访问yum源
## 参数: 无
Os_YumSource_Aliyun() {

  log_info "[*] CentOS 软件仓库镜像源配置&&初始化更新... "
  
  internetCheck
  if [ $? -eq 0 ];then  echo -e "\033[31m主机无法上网，请检查网络设置！\n\033[0m" && exit 2; fi

  mkdir -p /etc/yum.repos.d/back
  cp -a /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/back/CentOS-Base.repo

  curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
  curl -o /etc/yum.repos.d/CentOS-epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
  sed -i "s#mirrors.cloud.aliyuncs.com#mirrors.aliyun.com#g" /etc/yum.repos.d/CentOS-Base.repo
  sed -i "s#mirrors.aliyuncs.com#mirrors.aliyun.com#g" /etc/yum.repos.d/CentOS-Base.repo

# 代理方式设置
# curl -x 192.168.12.215:3128 -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
# tee -a /etc/yum.conf <<'EOF'
# proxy=http://192.168.12.215:3128/
# EOF

  rpm --import http://mirrors.aliyun.com/centos/RPM-GPG-KEY-CentOS-7
  # 清除并建立新缓存,然后更新
  yum clean all && yum makecache
  yum --exclude=kernel* update -y && yum upgrade -y &&  yum -y install epel*

}


## 名称: Os_Yum_Install_Software
## 用途: 安装常用的软件\工具
## 参数: 无
Os_Yum_Install_Software() {

  # 编译软件
  yum install -y gcc gcc-c++ g++ make jq libpam-cracklib openssl-devel bzip2-devel
  # 常规软件
  yum install -y nano vim git unzip wget ntpdate dos2unix net-tools policycoreutils-python
  yum install -y tree htop ncdu nload sysstat psmisc bash-completion fail2ban nfs-utils chrony lsof
  # 清空缓存和已下载安装的软件包
  yum clean all

  log_info "[*] Software configure modifiy successful!Please Happy use........."
}


## 名称: Os_Optimizationn 
## 用途: 操作系统优化设置(内核参数)
## 参数: 无
Os_Optimizationn() {

  log_info "[-] 正在进行操作系统内核参数优化设置......."

  # (1) Linux 系统的最大进程数和最大文件打开数限制
  # 修改用户级的限制，先删除掉以前设置的，然后再在# End 上面增加以下内容
  sed -i '/^*/d' /etc/security/limits.conf
  sed -i "/# End/i *  soft  nofile  102400" /etc/security/limits.conf
  sed -i "/# End/i *  hard  nofile  102400" /etc/security/limits.conf
  sed -i "/# End/i *  soft  nproc   102400" /etc/security/limits.conf
  sed -i "/# End/i *  hard  nproc   102400" /etc/security/limits.conf
  
  # (2) 系统内核参数的配置
  log_info "[-] 系统内核参数的配置 "
  # sysctl -p报错 sysctl: nf_conntrack_xxxx: No such file or directory
  conntrack_str=$(lsmod | grep conntrack)
  if [[ "$conntrack_str" = "" ]]; then
    modprobe ip_conntrack
  fi

  cat > /etc/sysctl.d/99-sysctl.conf << EOF
# sysctl settings are defined through files in
# /usr/lib/sysctl.d/, /run/sysctl.d/, and /etc/sysctl.d/.
#
# Vendors settings live in /usr/lib/sysctl.d/.
# To override a whole file, create a new file with the same in
# /etc/sysctl.d/ and put new settings there. To override
# only specific settings, add a file with a lexically later
# name in /etc/sysctl.d/ and put new settings there.
#
# For more information, see sysctl.conf(5) and sysctl.d(5).

#inotify的watch数量，默认值8192
fs.inotify.max_user_watches=8192000
#aio最大值，默认值65536
fs.aio-max-nr=1048576
#系统级别的打开文件描述符的最大值，默认值98529，是指所有进程的最大文件打开数
fs.file-max = 1048575
#单用户进程最大文件打开数
fs.nr_open = 1048575

#关sysrq功能
kernel.sysrq = 0
#core文件名添加pid作为扩展名
kernel.core_uses_pid = 1
#修改消息队列长度
kernel.msgmnb = 65536
kernel.msgmax = 65536
#设置最大内存共享段大小bytes
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
#centos7上默认值是30，在Centos6上是60,当内存使用100-10=90%，就开始出现有交换分区的使用
vm.swappiness=10

net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1

#内核分配给TCP连接的内存，单位是Page，1 Page = 4096 Bytes，4KB，可用命令# getconf PAGESIZE 查看
#8T内存机器，建议用以下参数：
#net.ipv4.tcp_mem = 94500000 915000000 927000000
#第一个数字表示，当 tcp 使用的 page 少于 94500000 时，kernel 不对其进行任何的干预，建议=系统内存*50%*50%
#第二个数字表示，当 tcp 使用了超过 915000000 的 pages 时，kernel 会进入 “memory pressure” 压力模式，建议=系统内存*50%*70%
#第三个数字表示，当 tcp 使用的 pages 超过 927000000 时（相当于3536GB内存），就会报：Out of socket memory,建议=系统内存的50%
#8GB内存机器，TCP连接最多约使用4GB内存），524288*4096/1024/1024/104=2GB,2.7GB,4GB，建议用以下参数：
#net.ipv4.tcp_mem = 524288     699050  1048576
#256GB内存机器，TCP连接最多约使用128GB内存，建议用以下参数：
net.ipv4.tcp_mem = 16777216     22369600  33554432 

#为每个TCP连接分配的读、写缓冲区内存大小，单位是Byte
#4GB，TCP内存能容纳的连接数，约为  4096MB/16KB = 256K = 26万
#48GB，TCP内存能容纳的连接数约为300万
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.somaxconn = 262144

#每个网络接口接收数据包速率比内核处理这些包的速率快时,允许送到队列数据包的最大数目,网络设备的收发包的队列大小
net.core.netdev_max_backlog = 262144
#最大孤儿套接字(orphan sockets)数，单位是个，每个孤儿socket占用64KB空间
#注意：当cat /proc/net/sockstat看到的orphans数量达到net.ipv4.tcp_max_orphans的约一半时，就会报：Out of socket memory
#每个孤儿socket可占用多达64KB内存，此时占用内存 3276800/2*64KB/1024=102400MB=100GB
net.ipv4.tcp_max_orphans = 3276800
#未收到客户端确认信息的连接请求最大值
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_timestamps = 0

#内核放弃建立连接之前发送SYNACK包数量
net.ipv4.tcp_synack_retries = 1
#内核放弃建立连接之前发送SYN包数量
net.ipv4.tcp_syn_retries = 1

#开SYN洪水攻击保护,防范DDOS攻击，防止SYN队列被占满
net.ipv4.tcp_syncookies = 1
  
net.ipv4.tcp_fin_timeout = 1
##keepalive启用时，TCP发送keepalive消息的频度缺省是2小时
##nginx做反向代理，为了快速释放链接，超时时间配置短一些，这样可以处理更高的并发。但是如果供tomcat、数据库等服务的话，就要配置长一些，来达到稳定的效果
##tcp空闲连接保持1200秒（20分钟），然后经过 3次探测 * 30秒后被丢弃
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl= 30
net.ipv4.tcp_keepalive_probes= 3

#允许系统打开端口范围，默认是32768 61000，则只能发起2w多连接，改成以下，一个IP可发起差不多6.4w连接。
net.ipv4.ip_local_port_range = 1024 65000
#修改防火墙的表大小默认65536
net.netfilter.nf_conntrack_max = 655350
net.netfilter.nf_conntrack_tcp_timeout_established = 1200

#避免放大攻击
net.ipv4.icmp_echo_ignore_broadcasts = 1
#开启恶意的icmp错误消息保护
net.ipv4.icmp_ignore_bogus_error_responses = 1

#开启路由转发
net.ipv4.ip_forward = 1
#关闭反向路径过滤
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

#处理无源路由的包
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

#关闭ipv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

EOF

  # 使其永久生效
  sysctl -p /etc/sysctl.d/99-sysctl.conf

  # (3) 禁用ipv6
  log_info "[-] 禁用ipv6... "
  sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="ipv6.disable=1 /g' /etc/default/grub 
  # 重新生成grub.cfg文件
  grub2-mkconfig -o /boot/grub2/grub.cfg
  sed -i 's/::/#::/g' /etc/hosts

}


## 名称: Os_TimedataZone
## 用途: 操作系统系统时间时区配置相关脚本
## 参数: 无
Os_TimedataZone() {

  log_info "[*] 系统时间时区配置相关脚本,开始执行..."
  
  # (1) 时区设置东8区，date -R查看系统时间 
  log_info "[*] 时区设置前的时间: $(date -R) "
  timedatectl set-timezone Asia/Shanghai
  echo 'Asia/Shanghai' >/etc/timezone
  timedatectl set-local-rtc 1

}

## 名称: Os_HostTimeSync_Chrony
## 用途: 主机间的时间同步，时间不一致会导致很多重要应用的故障。chrony既可作时间服务器服务端，也可作客户端。
## 参数: 无
Os_HostTimeSync_Chrony() {

  log_info "[*] 主机的时间同步，使用chrony,开始执行....."
  
  time_server_ip_1=192.168.0.254
  time_server_ip_2=192.168.10.254
  read -r -p " The time server IP is 192.168.0.254? If not, please enter? [Y/n] " input_yn
  case $input_yn in
      [yY][eE][sS]|[yY])
          echo -e "\033[32mYes, continue...\033[0m"
          ;; 
      [nN][oO]|[nN])
           while true; do   
	          read -p "请输入时间服务器-1的Ip：" time_server_ip_1
              isValidIp ${time_server_ip_1}  
             [ $? -eq 0 ] && break   
           done
		
		   while true; do   
	          read -p "请输入时间服务器-2的Ip：" time_server_ip_2
              isValidIp ${time_server_ip_2}  
             [ $? -eq 0 ] && break   
           done
          ;; 
      *)
          echo -e "\033[31merror! you input isn't yes or no.\n\033[0m"
          exit 1
          ;;
  esac
  
  
  # (1) 时间同步软件安装
  systemctl status chronyd || yum -y install chrony
  grep -q "${time_server_ip_1}" /etc/chrony.conf || sudo tee -a /etc/chrony.conf <<'EOF'
pool ${time_server_ip_1} iburst maxsources 1
pool ${time_server_ip_2} iburst maxsources 1
pool ntp.aliyun.com iburst maxsources 4
keyfile /etc/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1.0 3
#stratumweight 0.05
#noclientlog
#logchange 0.5
EOF

  systemctl enable chronyd && systemctl restart chronyd && systemctl status chronyd -l

  # 将当前的 UTC 时间写入硬件时钟 (硬件时间默认为UTC),运行命令timedatectl set-local-rtc 0，关闭硬件时钟校时
  sudo timedatectl set-local-rtc 0

  # 启用NTP时间同步：
  timedatectl set-ntp yes
  # 时间服务器连接查看
  chronyc tracking
  
  # 手动校准-强制更新时间
  # chronyc -a makestep

  # 硬件时钟(系统时钟同步硬件时钟 )
  hwclock --systohc 
  # 备用方案: 采用 ntpdate 进行时间同步 ntpdate 192.168.10.254

  # (2) 重启依赖于系统时间的服务
  sudo systemctl restart rsyslog.service crond.service

  log_info "[*] Tie confmigure modifiy successful! restarting chronyd rsyslog.service crond.service........."
  timedatectl

}


## 名称: Os_Security_UserPwd
## 用途: 操作系统安全加固配置脚本(符合等保要求-三级要求)-1-用户密码策略
## 参数: 无
Os_Security_UserPwd () {

  log_info "[-] 操作系统安全加固配置(符合等保要求-三级要求)-1..."

  # (0) 系统用户及其终端核查配置
  log_info "[-] 锁定或者删除多余的系统账户以及创建低权限用户"
  # cat /etc/passwd | cut -d ":" -f 1 | tr '\n' ' '
  defaultuser=(root bin daemon adm lp sync shutdown halt mail operator games ftp nobody systemd-network dbus polkitd sshd postfix chrony ntp rpc rpcuser nfsnobody)
  for i in $(cat /etc/passwd | cut -d ":" -f 1,7);do
    flag=0; name=${i%%:*}; terminal=${i##*:}
    if [[ "${terminal}" == "/bin/bash" || "${terminal}" == "/bin/sh" ]];then
      log_warning "用户${i} ，shell终端为 /bin/bash 或者 /bin/sh"
    fi
    for j in ${defaultuser[@]};do
      if [[ "${name}" == "${j}" ]];then
        flag=1
        break;
      fi
    done
    if [[ $flag -eq 0 ]];then
      log_warning "${i} 非默认用户"
    fi
  done

  #用户的密码文件：/etc/shadow
  cp -a /etc/shadow /${BACKUPDIR}/shadow-${EXEC_TIME}.bak
  # -l锁定用户的密码使其不能被更改，-u 解锁
  passwd -l adm&>/dev/null 2&>/dev/null; passwd -l daemon&>/dev/null 2&>/dev/null; passwd -l bin&>/dev/null 2&>/dev/null; passwd -l sys&>/dev/null 2&>/dev/null; passwd -l lp&>/dev/null 2&>/dev/null; passwd -l uucp&>/dev/null 2&>/dev/null; passwd -l nuucp&>/dev/null 2&>/dev/null; passwd -l smmsplp&>/dev/null 2&>/dev/null; passwd -l mail&>/dev/null 2&>/dev/null; passwd -l operator&>/dev/null 2&>/dev/null; passwd -l games&>/dev/null 2&>/dev/null; passwd -l gopher&>/dev/null 2&>/dev/null; passwd -l ftp&>/dev/null 2&>/dev/null; passwd -l nobody&>/dev/null 2&>/dev/null; passwd -l nobody4&>/dev/null 2&>/dev/null; passwd -l noaccess&>/dev/null 2&>/dev/null; passwd -l listen&>/dev/null 2&>/dev/null; passwd -l webservd&>/dev/null 2&>/dev/null; passwd -l rpm&>/dev/null 2&>/dev/null; passwd -l dbus&>/dev/null 2&>/dev/null; passwd -l avahi&>/dev/null 2&>/dev/null; passwd -l mailnull&>/dev/null 2&>/dev/null; passwd -l nscd&>/dev/null 2&>/dev/null; passwd -l vcsa&>/dev/null 2&>/dev/null; passwd -l rpc&>/dev/null 2&>/dev/null; passwd -l rpcuser&>/dev/null 2&>/dev/null; passwd -l nfs&>/dev/null 2&>/dev/null; passwd -l sshd&>/dev/null 2&>/dev/null; passwd -l pcap&>/dev/null 2&>/dev/null; passwd -l ntp&>/dev/null 2&>/dev/null; passwd -l haldaemon&>/dev/null 2&>/dev/null; passwd -l distcache&>/dev/null 2&>/dev/null; passwd -l webalizer&>/dev/null 2&>/dev/null; passwd -l squid&>/dev/null 2&>/dev/null; passwd -l xfs&>/dev/null 2&>/dev/null; passwd -l gdm&>/dev/null 2&>/dev/null; passwd -l sabayon&>/dev/null 2&>/dev/null; passwd -l named&>/dev/null 2&>/dev/null


  # (2) 口令策略设置
  log_info "[-] 用户口令复杂性策略设置 (密码过期周期0~90、到期前15天提示、密码长度至少15、复杂度设置至少有一个大小写、数字、特殊字符、密码三次不能一样、尝试次数为三次)"
  # 相关修改文件备份
  cp /etc/login.defs ${BACKUPDIR}/login.defs.bak;
  cp /etc/pam.d/password-auth ${BACKUPDIR}/password-auth.bak
  cp /etc/pam.d/system-auth ${BACKUPDIR}/system-auth.bak
  egrep -q "^\s*PASS_MIN_DAYS\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S*(\s*#.*)?\s*$/\PASS_MIN_DAYS  0/" /etc/login.defs || echo "PASS_MIN_DAYS  0" >> /etc/login.defs
  egrep -q "^\s*PASS_MAX_DAYS\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S*(\s*#.*)?\s*$/\PASS_MAX_DAYS  90/" /etc/login.defs || echo "PASS_MAX_DAYS  90" >> /etc/login.defs
  egrep -q "^\s*PASS_WARN_AGE\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S*(\s*#.*)?\s*$/\PASS_WARN_AGE  15/" /etc/login.defs || echo "PASS_WARN_AGE  15" >> /etc/login.defs
  egrep -q "^\s*PASS_MIN_LEN\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_LEN\s+\S*(\s*#.*)?\s*$/\PASS_MIN_LEN  15/" /etc/login.defs || echo "PASS_MIN_LEN  15" >> /etc/login.defs

  egrep -q "^password\s.+pam_pwquality.so\s+\w+.*$" /etc/pam.d/password-auth && sed -ri '/^password\s.+pam_pwquality.so/{s/pam_pwquality.so\s+\w+.*$/pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=  minlen=15 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=1 enforce_for_root/g;}' /etc/pam.d/password-auth
  egrep -q "^password\s.+pam_unix.so\s+\w+.*$" /etc/pam.d/password-auth && sed -ri '/^password\s.+pam_unix.so/{s/pam_unix.so\s+\w+.*$/pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=3/g;}' /etc/pam.d/password-auth

  egrep -q "^password\s.+pam_pwquality.so\s+\w+.*$" /etc/pam.d/system-auth && sed -ri '/^password\s.+pam_pwquality.so/{s/pam_pwquality.so\s+\w+.*$/pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=  minlen=15 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=1 enforce_for_root/g;}' /etc/pam.d/system-auth
  egrep -q "^password\s.+pam_unix.so\s+\w+.*$" /etc/pam.d/system-auth && sed -ri '/^password\s.+pam_unix.so/{s/pam_unix.so\s+\w+.*$/pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=3/g;}' /etc/pam.d/system-auth

  log_info "[-] 存储用户密码的文件，其内容经过sha512加密，所以非常注意其权限"
  # 解决首次登录配置密码时提示"passwd: Authentication token manipulation error"
  touch /etc/security/opasswd && chown root:root /etc/security/opasswd && chmod 600 /etc/security/opasswd 
  
  # 此参数需要根据业务来定，否则在使用时候会出现某些权限不足导致程序安装报错
  log_info "[-] 配置用户 umask 为022 "
  cp -a /etc/profile ${BACKUPDIR}/profile
  egrep -q "^\s*umask\s+\w+.*$" /etc/profile && sed -ri "s/^\s*umask\s+\w+.*$/umask 022/" /etc/profile || echo "umask 022" >> /etc/profile
  source /etc/profile
  #log_info "[-] 设置用户目录创建默认权限, (初始为077比较严格)在未设置umask为027则默认为077"
  #egrep -q "^\s*umask\s+\w+.*$" /etc/csh.login && sed -ri "s/^\s*umask\s+\w+.*$/umask 022/" /etc/csh.login || echo "umask 022" >> /etc/csh.login
  #egrep -q "^\s*umask\s+\w+.*$" /etc/csh.cshrc && sed -ri "s/^\s*umask\s+\w+.*$/umask 022/" /etc/csh.cshrc || echo "umask 022" >> /etc/csh.cshrc


}

## 名称: Os_Security_Grub
## 用途: 操作系统安全加固配置脚本(符合等保要求-三级要求)-2-grub
## 参数: 无
Os_Security_Grub () {

  # grub是一个用于加载和管理系统启动的完整程序,是一种引导程序;它是计算机启动时运行的第一个软件,会加载操作系统的内核,再由内核初始化操作系统的其他部分。

  # (8) GRUB 安全设置
  log_info "[-] 系统 GRUB 安全设置(防止物理接触从grub菜单中修改密码) "
  # Grub 关键文件备份
  cp -a /etc/grub.d/00_header ${BACKUPDIR}/'00_header'${EXEC_TIME}.bak
  cp -a /etc/grub.d/10_linux ${BACKUPDIR}/'10_linux'${EXEC_TIME}.bak
  # 设置Grub菜单界面显示时间
  sed -i -e 's|set timeout_style=${style}|#set timeout_style=${style}|g' -e 's|set timeout=${timeout}|set timeout=3|g' /etc/grub.d/00_header
  # sed -i -e 's|GRUB_TIMEOUT_STYLE=hidden|#GRUB_TIMEOUT_STYLE=hidden|g' -e 's|GRUB_TIMEOUT=0|GRUB_TIMEOUT=3|g' /etc/default/grub

  # grub 用户认证密码创建
  #sudo grub2-mkpasswd-pbkdf2
  # 输入口令：
  # Reeter password:n
  # PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.D3A42D2E24A2B2A62CFAB435890840E868088982B3B5EA14FB5F62BC5F0DF6E267CF1D42950A710A2539B4EA0E1D08569928427243E61E063DF2CEF34A571E6B.E7360FF876927678BD33348531B493039D9606062F7A4D9D722BDE94FF26A4B7D2B62AFDDA3F7D47EFDF46623DEAC547733B24E98630FE3961BEDA9257BAEA95

  # 设置认证用户和密钥（使用grub2-mkpasswd-pbkdf2生成密钥，口令为Liyanjing）
  tee -a /etc/grub.d/00_header <<'END'
cat <<'EOF'
# GRUB Authentication
set superusers="grub"
password_pbkdf2 grub grub.pbkdf2.sha512.10000.D3A42D2E24A2B2A62CFAB435890840E868088982B3B5EA14FB5F62BC5F0DF6E267CF1D42950A710A2539B4EA0E1D08569928427243E61E063DF2CEF34A571E6B.E7360FF876927678BD33348531B493039D9606062F7A4D9D722BDE94FF26A4B7D2B62AFDDA3F7D47EFDF46623DEAC547733B24E98630FE3961BEDA9257BAEA95
EOF
END
  # 设置进入正式系统不需要认证如进入单用户模式进行重置账号密码时需要进行认证。 （高敏感数据库系统不建议下述操作）
  # 在 135 加入 -unrestricted ，例如, 此处与Ubuntu不同的是不加--user=grub
  # 133 echo "menuentry $(echo "$title" | grub_quote)' ${CLASS} \$menuentry_id_option 'gnulinux-$version-$type-    $boot_device_id' {" | sed "s/^/$submenu_indentation/"
  # 134   else
  # 135 echo "menuentry --unrestricted '$(echo "$os" | grub_quote)' ${CLASS} \$menuentry_id_option 'gnulinux-simple-$boot_devic    e_id' {" | sed "s/^/$submenu_indentation/"
  sed -i '/echo "$title" | grub_quote/ { s/menuentry /menuentry /;}' /etc/grub.d/10_linux
  sed -i '/echo "$os" | grub_quote/ { s/menuentry /menuentry --unrestricted /;}' /etc/grub.d/10_linux
  # CentOS 方式更新GRUB从而生成boot启动文件
  grub2-mkconfig -o /boot/grub2/grub.cfg

}

## 名称: Os_Security_Ssh
## 用途: 操作系统安全加固配置脚本(符合等保要求-三级要求)-3-ssh安全加固设置
## 参数: 无
Os_Security_Ssh () {

  # (4) SSHD 服务安全加固设置以及网络登陆Banner设置
  log_info "[-] sshd 服务安全加固设置"
  cp /etc/ssh/sshd_config ${BACKUPDIR}/sshd_config.bak
  # 严格模式
  sudo egrep -q "^\s*StrictModes\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*StrictModes\s+.+$/StrictModes yes/" /etc/ssh/sshd_config || echo "StrictModes yes" >> /etc/ssh/sshd_config

  # 禁用X11转发以及端口转发
  sudo egrep -q "^\s*X11Forwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*X11Forwarding\s+.+$/X11Forwarding no/" /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config
  sudo egrep -q "^\s*X11UseLocalhost\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*X11UseLocalhost\s+.+$/X11UseLocalhost yes/" /etc/ssh/sshd_config || echo "X11UseLocalhost yes" >> /etc/ssh/sshd_config
  sudo egrep -q "^\s*AllowTcpForwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*AllowTcpForwarding\s+.+$/AllowTcpForwarding no/" /etc/ssh/sshd_config || echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
  sudo egrep -q "^\s*AllowAgentForwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*AllowAgentForwarding\s+.+$/AllowAgentForwarding no/" /etc/ssh/sshd_config || echo "AllowAgentForwarding no" >> /etc/ssh/sshd_config
  # 关闭禁用用户的 .rhosts 文件  ~/.ssh/.rhosts 来做为认证: 缺省IgnoreRhosts yes 
  egrep -q "^(#)?\s*IgnoreRhosts\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*IgnoreRhosts\s+.+$/IgnoreRhosts yes/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config

  # 登陆前后欢迎提示设置
  egrep -q "^\s*(banner|Banner)\s+\W+.*$" /etc/ssh/sshd_config && sed -ri "s/^\s*(banner|Banner)\s+\W+.*$/Banner \/etc\/issue/" /etc/ssh/sshd_config || \
  echo "Banner /etc/issue" >> /etc/ssh/sshd_config  
  log_info "[-] 远程SSH登录前后提示警告Banner设置"
  # SSH登录前后提示警告Banner设置
  sudo tee /etc/issue <<'EOF'
******************* [ 安全登陆 (Security Login) ] ******************* 
您的所有活动都将被安全中心监控和报告.
All activities will be monitored and reported by the security center.
EOF
  # SSH登录后提示Banner
  # 艺术字B格: http://www.network-science.de/ascii/
  sudo tee /etc/motd <<'EOF'
################## [ 安全运维 (Security Operation) ] ##################
               _    _                  _ _           
              | |  (_)_  _ __ _ _ _ _ | (_)_ _  __ _  
              | |__| | || / _` | ' \ || | | ' \/ _` |  
              |____|_|\_, \__,_|_||_\__/|_|_||_\__, | 
                      |__/                     |___/   
                                                   
※ 不用22/3306/6379/等高危默认端口, 不对 Internet 开放; 密码设置足够强壮.
※ WEB应用上线前须做安全渗透测试; 系统/软件/等定期打补丁.
※ 跳板机尽量将SSH限制IP在最小化范围内.

登录成功, 请仔细执行命令和操作数据.
Login success. Please execute the command and operation data carefully.
EOF

  # (5) 用户远程登录失败次数与终端超时设置 
  log_info "[-] 用户远程连续登录失败10次锁定帐号5分钟包括root账号"
  cp /etc/pam.d/sshd ${BACKUPDIR}/sshd.bak
  cp /etc/pam.d/login ${BACKUPDIR}/login.bak

  # 远程登陆
  sed -ri "/^\s*auth\s+required\s+pam_tally2.so\s+.+(\s*#.*)?\s*$/d" /etc/pam.d/sshd 
  sed -ri '2a auth required pam_tally2.so deny=10 unlock_time=300 even_deny_root root_unlock_time=300' /etc/pam.d/sshd 
  # 宿主机控制台登陆(可选)
  # sed -ri "/^\s*auth\s+required\s+pam_tally2.so\s+.+(\s*#.*)?\s*$/d" /etc/pam.d/login
  # sed -ri '2a auth required pam_tally2.so deny=10 unlock_time=300 even_deny_root root_unlock_time=300' /etc/pam.d/login


  # (6) 切换用户命令改为大写的SU,设置用户的日志记录
  log_info "[-] 切换用户命令改为大写的SU，设置用户的日志记录"
  cp -a /etc/rsyslog.conf  ${BACKUPDIR}/rsyslog.conf-${EXEC_TIME}.bak
  egrep -q "^\s*authpriv\.\*\s+.+$" /etc/rsyslog.conf && sed -ri "s/^\s*authpriv\.\*\s+.+$/authpriv.*  \/var\/log\/secure/" /etc/rsyslog.conf || echo "authpriv.*  /var/log/secure" >> /etc/rsyslog.conf
  egrep -q "^(\s*)SULOG_FILE\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)SULOG_FILE\s+\S*(\s*#.*)?\s*$/\SULOG_FILE  \/var\/log\/.history\/sulog/" /etc/login.defs || echo "SULOG_FILE  /var/log/.history/sulog" >> /etc/login.defs
  egrep -q "^\s*SU_NAME\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)SU_NAME\s+\S*(\s*#.*)?\s*$/\SU_NAME  SU/" /etc/login.defs || echo "SU_NAME  SU" >> /etc/login.defs
  mkdir -vp /usr/local/bin
  cp /usr/bin/su ${BACKUPDIR}/su.bak
  mv /usr/bin/su /usr/bin/SU
  chmod 777 ${HISDIR}
  chattr -R +a ${HISDIR}

  # (7) 用户终端执行的历史命令记录
  log_info "[-] 保存用户终端执行的历史命令记录 "
  egrep -q "^HISTSIZE\W\w+.*$" /etc/profile && sed -ri "s/^HISTSIZE\W\w+.*$/HISTSIZE=101/" /etc/profile || echo "HISTSIZE=101" >> /etc/profile
  source /etc/profile
  sudo tee /etc/profile.d/history-record.sh <<'EOF'
# 历史命令执行记录文件路径
LOGTIME=$(date +%Y%m%d-%H-%M-%S)
export HISTFILE="/var/log/.history/${USER}.${LOGTIME}.history"
if [ ! -f ${HISTFILE} ];then
  touch ${HISTFILE}
fi
chmod 600 /var/log/.history/${USER}.${LOGTIME}.history
# 历史命令执行文件大小记录设置
HISTFILESIZE=128
HISTTIMEFORMAT="%F_%T $(whoami)#$(who -u am i 2>/dev/null| awk '{print $NF}'|sed -e 's/[()]//g'):"
EOF
  sudo chmod +775 /etc/profile.d/history-record.sh
  sudo chmod a+x /etc/profile.d/history-record.sh
  source /etc/profile.d/history-record.sh

  log_info "[-] 关闭执行命令时提示：You have new mail in /var/spool/mail/root "
  egrep -q "unset MAILCHECK" /etc/profile && sed -ri "s/unset MAILCHECK/unset MAILCHECK/" /etc/profile || echo -e "unset MAILCHECK" >> /etc/profile	
  source /etc/profile
  ls -lth /var/spool/mail/
  cat /dev/null > /var/spool/mail/root
  
  log_info "[-] 设置登录超时时间为10分钟 "
  # source /etc/profile 报错 -bash: TMOUT: readonly variable，需要打开/etc/profile将#export TMOUT #readonly TMOUT 注释掉。 环境变量readonly TMOUT防止用户更改
  egrep -q "^\s*(export|)\s*TMOUT\S\w+.*$" /etc/profile && sed -ri "s/^\s*(export|)\s*TMOUT.\S\w+.*$/export TMOUT=600\nreadonly TMOUT/" /etc/profile || echo -e "export TMOUT=600\nreadonly TMOUT" >> /etc/profile
  source /etc/profile
  egrep -q "^\s*.*ClientAliveInterval\s\w+.*$" /etc/ssh/sshd_config && sed -ri "s/^\s*.*ClientAliveInterval\s\w+.*$/ClientAliveInterval 600/" /etc/ssh/sshd_config || echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config
}

## 名称: Os_Security_FilePermissions
## 用途: 操作系统安全加固配置脚本(符合等保要求-三级要求)-4-设置或恢复文件or目录权限
## 参数: 无
Os_Security_FilePermissions () {

  # (3) 设置或恢复重要目录和文件的权限
  log_info "[-] 操作系统安全加固配置(符合等保要求-三级要求)-4..."
  log_info "[-] 设置或恢复重要目录和文件的权限(设置日志文件非全局可写)"
  chmod 755 /etc;
  chmod 755 /etc/passwd; 
  chmod 755 /etc/shadow; 
  chmod 755 /etc/security; 
  chmod 644 /etc/group; 
  chmod 644 /etc/services; 
  chmod 750 /etc/rc*.d;
  chmod 755 /var/log/messages;
  chmod 775 /var/log/spooler;
  chmod 775 /var/log/cron;
  chmod 775 /var/log/secure;
  chmod 775 /var/log/maillog;
  chmod 775 /var/log/mail&>/dev/null 2&>/dev/null; 
  chmod 775 /var/log/localmessages&>/dev/null 2&>/dev/null
  chmod 600 ~/.ssh/authorized_keys 2&>/dev/null
  # 提高系统安全，更改其执行权限，解决Polkit 权限提升漏洞
  chmod 0755 /usr/bin/pkexec

  log_info "[-] 删除潜在威胁文件 "
  find / -maxdepth 3 -name hosts.equiv | xargs rm -rf
  find / -maxdepth 3 -name .netrc | xargs rm -rf
  find / -maxdepth 3 -name .rhosts | xargs rm -rf

}

## 名称: Os_Security_Others
## 用途: 操作系统安全加固配置脚本(符合等保要求-三级要求)-5-更多
## 参数: 无
Os_Security_Others () {
  # (9) 记录安全事件日志
  log_info "[-] 记录安全事件日志"
  touch /var/log/.history/adm&>/dev/null; chmod 755 /var/log/.history/adm
  semanage fcontext -a -t security_t '/var/log/.history/adm'
  restorecon -v '/var/log/.history/adm'&>/dev/null
  egrep -q "^\s*\*\.err;kern.debug;daemon.notice\s+.+$" /etc/rsyslog.conf && sed -ri "s/^\s*\*\.err;kern.debug;daemon.notice\s+.+$/*.err;kern.debug;daemon.notice  \/var\/log\/.history\/adm/" /etc/rsyslog.conf || echo "*.err;kern.debug;daemon.notice  /var/log/.history/adm" >> /etc/rsyslog.conf


  # (10) 配置自动屏幕锁定（适用于具备图形界面的设备）, 非图形界面不需要执行
  log_info "[-] 对于有图形界面的系统配置10分钟屏幕锁定"
# gconftool-2 --direct \
# --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
# --type bool \
# --set /apps/gnome-screensaver/idle_activation_enabled true \
# --set /apps/gnome-screensaver/lock_enabled true \
# --type int \
# --set /apps/gnome-screensaver/idle_delay 10 \
# --type string \
# --set /apps/gnome-screensaver/mode blank-only

  # (11) 启防火墙服务
  log_info "[-] 开启防火墙服务..."
  yum -y install firewalld
  systemctl start firewalld.service
  systemctl enable firewalld.service
  sleep 2
  # 161端口是用于“Simple Network Management Protocol”,该协议主要用于管理TCP/IP网络中的网络协议，目前，几乎所有的网络设备厂商都实现对SNMP的支持。
  firewall-cmd --zone=public --add-port=161/udp --permanent
  firewall-cmd --reload  
  sleep 3
  
  # (12) 禁用CentOS服务器中 SELINUX
  log_info "[-] 禁用SELinux，永久关闭，重启服务器生效. " 
  # 临时关闭"
  setenforce 0
  sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux

  log_info "[-] \n系统将在5s后重启。"
  shutdown -r -t 5
}


## 名称: Os_Operation 
## 用途: 操作系统安全运维设置相关脚本
## 参数: 无
Os_Operation () {

  log_info "[-] 操作系统安全运维设置相关脚本..."

  # (0) 禁用ctrl+alt+del组合键对系统重启 (必须要配置,我曾入过坑)
  log_info "[-] 禁用控制台ctrl+alt+del组合键重启"
  mv /usr/lib/systemd/system/ctrl-alt-del.target ${BACKUPDIR}/ctrl-alt-del.target-${EXEC_TIME}.bak

  # (1) 设置文件删除rm命令的别名
  log_info "[-] 设置文件删除rm命令的别名(防止误删数据，不删除而是移动到回收站) "
sudo cat > /etc/profile.d/alias.sh <<EOF
# User specific aliases and functions
# 删除回收站
# find ~/.trash -delete
# 删除空目录
# find ~/.trash -type d -delete
alias rm='sh /usr/local/bin/remove.sh'
EOF

  # $HOME是linux自身的变量，是当前用户的家目录变量，cd $HOME 进入当前用户的主目录
  sudo tee /usr/local/bin/remove.sh <<'EOF'
#!/bin/sh
# 定义回收站文件夹目录.trash
trash="/.trash"
deltime=$(date +%Y%m%d-%H-%M-%S)
TRASH_DIR="${HOME}${trash}/${deltime}"
# 回收站目录不存在则创建
if [ ! -e ${TRASH_DIR} ];then
   mkdir -p ${TRASH_DIR}
fi
for i in $*;do
  if [ "$i" = "-rf" ];then continue;fi
  # 防止误操作
  if [ "$i" = "/" ];then echo '# Danger delete command, Not delete / directory!';exit -1;fi

  #定义秒时间戳
  STAMP=$(date +%s)
  #得到文件名称(非文件夹)，参考man basename
  fileName=$(basename $i)
  #将输入的参数，对应文件mv至.trash目录，文件后缀，为当前的时间戳
  mv $i ${TRASH_DIR}/${fileName}.${STAMP}
done
EOF
  sudo chmod +775 /usr/local/bin/remove.sh /etc/profile.d/alias.sh
  sudo chmod a+x /usr/local/bin/remove.sh /etc/profile.d/alias.sh
  source /etc/profile.d/alias.sh  
  source /etc/profile
}


## 名称: Os_Disable_SomeServices
## 用途: 禁用与设置操作系统中某些服务(需要根据实际环境进行)
## 参数: 无
Os_Disable_SomeServices () {
  log_info "[-] 禁用操作系统中某些服务(需要根据实际环境进行配置)..."

  log_info "[-] 配置禁用telnet服务"
  cp /etc/services ${BACKUPDIR}/'services-'${EXEC_TIME}.bak
  egrep -q "^\s*telnet\s+\d*.+$" /etc/services && sed -ri "/^\s*telnet\s+\d*.+$/s/^/# /" /etc/services

  log_info "[-] 禁止匿名用户、root用户登录FTP"
  if [ -f /etc/vsftpd/vsftpd.conf ]; then
    cp /etc/vsftpd/vsftpd.conf /etc/vsftpd/'vsftpd.conf-'`date +%Y%m%d`.bak
    systemctl list-unit-files|grep vsftpd > /dev/null && sed -ri "/^\s*anonymous_enable\s*\W+.+$/s/^/#/" /etc/vsftpd/vsftpd.conf && echo "anonymous_enable=NO" >> /etc/vsftpd/vsftpd.conf
    systemctl list-unit-files|grep vsftpd > /dev/null && echo "root" >> /etc/vsftpd/ftpusers
    log_info "[-] 限制FTP用户上传的文件所具有的权限"
    systemctl list-unit-files|grep vsftpd > /dev/null && sed -ri "/^\s*write_enable\s*\W+.+$/s/^/#/" /etc/vsftpd/vsftpd.conf && echo "write_enable=NO" >> /etc/vsftpd/vsftpd.conf
    systemctl list-unit-files|grep vsftpd > /dev/null && sed -ri "/^\s*ls_recurse_enable\s*\W+.+$/s/^/#/" /etc/vsftpd/vsftpd.conf && echo "ls_recurse_enable=NO" >> /etc/vsftpd/vsftpd.conf
    systemctl list-unit-files|grep vsftpd > /dev/null && sed -ri "/^\s*anon_umask\s*\W+.+$/s/^/#/" /etc/vsftpd/vsftpd.conf && echo "anon_umask=077" >> /etc/vsftpd/vsftpd.conf
    systemctl list-unit-files|grep vsftpd > /dev/null && sed -ri "/^\s*local_umask\s*\W+.+$/s/^/#/" /etc/vsftpd/vsftpd.conf && echo "local_umask=022" >> /etc/vsftpd/vsftpd.conf
    log_info "[-] 限制FTP用户登录后能访问的目录"
    systemctl list-unit-files|grep vsftpd > /dev/null && sed -ri "/^\s*chroot_local_user\s*\W+.+$/s/^/#/" /etc/vsftpd/vsftpd.conf && echo "chroot_local_user=NO" >> /etc/vsftpd/vsftpd.conf
    log_info "[-] FTP Banner 设置"
    systemctl list-unit-files|grep vsftpd > /dev/null && sed -ri "/^\s*ftpd_banner\s*\W+.+$/s/^/#/" /etc/vsftpd/vsftpd.conf && echo "ftpd_banner='Authorized only. All activity will be monitored and reported.'" >> /etc/vsftpd/vsftpd.conf

    log_info "[-] 限制不必要的服务 (根据实际环境配置)"
    # systemctl disable rsh&>/dev/null 2&>/dev/null;systemctl disable talk&>/dev/null 2&>/dev/null;systemctl disable telnet&>/dev/null 2&>/dev/null;systemctl disable tftp&>/dev/null 2&>/dev/null;systemctl disable rsync&>/dev/null 2&>/dev/null;systemctl disable xinetd&>/dev/null 2&>/dev/null;systemctl disable nfs&>/dev/null 2&>/dev/null;systemctl disable nfslock&>/dev/null 2&>/dev/null
fi

  log_info "[-] 配置SNMP默认团体字"
  if [ -f /etc/snmp/snmpd.conf ]; then
    cp /etc/snmp/snmpd.conf ${BACKUPDIR}/'snmpd.conf-'${EXEC_TIME}.bak
    cat > /etc/snmp/snmpd.conf <<EOF
com2sec $SNMP_user  default    $SNMP_password   
group   $SNMP_group         v1           $SNMP_user
group   $SNMP_group         v2c          $SNMP_user
view    systemview      included        .1                      80
view    systemview      included        .1.3.6.1.2.1.1
view    systemview      included        .1.3.6.1.2.1.25.1.1
view    $SNMP_view        included        .1.3.6.1.4.1.2021.80
access  $SNMP_group         ""      any       noauth    exact  systemview none none
access  $SNMP_group         ""      any       noauth    exact  $SNMP_view   none none
dontLogTCPWrappersConnects yes
trapcommunity $SNMP_password
authtrapenable 1
trap2sink $SNMP_ip
agentSecName $SNMP_user
rouser $SNMP_user
defaultMonitors yes
linkUpDownNotifications yes
EOF
  fi
}


## 名称: Os_Change_SShPort
## 用途: 更改ssh端口号，不输入参数则使用defaultport
## 参数: $1(端口号) 或 无
function Change_SShPort() {

  log_info "[-] 更改ssh默认端口，提高安全性..."
  
  # 判断是否输入了参数
  if [ -n "$1" ];then
    # echo "第一个参数$1"
    SSH_PORT=${1}
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

## 用途: 执行更改ssh端口号
function run_change_sshport() {

  read -r -p "Do you agree change the SSH port to ${SSH_PORT} ? If not, please enter another port? [Y/n] " -t 30 input_ssh_yn
  case $input_ssh_yn in
      [yY][eE][sS]|[yY])
          echo -e "\033[32mYes, continue...\033[0m"
          Change_SShPort
          ;; 
      [nN][oO]|[nN])
           while true; do   
               read -p "建议端口从40101开始，请输入 ssh 端口号：" SSH_PORT
              isValidNum ${SSH_PORT}  
              [ $? -eq 0 ] && break   
            done
            Change_SShPort ${SSH_PORT}
          ;; 
      *)
          echo -e "\033[31merror! you input isn't yes or no.\n\033[0m"
          exit 1
          ;;
  esac

  log_warning  "[-!] 不要将 sshd 对 Internet 开放登陆权限，尽量将SSH局限在几个小范围内的 IP，请你另行设置！"
}

## 名称: Os_Kernel_Upgrade
## 用途: CentOS 操作系统内核升级(可选) ,yum方式在线升级，强烈推荐手动“离线升级”
## 参数: 无
Os_Kernel_Upgrade() {

  log_info "[*] CentOS 操作系统内核升级(可选) "
  
  # (2) CentOS 操作系统内核升级(可选)
  cp -a /etc/grub2.cfg ${BACKUPDIR}/grub2.cfg.kernelupdate.bak

  rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
  yum -y install https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm
  yum --disablerepo="*" --enablerepo=elrepo-kernel repolist
  yum --disablerepo="*" --enablerepo=elrepo-kernel list kernel*
  # 内核安装，服务器里我们选择长期lt版本，安全稳定是我们最大的需求，除非有特殊的需求内核版本需求;
  yum update -y --enablerepo=elrepo-kernel 
  # 内核版本介绍, lt:longterm 的缩写长期维护版, ml:mainline 的缩写最新主线版本;
  yum install -y --enablerepo=elrepo-kernel --skip-broken kernel-lt kernel-lt-devel kernel-lt-tools
  # yum -y --enablerepo=elrepo-kernel --skip-broken install kernel-ml.x86_64 kernel-ml-devel.x86_64 kernel-ml-tools.x86_64
  log_warning "[*] 当前 CentOS 操作系统可切换的内核内核版本"
  awk -F \' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg
  sudo grub2-set-default 0
  #传统引导
  # grub2-mkconfig -o /boot/grub2/grub.cfg
  # grubby --default-kernel
  reboot

}


## 名称: Disk_LvsManager
## 用途: CentOS7 操作系统磁盘 LVS 逻辑卷添加与配置(扩容流程) - 请按需调用执行
## 参数: 无
Disk_lvsManager () {
  echo -e "\n 分区信息:"
  sudo df -Th
  sudo lsblk
  echo -e "\n 磁盘信息："
  sudo fdisk -l
  echo -e "\n PV物理卷查看："
  sudo pvscan
  echo -e "\n vgs虚拟卷查看："
  sudo vgs
  echo -e "\n lvscan逻辑卷扫描:"
  sudo lvscan
  echo -e "\n 分区扩展"
  echo -e "CentOS \n lvextend -L +24G /dev/centos/root"
  echo "lsblk"
  echo -e "Centos \n # xfs_growfs /dev/mapper/centos-root"
}


## 名称: Os_Network
## 用途: 操作系统网络配置相关脚本包括(IP地址修改)
## 参数: 无
Os_Network(){

  log_info "[-] 操作系统网络配置相关脚本,开始执行..."

  # (1) 静态网络IP地址设置
  log_info "[-] 修改网卡配置（设置静态ip）..."
  tee /opt/network_staticIp_set.sh <<'EOF'
#!/bin/bash
IPADDR="${1}"
NETMASK="${2}"
GATEWAY="${3}"
DEVNAME="ifcfg-ens192"
if [ "${4}" != "" ];then
  DEVNAME="ifcfg-${4}"
fi
if [[ $# -lt 3 ]];then
  echo -e "\e[32m[*] Usage: $0 IP-Address MASK Gateway \e[0m"
  echo -e "\e[32m[*] Usage: $0 192.168.1.99 255.255.255.0 192.168.1.1 \e[0m"
  exit 1
fi
NET_FILE="/etc/sysconfig/network-scripts/${DEVNAME}"
if [[ ! -f ${NET_FILE} ]];then
  echo "\033[31m[*] Not Found ${NET_FILE} File\n\033[0m"
  exit 2
fi
cp ${NET_FILE}{,.bak}
sed -i -e 's/^ONBOOT=.*$/ONBOOT="yes"/' -e 's/^BOOTPROTO=.*$/BOOTPROTO="static"/' ${NET_FILE}
grep -q "^IPADDR=.*$" ${NET_FILE} &&  sed -i "s/^IPADDR=.*$/IPADDR=\"${IPADDR}\"/" ${NET_FILE} || echo "IPADDR=\"${IPADDR}\"" >> ${NET_FILE}
grep -q "^NETMASK=.*$" ${NET_FILE} &&  sed -i "s/^NETMASK=.*$/NETMASK=\"${NETMASK}\"/" ${NET_FILE} || echo "NETMASK=\"${NETMASK}\"" >> ${NET_FILE}
grep -q "^GATEWAY=.*$" ${NET_FILE} &&  sed -i "s/^GATEWAY=.*$/GATEWAY=\"${GATEWAY}\"/" ${NET_FILE} || echo "GATEWAY=\"${GATEWAY}\"" >> ${NET_FILE}
EOF
  chmod +x /opt/network_staticIp_set.sh

  # 网络变量，IPADDR静态ip\NETMASK子网掩码\GATEWAY默认网关  
  # 0.获取网卡名
  network_name=$(ip a | sed -r -n 's/^[0-9]+: (.*):.*/\1/p' | grep -v lo)
  array_network_name=(`echo $network_name | tr '\n' ' '` ) 
  num=${#array_network_name[@]}  					#获取数组元素的个数

  echo -e "\033[035m*********** 网络卡列表 ***********\033[0m"
  for(( i=0;i<${#array_network_name[@]};i++)) do 
               echo -e "\033[032m*    [ $i ]    ${array_network_name[$i]}    \033[0m"
  done;
  echo -e "\033[035m********************************\033[0m"
      
  read -r -p "*请选择网卡名前的序号: " input_n
  if [[ ! $input_n =~ [0-$num]+ ]]; then
            echo -e "\033[31merror! the number you input isn't 1 to $num \n\033[0m"
            exit 1
  fi
  DEVNAME=${array_network_name[$input_n]}
  echo "您选择的网卡是：${DEVNAME}"
  
  # 1. 输入静态ip
  while true; do   
	 read -p "请输入 ${DEVNAME} 的静态Ip：" IPADDR
     isValidIp ${IPADDR}  
     [ $? -eq 0 ] && break
  done
 
 # 2. 输入子网掩码
  while true; do  
    read -p "输入子网掩码(225.255.255.0):" NETMASK
    if [ -z "$NETMASK" ];then
        NETMASK="225.255.255.0"
    fi
     isValidIp ${NETMASK}  
     [ $? -eq 0 ] && break
  done
  #echo "子网掩码 is $NETMASK"

  # 3. 输入默认网关
  ip=(${IPADDR//\./ }) # 按.分割，转成数组
  netmask_default="${ip[0]}.${ip[1]}.${ip[2]}.254"
		
  while true; do  
    read -p "输入默认网关(${netmask_default}):" GATEWAY
    if [ -z "$GATEWAY" ];then
        GATEWAY=${netmask_default}
    fi
     isValidIp ${GATEWAY}  
     [ $? -eq 0 ] && break
  done
  #echo "默认网关 is $GATEWAY"
  
  # 调用脚本，设置网卡信息（静态ip...）
  /opt/network_staticIp_set.sh ${IPADDR} ${NETMASK} ${GATEWAY} ${DEVNAME}

  
  # (2) 系统主机名与本地解析设置  
  log_info "[-] 系统主机名与本地解析设置..."
  read -p "请数据主机名(`hostname`):" HOST_NAME
  if [ -z "$HOST_NAME" ];then
        HOST_NAME=`hostname`
  fi
   
  sudo hostnamectl set-hostname ${HOST_NAME} 
  # sed -i "s/127.0.1.1\s.\w.*$/127.0.1.1 ${NAME}/g" /etc/hosts
  cp -a /etc/hosts  ${BACKUPDIR}/hosts.bak
  grep -q "^\$(hostname -I)\s.\w.*$" /etc/hosts && sed -i "s/\$(hostname -I)\s.\w.*$/${IPADDR} ${HOST_NAME}" /etc/hosts || echo "${IPADDR} ${HOST_NAME}" >> /etc/hosts

  # (3) 系统DNS域名解析服务设置
  log_info "[-] DNS域名解析服务设置..."
  # DNS服务器地址
  DNSIP=("8.8.8.8" "114.114.114.114" "223.5.5.5")
  cp -a /etc/resolv.conf  ${BACKUPDIR}/resolv.conf.bak
  for dns in  ${DNSIP[@]};do 
    egrep -q "^nameserver .*${dns}$" /etc/resolv.conf && sed -ri "s/^nameserver.*${dns}$/nameserver ${dns}/" /etc/resolv.conf || echo "nameserver ${dns}" >> /etc/resolv.conf
  done

  log_info "[*] network configure modifiy successful! restarting Network........."
  service network restart && ip addr
}


## 名称: add_group
## 用途：创建普通用户的所属组
## 参数: 无
function add_group() {
  # create group if not exists
  egrep "^$group_name" /etc/group >& /dev/null
  if [ $? -ne 0 ]
  then
      groupadd --gid 5001 $group_name
  fi
}

## 名称: add_group
## 用途：创建普通用户的所属组
## 参数: $1(用户名) 或 无
function add_user() {

  log_info "[-] 创建一个拥有管理权限的普通用户，执行sodu命令需要输入密码..."
  
  # 判断是否输入了参数
  if [ -n "$1" ];then
    # echo "第一个参数$1"
    user_name=${1}
  fi
  
  # 1.添加用户，并指定用户id,组id,
  useradd --home-dir /home/$user_name --create-home --uid 5001 \
    --gid 5001 --shell /bin/bash --skel /dev/null $user_name

  # 2.设置用户密码
  echo $user_passwd | passwd --stdin $user_name
	
  # 3.给普通用户授权sudo，先删除后添加
  cp /etc/sudoers ${BACKUPDIR}/sudoers.bak
  chmod -v u+w /etc/sudoers
  sed -i '/^'"$user_name"'.*$/d' /etc/sudoers
   
  # 允许用户your_user执行sudo命令，不输入密码
  tmp_str="$user_name    ALL=(ALL)   NOPASSWD:ALL"
  # 允许用户your_user执行sudo命令，需要输入密码
  #tmp_str="$user_name    ALL=(ALL)  ALL"  
  sed -i "/^root.*$/a ${tmp_str}"  /etc/sudoers
  chmod -v u-w /etc/sudoers
  
  # 4.将普通用户加入到root组
  usermod -a -G root $user_name
  
  log_info "[-] 一个拥有管理权限的普通用户 $user_name 已创建完毕，记得更改其密码哦 "
}

## 名字：run_add_user
## 用途：执行添加用户方法
## 参数：无
function run_add_user() {

  # create group if not exists
  add_group

  read -p "创建拥有管理权限的普通用户 ${user_name} (直接回车键)，若自定义名请输入:" input_user_name
  # 若没有输入，则使用默认值
  if [  -z "$input_user_name" ];then
        input_user_name=${user_name}
  fi

  # create user if not exists
  egrep "^$input_user_name" /etc/passwd >& /dev/null
  if [ $? -ne 0 ]; then
        add_user  ${input_user_name}
  else
        log_warning "用户 ${input_user_name} 已存在，无需重复创建 "
  fi
   
}

## 名字：Force_UserNextLogin_ChangePwd
## 用途：强制用户在下次登录时更改密码
## 参数: 无
function Force_UserNextLogin_ChangePwd() {

  log_info "[-] 强制用户在下次登录时更改密码... "

  Tmp_DefaultUser="root"

  read -r -p "Yes 强制 ${DefaultUser} 用户在下次登录时更改密码? Not 输入其他用户名? [Y/n] " -t 30 input_uname_yn
  case $input_uname_yn in
      [yY][eE][sS]|[yY])
          echo -e "\033[32mYes, continue...\033[0m"        
          chage -d 0 -m 0 -M 90 -W 15 root && passwd --expire root 
          ;; 
      [nN][oO]|[nN])          
	      read -p "请输入用户名：" Tmp_DefaultUser
          # 判断用户是否存在
          egrep "^$Tmp_DefaultUser" /etc/passwd >& /dev/null
          if [ $? -ne 0 ]; then
             log_warning "你输入的用户 ${user_name} 不存在！"
		  else
		     chage -d 0 -m 0 -M 90 -W 15 ${DefaultUser} && passwd --expire ${DefaultUser}  
          fi
          ;; 
      *)
          echo -e "\033[31merror! you input isn't yes or no.\n\033[0m"
          exit 1
          ;;
  esac

}

## 名字：Permit_RootSshLogin
## 用途：禁止或允许root用户ssh远程登陆，等保三级要求禁止root远程登陆
## 参数: 无
function Root_NoLogin() {

  read -r -p "禁止root远程登陆，普通用户你已创建好了吗? [Y/n] " -t 30 input_rootlogin_yn
  case $input_rootlogin_yn in
      [yY][eE][sS]|[yY])
          log_info "[-] yes 已创建普通用户，继续禁止root用户ssh远程登陆... "
          egrep -q "^\s*PermitRootLogin\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^\s*PermitRootLogin\s+.+$/PermitRootLogin no/" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
          systemctl restart sshd
          ;; 
      [nN][oO]|[nN])          
	      log_info "[-] no 没创建普通用户，还不能禁止root远程登陆... "		 
          ;; 
      *)
          echo -e "\033[31merror! you input isn't yes or no.\n\033[0m"
          exit 1
          ;;
  esac
  
}

function Permit_RootSshLogin() {
  
  read -r -p "你想禁止还是允许root用户ssh远程登陆? [Y禁止/n允许] " -t 30 input_rootlogin_yn
  case $input_rootlogin_yn in
      [yY][eE][sS]|[yY])
          Root_NoLogin
          ;; 
      [nN][oO]|[nN])          
	      log_info "[-] 允许root用户ssh远程登陆... "
		  egrep -q "^\s*PermitRootLogin\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^\s*PermitRootLogin\s+.+$/PermitRootLogin yes/" /etc/ssh/sshd_config || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
          systemctl restart sshd
          ;; 
      *)
          echo -e "\033[31merror! you input isn't yes or no.\n\033[0m"
          exit 1
          ;;
  esac
  
}

## 名字：Trash_Clear
## 用途：清空回收站，清除历史*.gz日志
## 参数: 无
function Trash_Clear() {

  log_info "[-] （1）清空回收站... " 

  # 附-如何防止rm误删数据，1）为rm设置了别名，2）放弃使用rm改用mv\find ，3）不删除，移动到回收站，4）不要这样用rm -fr /opt/* 正确做法是先切换到指定目录下再删除
  # 查看rm别名# alias rm ，默认设置的别名 # alias rm='rm -i'   rm默认开启了alias保护，在删除之前会提示是否删除。
  # 删除以前定义rm的别名。 
  #unalias rm  > /dev/null 2>&1
  #alias rm='rm -i'
  
  # 删除家目录回收站中的文件，即清空垃圾桶
  find ~/.trash/* -delete 2> /dev/null
  # 删除其他用户(家目录)中的回收站中的文件目录
  find /home/ -type d -name .trash -exec find {} -delete \;

  log_info "[-] （2）清理log日志... "  
  find /var/log -name "*.gz" -delete
  find /var/log -name "*log.*" -delete
  find /var/log -name "vmware-*.*.log" -delete
  find /var/log -name "*.log" -exec truncate -s 0 {} \;
  find /var/log -name "system@*" -delete
  find /var/log -name "user-1000@*" -delete
  find /tmp/* -delete 2> /dev/null
  
  log_warning "[-!] 询问要不要去掉回收站机制（测试类服务器不需要回收站）..."
  
  echo -e -n "\033[31m\n你要去掉回收站机制吗? [Y去掉/n保留]:\033[0m"
  read -t 30 input_trash_yn
  case $input_trash_yn in
      [yY][eE][sS]|[yY])
          unalias rm  > /dev/null 2>&1
          alias rm='rm -i'         
          ;; 
      [nN][oO]|[nN]) 
	      unalias rm  > /dev/null 2>&1
	      alias rm='sh /usr/local/bin/remove.sh'
          ;; 
      *)
          echo -e "\033[31merror! you input isn't yes or no.\n\033[0m"
          exit 1
          ;;
  esac
}


## 打印出选择项
function cmd_info_print() {

  echo -e '\033[32m 
==========================请选择要操作的项：==========================
# [0]  创建SWAP交换分区(默认2G) 
# [1]  设置网卡静态IP和DNS(按引导输入ip\子网掩码\默认网关)
#      + <11> 全局配置DNS
#      + <12> 判断能不能上网
# [2]  在线设置国内yum源，在线yum安装常用软件（htop\ncdu比du性能强\...）
# [3]  系统优化、安全加固等一键设置：
#      + <31> 系统的最大文件打开数限制，系统内核参数优化(含关闭ipv6)
#      + <32> 时区设置为东8区
#      + <33> 禁用ctrl+alt+del重启系统、定义回收站目录等
#      + <  > 系统安全加固(等保三级-操作系统检查项)如下：
#              ++ <35> 用户口令策略(密码过期90天、到期前15天提示、密码长度至少15等)
#              ++ <36> GRUB 安全设置
#              ++ <37> ssh安全加固设置
#              ++ <38> 设置或恢复重要目录和文件的权限
#              ++ <39> 开启防火墙、禁用SELINUX等更多设置，然后重启主机
# [4]  更改ssh端口号(等保要求不使用22端口，缺省时改为40107)
# [5]  创建一个拥有管理权限的普通用户(uudocker)，执行sodu命令时需要输入密码
# [6]  禁止或允许root用户远程登陆(等保要求禁止root远程登陆,正解:普通用户登陆后su root）
# [7]  强制用户在下次登录时更改密码
# [8]  使用Chrony配置主机时间同步(根据环境需要，可选项)
# [9]  禁用与设置系统中的某些服务(根据环境需要，可选项)
# [10] 清空回收站内容 and 询问你删除回收站功能吗？（执行rm误删时，它可拯救你）
#
# 以下脚本，仅供参考：
#       Os_Kernel_Upgrade 推荐"离线升级系统内核"
#       disk_Lvsmanager 磁盘LVS逻辑卷添加与配置\033[32m
=====================================================================
\033[31m注意：
	1. 切换用户的命令su已改为大写的SU
	2. 回收站目录 cd ${HOME}/.trash 会不断堆积会导致空间不足哦！日志定时清理脚本记得不要用rm改用find或其他切分工具
	3. 用户终端执行的历史命令记录保存目录为/var/log/.history/${USER}.${LOGTIME}.history\033[0m'

}

function run_main(){

  log_info "run start..."

  # 1. 判断系统内核
  kernel=$(uname -r) && log_info "[-] 此系统的内核为：$kernel" 
  result=$(echo $kernel | grep "3.10")
  if [[ "$result" != "" ]];  then
      #echo "包含"
	  log_warning "[!] Centos7操作系统默认内核3.10存在一些Bugs，请尽快升级。" 
  fi

  log_info "[-] 本系统的openssh 版本：" && ssh -V 
  result_openssh=$(rpm -qi openssh |grep "openssh-7.4")
  if [[ "$result_openssh" != "" ]];  then
      #echo "包含"
	  log_warning "[!] openssh默认版本是7.4存在安全漏洞，请尽快升级到最新版本。"
  fi

  # 2. 打印出选择项
  cmd_info_print

  # 3. 输入数字，执行对应的选项操作
  # 定义一个循环次数计数器
  declare -i autoprintcmd_count=0
  while [[ "$autoprintcmd_count" -le "10" ]]; do  
    cmd_number=""
    read -p "Please enter the number of the operation item or Press q to exit: " -t 90 cmd_number

    if [[ $cmd_number = "Q" || $cmd_number = "q" ]]; then  break; fi

    case ${cmd_number} in
      0) 
         # Liunx 系统创建SWAP交换分区(默认2G)
		 Os_Swap
         ;;
      1) 
         # 网卡设置静态IP(根据提示，输入ip\子网掩码\默认网关），设置DNS
         Os_Network
         ;;
	  2) 
         # 在线设置国内yum源、安装常用软件
         Os_YumSource_Aliyun
		 Os_Yum_Install_Software
         ;;
      3) 
        ## 系统优化、安全加固等，一键设置
		 # 系统的最大文件打开数限制；系统内核参数优化(含关闭ipv6)
         Os_Optimizationn
		 # 主机时区设置东8区
		 Os_TimedataZone
		 # 禁用ctrl+alt+del重启系统、定义回收站文件夹目录等安全运维有关的设置
		 Os_Operation
		 # 防止不生效，单独再执行一下
		 source /etc/profile.d/alias.sh

		 # 安全加固-用户口令策略
		 Os_Security_UserPwd
		 # 安全加固-GRUB 安全设置
		 Os_Security_Grub
		 # 安全加固-ssh设置
		 Os_Security_Ssh
		 # 安全加固-设置或恢复重要目录和文件的权限
		 Os_Security_FilePermissions

		 # 安全加固-开启防火墙、禁用SELINUX等更多设置，会重启服务器
		 Os_Security_Others

         ;;
      31)
         # 系统的最大文件打开数限制；系统内核参数优化(含关闭ipv6)
         Os_Optimizationn		 
         ;;
      32) 
         # 主机时区设置东8区
         Os_TimedataZone
         ;;		
      33) 
         # 禁用ctrl+alt+del重启系统、定义回收站文件夹目录等安全运维有关的设置
         Os_Operation
		 # 防止不生效，单独再执行一下
		 source /etc/profile.d/alias.sh
         ;;
      34) 
		 log_warning "[-!] 此选项未配置,请选择其他名目的序号"
         ;;
      35) 
         # 安全加固-用户口令策略
         Os_Security_UserPwd
         ;;
      36) 
         # GRUB 安全设置
         Os_Security_Grub
         ;;
      37) 
         # 安全加固-ssh设置
         Os_Security_Ssh
         ;;
      38) 
         # 设置或恢复重要目录和文件的权限
         Os_Security_FilePermissions
         ;;
      39) 
         # 开启防火墙、禁用SELINUX等更多设置，然后重启主机
         Os_Security_Others
         ;;
      4) 
         # 更改ssh登陆端口(默认改为40107)
         run_change_sshport
         ;;
      5) 
         # 创建拥有sudo权限的运维用户(默认uudocker）
         run_add_user
         ;;
      6) 
         # 禁止或允许root远程登录（若禁止root远程登陆，确保已创建了普通用户）
         Permit_RootSshLogin
         ;;
      7) 
         # 强制用户在下次登录时更改密码
         Force_UserNextLogin_ChangePwd
         ;;	
      8) 
         # 配置主机时间同步(使用Chrony，根据实际环境进行，可选项)
         Os_HostTimeSync_Chrony
         ;;
      9) 
         # 禁用与设置操作系统中某些服务(根据实际环境进行，可选项)
         Os_Disable_SomeServices
         ;;
      10) 
         # 清空回收站，清理log日志
         Trash_Clear
         ;;
      11) 
         # 全局配置DNS
         setDNS
         ;;
      12) 
         # 判断能不能上网
         internetCheck
         if [ $? -eq 0 ];then  
		      echo -e "\033[31m主机无法上网，请检查网络设置！\n\033[0m"; 
			  # 配置下dns
              setDNS
         else
		      echo -e "\033[32m哇塞，可以上网冲浪啦！\n\033[0m"; 
         fi
         ;;
      *) 
         # 打印出选择项
         cmd_info_print
         ((autoprintcmd_count++))
         ;; 
    esac

  done
  
  log_info " It's over, Good night. Bye!"

}

run_main
