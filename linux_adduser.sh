#!/bin/bash
#
#用途：添加普通用户，日常运维使用普通用户
#

# 添加普通用户，定义变量
user_name="uudocker"
#单引号中的任何字符都只当作是普通字符
user_passwd='zRM8B%Ka!5Fh%Out'
group_name="docker"

#变更所属用户的目录，多个目录空格隔开
arr_dirs=(/usr/local/docker /data)

function add_group(){
  #create group if not exists
  egrep "^$group_name" /etc/group >& /dev/null
  if [ $? -ne 0 ]
  then
      groupadd $group_name
  fi
}

function add_user(){

  #1.添加一个用户，并指定根目录
  useradd -d /home/$user_name -m $user_name -s /bin/bash 
  
  #2。将用户添加到组（多个时以逗号隔开）,添加时是追加的方式
  usermod -G $group_name $user_name

  #3.设置用户密码
  echo $user_passwd | passwd --stdin $user_name
	
  #4.给普通用户授权sudo
  chmod -v u+w /etc/sudoers
  sed -i '/^'"$user_name"'.*$/d' /etc/sudoers
  tmp_str="$user_name    ALL=(ALL)   ALL"
  sed -i "/^root.*$/a ${tmp_str}"  /etc/sudoers
  chmod -v u-w /etc/sudoers

  #5.给目录赋予权限的可读可写
  for dstr in ${arr_dirs[*]}
  do
     if [ ! -d "$dstr" ]; then
        mkdir -p $dstr
     fi

     chown -R $user_name:docker $dstr     
     chmod -R 755 $dstr
    
  done

}

function add_user_main(){
  #create user if not exists
  egrep "^$user_name" /etc/passwd >& /dev/null
  if [ $? -ne 0 ]
  then
     add_user  
  fi
}

read -r -p "你需要创建一个普通用户（$user_name）吗？[Y/n] " input
  case $input in
      [yY][eE][sS]|[yY])
          #echo -e "\033[32mYes, continue...\033[0m"  
		  add_group
		  add_user_main
		  echo "普通用户 $user_name:$group_name 创建完毕！"
          ;; 
      [nN][oO]|[nN])
         echo -e "\033[33mNo, continue...\033[0m"  
          ;; 
      *)
          echo -e "\033[31m you input isn't yes or no.\n\033[0m"
          ;;
  esac