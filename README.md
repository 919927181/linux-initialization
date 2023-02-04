# linux-initialization
linux系统初始化设置，包含内核参数、时区、安全加固等

### . 用途：
适用于企业内部 CentOS7 系列服务器初始化、系统安全加固 参考：https://github.com/WeiyiGeek/SecOpsDev/tree/master/OS-%E6%93%8D%E4%BD%9C%E7%B3%BB%E7%BB%9F/Linux

### . 问题：
若设置了用户登陆超时，执行 source /etc/profile时报错 -bash: TMOUT: readonly variable，解决方法是 vi /etc/profile将#export TMOUT #readonly TMOUT 注释掉。

注意：设置了密码90天过期，记得到期前更改密码喔！！！
