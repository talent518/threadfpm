# threadfpm
php多线程fastcgi的sapi扩展。

### 编译
* 放到php源码目录的sapi目录下
* 执行重新构建configure宏配置脚本的命令: ./buildconf -f
* 执行编译脚本: ./sapi/threadtask/build.sh
* 运行: /opt/phpts/sbin/threadfpm -t 128
* php.ini配置中opcache.protect_memory=0，如果设置为1会导航段错误，原因：这个参数是非线程安全的开关

