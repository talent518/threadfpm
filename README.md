# threadfpm
php多线程fastcgi的sapi扩展，优点是占用内存少且稳定，避免出现502错误。

### 编译
* 放到php源码目录的sapi目录下
* 执行重新构建configure宏配置脚本的命令: ./buildconf -f
* 执行编译脚本: ./sapi/threadtask/build.sh
* 运行: /opt/phpts/sbin/threadfpm -t 128
* php.ini配置中opcache.protect_memory=0，如果设置为1会导致段错误，原因：这个参数是非线程安全的开关
* 重启信号SIGUSR1,SIGUSR2: kill -SIGUSR1 pid

### 函数说明
* 是否存在指定的共享变量: share_var_exists($key1[,...])
* 读取共享变量: share_var_get([$key1,...])
* 写入共享变量(至少一个参数，每个参数代码要查询的多维数组的key，最后一个是数组可与存在数组合并，否则则替换): share_var_put(...)
* 累加共享变量($key[,...]查到的变量：是数组则会把$value附加到数组后，是字符串则在其后附加$value字符串，其它数值类型或布尔值则会按数值累加): share_var_inc($key[,...],$value)
  * 返回运算结果
* 写入共享变量: share_var_set($key[,...], $value)
* 写入过期共享变量: share_var_set_ex($key[,...], $value, $expire)
  * $expire: int 过期时间戳，为0时永不过期
* 删除共享变量: share_var_del($key1[,...])
* 清空共享变量: share_var_clean()

