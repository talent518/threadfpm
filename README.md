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
* 读取并删除共享变量: share_var_get_and_del([$key1,...])
* 写入共享变量(至少一个参数，每个参数代码要查询的多维数组的key，最后一个是数组可与存在数组合并，否则则替换): share_var_put(...)
* 累加共享变量($key[,...]查到的变量：是数组则会把$value附加到数组后，是字符串则在其后附加$value字符串，其它数值类型或布尔值则会按数值累加): share_var_inc($key[,...],$value)
  * 返回运算结果
* 写入共享变量: share_var_set($key[,...], $value)
* 写入过期共享变量: share_var_set_ex($key[,...], $value, $expire)
  * $expire: int 过期时间戳，为0时永不过期
* 删除共享变量: share_var_del($key1[,...])
* 清空共享变量: share_var_clean()
* 统计变量(返回：大于0为数组元素数，小于0为字符长度，true为对象，未找到为null，否则为false): share_var_count([$key1,...])
* 声明线程安全的共享变量: ts_var_declare(string|int $varname, ?resource $var = null, bool $is_fd = false): resource|bool
  * $varname: 变量名
  * $var: 如果为空，则在share_var_中创建，否则在ts_var_declare创建的线程安全共享变量中创建
  * $is_fd: 如果为true，则可以使用ts_var_fd()函数
* 导出socket文件描述符的管道对（可使用sockets扩展中的函数进行操作）：ts_var_fd(resource $var, bool $is_write = false): socket|bool
  * $var: 由ts_var_declare函数返回的变量
  * $is_write: 是返回
* 是否存在指定的共享变量：ts_var_exists(resource $var, string|int $key)
  * $var: 由ts_var_declare函数返回的变量
  * $key: 键名，可为字符串和整形
* 向线程安全变量中存储数据：ts_var_set(resource $var, string|int|null $key, mixed $val, bool $expire = 0): bool
  * $var: 由ts_var_declare函数返回的变量
  * $key: 键名，可为字符串、整形或空，为空时把$val附加到最后
  * $val: 值
  * $expire: 过期时间戳，为0时永不过期
* ts_var_put是ts_var_set的别名
* 压入队列：ts_var_push(resource $var, mixed $val ...): bool
  * $val ...: 同时可以压入多个值
* 弹出队列（线程安全变量）中最后一个：ts_var_pop(resource $var, string|long &$key = null)
  * $key: 是弹出值对应的键
* 弹出队列（线程安全变量）中第一个：ts_var_shift(resource $var, string|long &$key = null)
  * $key: 是弹出值对应的键
* 获取线程安全变量数据：ts_var_get(resource $var, string|int|null $key = null, bool $is_del = false): mixed
  * $var: 由ts_var_declare函数返回的变量
  * $key: 键名，可为字符串、整形或空，为空时返回$var中的所有变量
  * $is_del: 是否删除该变量
* 删除线程安全变量中的数据：ts_var_del(resource $var, string|int $key): bool
  * $var: 由ts_var_declare函数返回的变量
  * $key: 键名，可为字符串或整形
* 自增线程安全变量并返回：ts_var_inc(resource $var, string|int|null $key, mixed $inc): mixed
  * $var: 由ts_var_declare函数返回的变量
  * $key: 键名，可为字符串或整形
  * $inc: 相当于$var[$key] += $inc
* 获取线程安全变量有多少个数据（与count函数类似）：ts_var_count(resource $var)
  * $var: 由ts_var_declare函数返回的变量
* 清理线程安全变量并返回元素个数：ts_var_clean(resource $var, int $expire = 0)
  * $var: 由ts_var_declare函数返回的变量
* 重建线程安全变量索引：ts_var_reindex(resource $var, bool $only_integer_keys = false): bool
  * $var: 由ts_var_declare函数返回的变量
  * $only_integer_keys: 是否紧整数索引
