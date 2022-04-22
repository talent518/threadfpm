<?php
if(!function_exists('ts_var_declare')) die("Not threadfpm\n");

define('LOG_SIZE', 2*1024*1024);
define('LOG_FILE', 'threadfpm.log');
define('LOG_IDX', 'threadfpm.idx');
define('LOG_FMT', 'threadfpm-%02d.log');
define('N', 50);

$running = true;

$sighandle = function($sig) use(&$running) {
	$running = false;
	echo "SIG: $sig\n";
};

pcntl_async_signals(true);
pcntl_signal(SIGTERM, $sighandle, false);
pcntl_signal(SIGINT, $sighandle, false);
pcntl_signal(SIGUSR1, $sighandle, false);
pcntl_signal(SIGUSR2, $sighandle, false);

$logVar = ts_var_declare('logger', null, true);
$logFd = ts_var_fd($logVar);

$fp = fopen(LOG_FILE, 'a');

$line = str_repeat('-', N);
$line2 = str_repeat('=', N);

$nlog = (int) @file_get_contents(LOG_IDX);

echo "phpfile begin\n";
while($running || ts_var_count($logVar)) {
	$reads = [$logFd];
	$writes = $excepts = [];
	if(!@socket_select($reads, $writes, $excepts, 1)) {
		continue;
	}
	
	$n = strlen(socket_read($logFd, 128)?:'');
	
	for($i=0; $i<$n; $i++) {
		$log = ts_var_shift($logVar, $key);
		fwrite($fp, "$line2\nKEY: $key\n");
		if(is_array($log) || is_object($log)) {
			foreach($log as $k=>$v) {
				$k = strtoupper($k);
				$v = format($v);
				if(strpos($v, "\n")) {
					$v = "\n$v";
				}
				fwrite($fp, "$line\n$k: $v\n");
			}
		} else {
			fwrite($fp, "$log\n");
		}
		fwrite($fp, "\n");
	}

	$i = strlen((string) $n);
	$pi = (int) ((N - 2 - $i) / 2);
	$prefix = str_repeat('=', $pi);
	$suffix = str_repeat('=', N - 2 - $i - $pi);
	fwrite($fp, "$prefix $n $suffix\n");
	fflush($fp);
	
	if(ftell($fp) > LOG_SIZE) {
		fclose($fp);
		$nlog++;
		if($nlog > 50) {
			$nlog = 1;
		}
		file_put_contents(LOG_IDX, $nlog);
		rename(LOG_FILE, sprintf(LOG_FMT, $nlog));
		$fp = fopen(LOG_FILE, 'a');
	}
}
echo "phpfile end\n";

function format($v) {
	if(is_array($v) || is_object($v)) {
		return var_export($v, true);
	} else {
		return (string) $v;
	}
}

