/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Rasmus Lerdorf <rasmus@lerdorf.on.ca>                       |
   |          Stig Bakken <ssb@php.net>                                   |
   |          Zeev Suraski <zeev@php.net>                                 |
   | FastCGI: Ben Mansell <php@slimyhorror.com>                           |
   |          Shane Caraveo <shane@caraveo.com>                           |
   |          Dmitry Stogov <dmitry@php.net>                              |
   +----------------------------------------------------------------------+
*/

#include <stdio.h>
#include <stdlib.h>

#include "php.h"
#include "php_globals.h"
#include "php_variables.h"
#include "zend_modules.h"
#include "php.h"
#include "zend_ini_scanner.h"
#include "zend_globals.h"
#include "zend_stream.h"
#include "zend_types.h"
#include "php_ticks.h"
#include "zend_exceptions.h"
#include "rfc1867.h"

#include "SAPI.h"

#include <stdio.h>
#include "php.h"

#if HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <signal.h>

#include <locale.h>

#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#if HAVE_NETDB_H
# include <netdb.h>
#endif

#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#if HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <sys/prctl.h>
#include <time.h>
#include <syslog.h>
#include <semaphore.h>

#include "zend.h"
#include "zend_extensions.h"
#include "zend_smart_str.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"
#include "fopen_wrappers.h"
#include "ext/standard/php_standard.h"
#include "ext/standard/php_var.h"
#include "ext/sockets/php_sockets.h"

#ifdef __riscos__
# include <unixlib/local.h>
int __riscosify_control = __RISCOSIFY_STRICT_UNIX_SPECS;
#endif

#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_highlight.h"

#include "php_getopt.h"

#include "http_status_codes.h"

#include "fastcgi.h"

#include <php_config.h>

#ifdef HAVE_SYSEXITS_H
#include <sysexits.h>
#endif

#ifdef EX_OK
#define FPM_EXIT_OK EX_OK
#else
#define FPM_EXIT_OK 0
#endif

#ifdef EX_USAGE
#define FPM_EXIT_USAGE EX_USAGE
#else
#define FPM_EXIT_USAGE 64
#endif

#ifdef EX_SOFTWARE
#define FPM_EXIT_SOFTWARE EX_SOFTWARE
#else
#define FPM_EXIT_SOFTWARE 70
#endif

#ifdef EX_CONFIG
#define FPM_EXIT_CONFIG EX_CONFIG
#else
#define FPM_EXIT_CONFIG 78
#endif

// ------------------------------------------------------------

#ifndef Z_PARAM_RESOURCE_OR_NULL
	#define Z_PARAM_RESOURCE_OR_NULL(dest) \
		Z_PARAM_RESOURCE_EX(dest, 1, 0)
#endif

#ifndef Z_PARAM_ZVAL_DEREF
	#define Z_PARAM_ZVAL_DEREF(dest) Z_PARAM_ZVAL_EX2(dest, 0, 1, 0)
#endif

#ifndef Z_PARAM_STR_OR_LONG_EX
	#define Z_PARAM_STR_OR_LONG_EX(dest_str, dest_long, is_null, allow_null) \
		Z_PARAM_PROLOGUE(0, 0); \
		if (UNEXPECTED(!zend_parse_arg_str_or_long(_arg, &dest_str, &dest_long, &is_null, allow_null))) { \
			_expected_type = Z_EXPECTED_STRING; \
			_error_code = ZPP_ERROR_WRONG_ARG; \
			break; \
		}

	#define Z_PARAM_STR_OR_LONG(dest_str, dest_long) \
		Z_PARAM_STR_OR_LONG_EX(dest_str, dest_long, _dummy, 0);

	#define Z_PARAM_STR_OR_LONG_OR_NULL(dest_str, dest_long, is_null) \
		Z_PARAM_STR_OR_LONG_EX(dest_str, dest_long, is_null, 1);

	static zend_always_inline int zend_parse_arg_str_or_long(zval *arg, zend_string **dest_str, zend_long *dest_long,
		zend_bool *is_null, int allow_null)
	{
		if (allow_null) {
			*is_null = 0;
		}
		if (EXPECTED(Z_TYPE_P(arg) == IS_STRING)) {
			*dest_str = Z_STR_P(arg);
			return 1;
		} else if (EXPECTED(Z_TYPE_P(arg) == IS_LONG)) {
			*dest_str = NULL;
			*dest_long = Z_LVAL_P(arg);
			return 1;
		} else if (allow_null && EXPECTED(Z_TYPE_P(arg) == IS_NULL)) {
			*dest_str = NULL;
			*is_null = 1;
			return 1;
		} else {
			if (zend_parse_arg_long_weak(arg, dest_long)) {
				*dest_str = NULL;
				return 1;
			} else if (zend_parse_arg_str_weak(arg, dest_str)) {
				*dest_long = 0;
				return 1;
			} else {
				return 0;
			}
		}
	}
#endif

// ------------------------------------------------------------

#include "hash.h"

/* XXX this will need to change later when threaded fastcgi is implemented.  shane */
struct sigaction act, old_term, old_quit, old_int;

static void (*php_php_import_environment_variables)(zval *array_ptr);

/* these globals used for forking children on unix systems */

/**
 * Set to non-zero if we are the parent process
 */
static int parent = 1;

static int fpm_is_running = 0;

static char *sapi_cgibin_getenv(const char *name, size_t name_len);

#define PHP_MODE_STANDARD	1
#define PHP_MODE_HIGHLIGHT	2
#define PHP_MODE_INDENT		3
#define PHP_MODE_LINT		4
#define PHP_MODE_STRIP		5

static char *php_optarg = NULL;
static int php_optind = 1;
static zend_module_entry cgi_module_entry;

static const opt_struct OPTIONS[] = {
	{'c', 1, "php-ini"},
	{'d', 1, "define"},
	{'e', 0, "profile-info"},
	{'h', 0, "help"},
	{'i', 0, "info"},
	{'m', 0, "modules"},
	{'n', 0, "no-php-ini"},
	{'?', 0, "usage"},/* help alias (both '?' and 'usage') */
	{'v', 0, "version"},
	{'R', 0, "realpath"},
	{'P', 1, "pid"},
	{'u', 1, "user"},
	{'a', 1, "accepts"},
	{'t', 1, "threads"},
	{'I', 1, "idle-seconds"},
	{'r', 1, "max-requests"},
	{'p', 1, "path"},
	{'b', 1, "backlog"},
#ifdef THREADFPM_DEBUG
	{'D', 0, "debug"},
#endif
	{'A', 0, "access"},
	{'-', 0, NULL} /* end of args */
};

typedef struct _php_cgi_globals_struct {
	zend_bool rfc2616_headers;
	zend_bool nph;
	zend_bool fix_pathinfo;
	zend_bool force_redirect;
	zend_bool discard_path;
	zend_bool fcgi_logging;
	int body_fd;
	char strftime[20]; // 2020-11-08 09:42:30
	zend_bool is_accept;
	unsigned long int response_length;
	char *redirect_status_env;
	HashTable user_config_cache;
	char *error_header;
} php_cgi_globals_struct;

/* {{{ user_config_cache
 *
 * Key for each cache entry is dirname(PATH_TRANSLATED).
 *
 * NOTE: Each cache entry config_hash contains the combination from all user ini files found in
 *       the path starting from doc_root through to dirname(PATH_TRANSLATED).  There is no point
 *       storing per-file entries as it would not be possible to detect added / deleted entries
 *       between separate files.
 */
typedef struct _user_config_cache_entry {
	time_t expires;
	HashTable user_config;
} user_config_cache_entry;

static void user_config_cache_entry_dtor(zval *el)
{
	user_config_cache_entry *entry = (user_config_cache_entry *)Z_PTR_P(el);
	zend_hash_destroy(&entry->user_config);
	free(entry);
}
/* }}} */

static int php_cgi_globals_id;
#define CGIG(v) ZEND_TSRMG(php_cgi_globals_id, php_cgi_globals_struct *, v)

const char *gettimeofstr() {
	time_t t;
	struct tm *tmp;

	t = time(NULL);
	tmp = localtime(&t);
	if (tmp == NULL) {
		perror("localtime error");
		return "";
	}

	if (strftime(CGIG(strftime), sizeof(CGIG(strftime)), "%F %T", tmp) == 0) {
		perror("strftime error");
		return "";
	}

	return CGIG(strftime);
}

static int module_name_cmp(Bucket *f, Bucket *s) /* {{{ */
{
	return strcasecmp(	((zend_module_entry *) Z_PTR(f->val))->name,
						((zend_module_entry *) Z_PTR(s->val))->name);
}
/* }}} */

static void print_modules(void) /* {{{ */
{
	HashTable sorted_registry;
	zend_module_entry *module;

	zend_hash_init(&sorted_registry, 50, NULL, NULL, 1);
	zend_hash_copy(&sorted_registry, &module_registry, NULL);
	zend_hash_sort(&sorted_registry, module_name_cmp, 0);
	ZEND_HASH_FOREACH_PTR(&sorted_registry, module) {
		php_printf("%s\n", module->name);
	} ZEND_HASH_FOREACH_END();
	zend_hash_destroy(&sorted_registry);
}
/* }}} */

static void print_extension_info(zend_extension *ext) /* {{{ */
{
	php_printf("%s\n", ext->name);
}
/* }}} */

static int extension_name_cmp(const zend_llist_element **f, const zend_llist_element **s) /* {{{ */
{
	zend_extension *fe = (zend_extension*)(*f)->data;
	zend_extension *se = (zend_extension*)(*s)->data;
	return strcmp(fe->name, se->name);
}
/* }}} */

static void print_extensions(void) /* {{{ */
{
	zend_llist sorted_exts;

	zend_llist_copy(&sorted_exts, &zend_extensions);
	sorted_exts.dtor = NULL;
	zend_llist_sort(&sorted_exts, extension_name_cmp);
	zend_llist_apply(&sorted_exts, (llist_apply_func_t) print_extension_info);
	zend_llist_destroy(&sorted_exts);
}
/* }}} */

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif


struct pthread_fake {
	void *nothing[90];
	pid_t tid;
	pid_t pid;
};

#define pthread_tid ((struct pthread_fake*) pthread_self())->tid
#define pthread_pid getpid() // ((struct pthread_fake*) pthread_self())->pid

#ifdef THREADFPM_DEBUG
#	define dprintf(fmt, args...) if(UNEXPECTED(isDebug)) {fprintf(stderr, "[%s] %d " fmt, gettimeofstr(), pthread_tid, ##args);fflush(stderr);}
	static zend_bool isDebug = 0;
#else
#	define dprintf(...)
#endif

static inline size_t sapi_cgibin_single_write(const char *str, uint32_t str_length) /* {{{ */
{
	ssize_t ret;

	/* sapi has started which means everyhting must be send through fcgi */
	if (fpm_is_running) {
		fcgi_request *request = (fcgi_request*) SG(server_context);

		ret = fcgi_write(request, FCGI_STDOUT, str, str_length);
		if (ret <= 0) {
			return 0;
		}

		return (size_t)ret;
	}

	/* sapi has not started, output to stdout instead of fcgi */
#ifdef PHP_WRITE_STDOUT
	ret = write(STDOUT_FILENO, str, str_length);
	if (ret <= 0) {
		return 0;
	}
	return (size_t)ret;
#else
	return fwrite(str, 1, MIN(str_length, 16384), stdout);
#endif
}
/* }}} */

static size_t sapi_cgibin_ub_write(const char *str, size_t str_length) /* {{{ */
{
	const char *ptr = str;
	uint32_t remaining = str_length;
	size_t ret;

	CGIG(response_length) += str_length;

	while (remaining > 0) {
		ret = sapi_cgibin_single_write(ptr, remaining);
		if (!ret) {
			php_handle_aborted_connection();
			return str_length - remaining;
		}
		ptr += ret;
		remaining -= ret;
	}

	return str_length;
}
/* }}} */

static void sapi_cgibin_flush(void *server_context) /* {{{ */
{
	/* fpm has started, let use fcgi instead of stdout */
	if (fpm_is_running) {
		fcgi_request *request = (fcgi_request*) server_context;
		if (!parent && request && !fcgi_flush(request, 0)) {
			php_handle_aborted_connection();
		}
		return;
	}

	/* fpm has not started yet, let use stdout instead of fcgi */
	if (fflush(stdout) == EOF) {
		php_handle_aborted_connection();
	}
}
/* }}} */

#define SAPI_CGI_MAX_HEADER_LENGTH 1024

static int sapi_cgi_send_headers(sapi_headers_struct *sapi_headers) /* {{{ */
{
	char buf[SAPI_CGI_MAX_HEADER_LENGTH];
	sapi_header_struct *h;
	zend_llist_position pos;
	zend_bool ignore_status = 0;
	int response_status = sapi_headers->http_response_code;

	if (SG(request_info).no_headers == 1) {
		return  SAPI_HEADER_SENT_SUCCESSFULLY;
	}

	if (CGIG(nph) || sapi_headers->http_response_code != 200)
	{
		int len;
		zend_bool has_status = 0;

		if (CGIG(rfc2616_headers) && sapi_headers->http_status_line) {
			char *s;
			len = slprintf(buf, SAPI_CGI_MAX_HEADER_LENGTH, "%s\r\n", sapi_headers->http_status_line);
			if ((s = strchr(sapi_headers->http_status_line, ' '))) {
				response_status = atoi((s + 1));
			}

			if (len > SAPI_CGI_MAX_HEADER_LENGTH) {
				len = SAPI_CGI_MAX_HEADER_LENGTH;
			}

		} else {
			char *s;

			if (sapi_headers->http_status_line &&
				(s = strchr(sapi_headers->http_status_line, ' ')) != 0 &&
				(s - sapi_headers->http_status_line) >= 5 &&
				strncasecmp(sapi_headers->http_status_line, "HTTP/", 5) == 0
			) {
				len = slprintf(buf, sizeof(buf), "Status:%s\r\n", s);
				response_status = atoi((s + 1));
			} else {
				h = (sapi_header_struct*)zend_llist_get_first_ex(&sapi_headers->headers, &pos);
				while (h) {
					if (h->header_len > sizeof("Status:") - 1 &&
						strncasecmp(h->header, "Status:", sizeof("Status:") - 1) == 0
					) {
						has_status = 1;
						break;
					}
					h = (sapi_header_struct*)zend_llist_get_next_ex(&sapi_headers->headers, &pos);
				}
				if (!has_status) {
					http_response_status_code_pair *err = (http_response_status_code_pair*)http_status_map;

					while (err->code != 0) {
						if (err->code == sapi_headers->http_response_code) {
							break;
						}
						err++;
					}
					if (err->str) {
						len = slprintf(buf, sizeof(buf), "Status: %d %s\r\n", sapi_headers->http_response_code, err->str);
					} else {
						len = slprintf(buf, sizeof(buf), "Status: %d\r\n", sapi_headers->http_response_code);
					}
				}
			}
		}

		if (!has_status) {
			PHPWRITE_H(buf, len);
			ignore_status = 1;
		}
	}

	h = (sapi_header_struct*)zend_llist_get_first_ex(&sapi_headers->headers, &pos);
	while (h) {
		/* prevent CRLFCRLF */
		if (h->header_len) {
			if (h->header_len > sizeof("Status:") - 1 &&
				strncasecmp(h->header, "Status:", sizeof("Status:") - 1) == 0
			) {
				if (!ignore_status) {
					ignore_status = 1;
					PHPWRITE_H(h->header, h->header_len);
					PHPWRITE_H("\r\n", 2);
				}
			} else if (response_status == 304 && h->header_len > sizeof("Content-Type:") - 1 &&
				strncasecmp(h->header, "Content-Type:", sizeof("Content-Type:") - 1) == 0
			) {
				h = (sapi_header_struct*)zend_llist_get_next_ex(&sapi_headers->headers, &pos);
				continue;
			} else {
				PHPWRITE_H(h->header, h->header_len);
				PHPWRITE_H("\r\n", 2);
			}
		}
		h = (sapi_header_struct*)zend_llist_get_next_ex(&sapi_headers->headers, &pos);
	}
	PHPWRITE_H("\r\n", 2);

	return SAPI_HEADER_SENT_SUCCESSFULLY;
}
/* }}} */

#ifndef STDIN_FILENO
# define STDIN_FILENO 0
#endif

#ifndef HAVE_ATTRIBUTE_WEAK
static void fpm_fcgi_log(int type, const char *fmt, ...) /* {{{ */
#else
void fcgi_log(int type, const char *fmt, ...)
#endif
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}
/* }}} */

static size_t sapi_cgi_read_post(char *buffer, size_t count_bytes) /* {{{ */
{
	uint32_t read_bytes = 0;
	int tmp_read_bytes;
	size_t remaining = SG(request_info).content_length - SG(read_post_bytes);

	dprintf("read_post %lu\n", remaining);

	if (remaining < count_bytes) {
		count_bytes = remaining;
	}
	while (read_bytes < count_bytes) {
		fcgi_request *request = (fcgi_request*) SG(server_context);

		if (CGIG(body_fd) == -1) {
			char *request_body_filename = FCGI_GETENV(request, "REQUEST_BODY_FILE");

			if (request_body_filename && *request_body_filename) {
				CGIG(body_fd) = open(request_body_filename, O_RDONLY);

				if (0 > CGIG(body_fd)) {
					php_error(E_WARNING, "REQUEST_BODY_FILE: open('%s') failed: %s (%d)",
							request_body_filename, strerror(errno), errno);
					return 0;
				}
			}
		}

		/* If REQUEST_BODY_FILE variable not available - read post body from fastcgi stream */
		if (CGIG(body_fd) < 0) {
			tmp_read_bytes = fcgi_read(request, buffer + read_bytes, count_bytes - read_bytes);
		} else {
			tmp_read_bytes = read(CGIG(body_fd), buffer + read_bytes, count_bytes - read_bytes);
		}
		if (tmp_read_bytes <= 0) {
			break;
		}
		read_bytes += tmp_read_bytes;
	}

	return read_bytes;
}
/* }}} */

static char *sapi_cgibin_getenv(const char *name, size_t name_len) /* {{{ */
{
	/* if fpm has started, use fcgi env */
	if (fpm_is_running) {
		fcgi_request *request = (fcgi_request*) SG(server_context);
		return fcgi_getenv(request, name, name_len);
	}

	/* if fpm has not started yet, use std env */
	return getenv(name);
}
/* }}} */

static char *sapi_cgi_read_cookies(void) /* {{{ */
{
	fcgi_request *request = (fcgi_request*) SG(server_context);

	return FCGI_GETENV(request, "HTTP_COOKIE");
}
/* }}} */

static void cgi_php_load_env_var(const char *var, unsigned int var_len, char *val, unsigned int val_len, void *arg) /* {{{ */
{
	zval *array_ptr = (zval *) arg;
	int filter_arg = (Z_ARR_P(array_ptr) == Z_ARR(PG(http_globals)[TRACK_VARS_ENV])) ? PARSE_ENV : PARSE_SERVER;
	size_t new_val_len;

	if (sapi_module.input_filter(filter_arg, var, &val, strlen(val), &new_val_len)) {
		php_register_variable_safe(var, val, new_val_len, array_ptr);
	}
}
/* }}} */

void cgi_php_import_environment_variables(zval *array_ptr) /* {{{ */
{
	fcgi_request *request = NULL;
	zval *zg = PG(http_globals);

	if (Z_TYPE(zg[TRACK_VARS_ENV]) == IS_ARRAY &&
		Z_ARR_P(array_ptr) != Z_ARR(zg[TRACK_VARS_ENV]) &&
		zend_hash_num_elements(Z_ARRVAL(zg[TRACK_VARS_ENV])) > 0
	) {
		zend_array_destroy(Z_ARR_P(array_ptr));
		Z_ARR_P(array_ptr) = zend_array_dup(Z_ARR(zg[TRACK_VARS_ENV]));
		return;
	} else if (Z_TYPE(zg[TRACK_VARS_SERVER]) == IS_ARRAY &&
		Z_ARR_P(array_ptr) != Z_ARR(zg[TRACK_VARS_SERVER]) &&
		zend_hash_num_elements(Z_ARRVAL(zg[TRACK_VARS_SERVER])) > 0
	) {
		zend_array_destroy(Z_ARR_P(array_ptr));
		Z_ARR_P(array_ptr) = zend_array_dup(Z_ARR(zg[TRACK_VARS_SERVER]));
		return;
	}

	/* call php's original import as a catch-all */
	php_php_import_environment_variables(array_ptr);

	request = (fcgi_request*) SG(server_context);
	fcgi_loadenv(request, cgi_php_load_env_var, array_ptr);
}
/* }}} */

static void sapi_cgi_register_variables(zval *track_vars_array) /* {{{ */
{
	size_t php_self_len;
	char *php_self;

	/* In CGI mode, we consider the environment to be a part of the server
	 * variables
	 */
	php_import_environment_variables(track_vars_array);

	if (CGIG(fix_pathinfo)) {
		char *script_name = SG(request_info).request_uri;
		unsigned int script_name_len = script_name ? strlen(script_name) : 0;
		char *path_info = sapi_cgibin_getenv("PATH_INFO", sizeof("PATH_INFO") - 1);
		unsigned int path_info_len = path_info ? strlen(path_info) : 0;

		php_self_len = script_name_len + path_info_len;
		php_self = emalloc(php_self_len + 1);

		/* Concat script_name and path_info into php_self */
		if (script_name) {
			memcpy(php_self, script_name, script_name_len + 1);
		}
		if (path_info) {
			memcpy(php_self + script_name_len, path_info, path_info_len + 1);
		}

		/* Build the special-case PHP_SELF variable for the CGI version */
		if (sapi_module.input_filter(PARSE_SERVER, "PHP_SELF", &php_self, php_self_len, &php_self_len)) {
			php_register_variable_safe("PHP_SELF", php_self, php_self_len, track_vars_array);
		}
		efree(php_self);
	} else {
		php_self = SG(request_info).request_uri;
		if(!php_self) php_self = "";
		php_self_len = strlen(php_self);
		if (sapi_module.input_filter(PARSE_SERVER, "PHP_SELF", &php_self, php_self_len, &php_self_len)) {
			php_register_variable_safe("PHP_SELF", php_self, php_self_len, track_vars_array);
		}
	}
}
/* }}} */

/* {{{ sapi_cgi_log_fastcgi
 *
 * Ignore level, we want to send all messages through fastcgi
 */
void sapi_cgi_log_fastcgi(int level, char *message, size_t len)
{

	fcgi_request *request = (fcgi_request*) SG(server_context);

	/* message is written to FCGI_STDERR if following conditions are met:
	 * - logging is enabled (fastcgi.logging in php.ini)
	 * - we are currently dealing with a request
	 * - the message is not empty
	 * - the fcgi_write did not fail
	 */
	if (CGIG(fcgi_logging) && request && message && len > 0
			&& fcgi_write(request, FCGI_STDERR, message, len) < 0) {
		php_handle_aborted_connection();
	}
}
/* }}} */

/* {{{ sapi_cgi_log_message
 */
static void sapi_cgi_log_message(const char *message, int syslog_type_int)
{
	fprintf(stderr, "PHP message: %s\n", message);
}
/* }}} */

/* {{{ php_cgi_ini_activate_user_config
 */
static void php_cgi_ini_activate_user_config(char *path, int path_len, const char *doc_root, int doc_root_len)
{
	char *ptr;
	time_t request_time = sapi_get_request_time();
	user_config_cache_entry *entry = zend_hash_str_find_ptr(&CGIG(user_config_cache), path, path_len);

	/* Find cached config entry: If not found, create one */
	if (!entry) {
		entry = pemalloc(sizeof(user_config_cache_entry), 1);
		entry->expires = 0;
		zend_hash_init(&entry->user_config, 0, NULL, config_zval_dtor, 1);
		zend_hash_str_update_ptr(&CGIG(user_config_cache), path, path_len, entry);
	}

	/* Check whether cache entry has expired and rescan if it is */
	if (request_time > entry->expires) {
		char * real_path;
		int real_path_len;
		char *s1, *s2;
		int s_len;

		/* Clear the expired config */
		zend_hash_clean(&entry->user_config);

		if (!IS_ABSOLUTE_PATH(path, path_len)) {
			real_path = tsrm_realpath(path, NULL);
			if (real_path == NULL) {
				return;
			}
			real_path_len = strlen(real_path);
			path = real_path;
			path_len = real_path_len;
		}

		if (path_len > doc_root_len) {
			s1 = (char *) doc_root;
			s2 = path;
			s_len = doc_root_len;
		} else {
			s1 = path;
			s2 = (char *) doc_root;
			s_len = path_len;
		}

		/* we have to test if path is part of DOCUMENT_ROOT.
		  if it is inside the docroot, we scan the tree up to the docroot
			to find more user.ini, if not we only scan the current path.
		  */
		if (strncmp(s1, s2, s_len) == 0) {
			ptr = s2 + doc_root_len;
			while ((ptr = strchr(ptr, DEFAULT_SLASH)) != NULL) {
				*ptr = 0;
				php_parse_user_ini_file(path, PG(user_ini_filename), &entry->user_config);
				*ptr = '/';
				ptr++;
			}
		} else {
			php_parse_user_ini_file(path, PG(user_ini_filename), &entry->user_config);
		}

		entry->expires = request_time + PG(user_ini_cache_ttl);
	}

	/* Activate ini entries with values from the user config hash */
	php_ini_activate_config(&entry->user_config, PHP_INI_PERDIR, PHP_INI_STAGE_HTACCESS);
}
/* }}} */

static int sapi_cgi_activate(void) /* {{{ */
{
	fcgi_request *request = (fcgi_request*) SG(server_context);
	char *path, *doc_root, *server_name;
	uint32_t path_len, doc_root_len, server_name_len;

	/* PATH_TRANSLATED should be defined at this stage but better safe than sorry :) */
	if (!SG(request_info).path_translated) {
		return FAILURE;
	}

	if (php_ini_has_per_host_config()) {
		/* Activate per-host-system-configuration defined in php.ini and stored into configuration_hash during startup */
		server_name = FCGI_GETENV(request, "SERVER_NAME");
		/* SERVER_NAME should also be defined at this stage..but better check it anyway */
		if (server_name) {
			server_name_len = strlen(server_name);
			server_name = estrndup(server_name, server_name_len);
			zend_str_tolower(server_name, server_name_len);
			php_ini_activate_per_host_config(server_name, server_name_len);
			efree(server_name);
		}
	}

	if (php_ini_has_per_dir_config() ||
		(PG(user_ini_filename) && *PG(user_ini_filename))
	) {
		/* Prepare search path */
		path_len = strlen(SG(request_info).path_translated);

		/* Make sure we have trailing slash! */
		if (!IS_SLASH(SG(request_info).path_translated[path_len])) {
			path = emalloc(path_len + 2);
			memcpy(path, SG(request_info).path_translated, path_len + 1);
			path_len = zend_dirname(path, path_len);
			path[path_len++] = DEFAULT_SLASH;
		} else {
			path = estrndup(SG(request_info).path_translated, path_len);
			path_len = zend_dirname(path, path_len);
		}
		path[path_len] = 0;

		/* Activate per-dir-system-configuration defined in php.ini and stored into configuration_hash during startup */
		php_ini_activate_per_dir_config(path, path_len); /* Note: for global settings sake we check from root to path */

		/* Load and activate user ini files in path starting from DOCUMENT_ROOT */
		if (PG(user_ini_filename) && *PG(user_ini_filename)) {
			doc_root = FCGI_GETENV(request, "DOCUMENT_ROOT");
			/* DOCUMENT_ROOT should also be defined at this stage..but better check it anyway */
			if (doc_root) {
				doc_root_len = strlen(doc_root);
				if (doc_root_len > 0 && IS_SLASH(doc_root[doc_root_len - 1])) {
					--doc_root_len;
				}

				php_cgi_ini_activate_user_config(path, path_len, doc_root, doc_root_len);
			}
		}

		efree(path);
	}

	return SUCCESS;
}
/* }}} */

static int sapi_cgi_deactivate(void) /* {{{ */
{
	/* flush only when SAPI was started. The reasons are:
		1. SAPI Deactivate is called from two places: module init and request shutdown
		2. When the first call occurs and the request is not set up, flush fails on FastCGI.
	*/
	if (SG(sapi_started) && SG(server_context)) {
		if (!parent && !fcgi_finish_request((fcgi_request*)SG(server_context), 0)) {
			php_handle_aborted_connection();
		}
	}
	return SUCCESS;
}
/* }}} */

static int php_cgi_startup(sapi_module_struct *sapi_module) /* {{{ */
{
	if (php_module_startup(sapi_module, &cgi_module_entry, 1) == FAILURE) {
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ sapi_module_struct cgi_sapi_module
 */
static sapi_module_struct cgi_sapi_module = {
	"fpm-fcgi",						/* name */
	"FPM/FastCGI",					/* pretty name */

	php_cgi_startup,				/* startup */
	php_module_shutdown_wrapper,	/* shutdown */

	sapi_cgi_activate,				/* activate */
	sapi_cgi_deactivate,			/* deactivate */

	sapi_cgibin_ub_write,			/* unbuffered write */
	sapi_cgibin_flush,				/* flush */
	NULL,							/* get uid */
	sapi_cgibin_getenv,				/* getenv */

	php_error,						/* error handler */

	NULL,							/* header handler */
	sapi_cgi_send_headers,			/* send headers handler */
	NULL,							/* send header handler */

	sapi_cgi_read_post,				/* read POST data */
	sapi_cgi_read_cookies,			/* read Cookies */

	sapi_cgi_register_variables,	/* register server variables */
	sapi_cgi_log_message,			/* Log message */
	NULL,							/* Get request time */
	NULL,							/* Child terminate */

	STANDARD_SAPI_MODULE_PROPERTIES
};
/* }}} */

/* {{{ php_cgi_usage
 */
static void php_cgi_usage(char *argv0)
{
	char *prog;

	prog = strrchr(argv0, '/');
	if (prog) {
		prog++;
	} else {
		prog = "php";
	}

	php_printf(	"Usage: %s [-n] [-e] [-h] [-i] [-m] [-v] [-R] [[-P <pidfile>] -u <user>] [-a <accepts>] [-t <threads>] [-I <idleseconds>] [-r <max requests>] [-p <path>|<host:port>] [-b backlog]"
			#ifdef THREADFPM_DEBUG
				" [-D]"
			#endif
				" [-A]\n"
				"  -c <path>|<file>  Look for php.ini file in this directory\n"
				"  -n                No php.ini file will be used\n"
				"  -d foo[=bar]      Define INI entry foo with value 'bar'\n"
				"  -e                Generate extended information for debugger/profiler\n"
				"  -h                This help\n"
				"  -i                PHP information\n"
				"  -m                Show compiled in modules\n"
				"  -v                Version number\n"
				"  -R                Enable realpath\n"
	         	"  -P <pidfile>      Output pid to file\n"
	         	"  -u <user>         User name for system\n"
	         	"  -a <accepts>      Accept threads\n"
	         	"  -t <threads>      Max worker threads\n"
	         	"  -I <idleseconds>  Automatically kill threads with space idleseconds seconds.\n"
	         	"  -r <max requests> Automatically restart the program when it is idle and exceeds the maximum number of requests\n"
				"  -p <path>         Listen for unix socket\n"
				"  -p <host:port>    Listen for tcp"
				"  -b backlog        The backlog argument defines the maximum length to which the queue of pending connections for sockfd may grow.\n"
			#ifdef THREADFPM_DEBUG
				"  -D                Debug info\n"
			#endif
				"  -A                Access info\n"
				, prog);
}
/* }}} */

/* {{{ is_valid_path
 *
 * some server configurations allow '..' to slip through in the
 * translated path.   We'll just refuse to handle such a path.
 */
static int is_valid_path(const char *path)
{
	const char *p;

	if (!path) {
		return 0;
	}
	p = strstr(path, "..");
	if (p) {
		if ((p == path || IS_SLASH(*(p-1))) &&
			(*(p+2) == 0 || IS_SLASH(*(p+2)))
		) {
			return 0;
		}
		while (1) {
			p = strstr(p+1, "..");
			if (!p) {
				break;
			}
			if (IS_SLASH(*(p-1)) &&
				(*(p+2) == 0 || IS_SLASH(*(p+2)))
			) {
					return 0;
			}
		}
	}
	return 1;
}
/* }}} */

/* {{{ init_request_info

  initializes request_info structure

  specificly in this section we handle proper translations
  for:

  PATH_INFO
	derived from the portion of the URI path following
	the script name but preceding any query data
	may be empty

  PATH_TRANSLATED
    derived by taking any path-info component of the
	request URI and performing any virtual-to-physical
	translation appropriate to map it onto the server's
	document repository structure

	empty if PATH_INFO is empty

	The env var PATH_TRANSLATED **IS DIFFERENT** than the
	request_info.path_translated variable, the latter should
	match SCRIPT_FILENAME instead.

  SCRIPT_NAME
    set to a URL path that could identify the CGI script
	rather than the interpreter.  PHP_SELF is set to this

  REQUEST_URI
    uri section following the domain:port part of a URI

  SCRIPT_FILENAME
    The virtual-to-physical translation of SCRIPT_NAME (as per
	PATH_TRANSLATED)

  These settings are documented at
  http://cgi-spec.golux.com/


  Based on the following URL request:

  http://localhost/info.php/test?a=b

  should produce, which btw is the same as if
  we were running under mod_cgi on apache (ie. not
  using ScriptAlias directives):

  PATH_INFO=/test
  PATH_TRANSLATED=/docroot/test
  SCRIPT_NAME=/info.php
  REQUEST_URI=/info.php/test?a=b
  SCRIPT_FILENAME=/docroot/info.php
  QUERY_STRING=a=b

  but what we get is (cgi/mod_fastcgi under apache):

  PATH_INFO=/info.php/test
  PATH_TRANSLATED=/docroot/info.php/test
  SCRIPT_NAME=/php/php-cgi  (from the Action setting I suppose)
  REQUEST_URI=/info.php/test?a=b
  SCRIPT_FILENAME=/path/to/php/bin/php-cgi  (Action setting translated)
  QUERY_STRING=a=b

  Comments in the code below refer to using the above URL in a request

 */
static void init_request_info(void)
{
	fcgi_request *request = (fcgi_request*) SG(server_context);
	char *env_script_filename = FCGI_GETENV(request, "SCRIPT_FILENAME");
	char *env_path_translated = FCGI_GETENV(request, "PATH_TRANSLATED");
	char *script_path_translated = env_script_filename;
	int apache_was_here = 0;
	sapi_request_info *request_info = &SG(request_info);

	/* some broken servers do not have script_filename or argv0
	 * an example, IIS configured in some ways.  then they do more
	 * broken stuff and set path_translated to the cgi script location */
	if (!script_path_translated && env_path_translated) {
		script_path_translated = env_path_translated;
	}

	/* initialize the defaults */
	request_info->path_translated = NULL;
	request_info->request_method = FCGI_GETENV(request, "REQUEST_METHOD");
	request_info->proto_num = 1000;
	request_info->query_string = NULL;
	request_info->request_uri = NULL;
	request_info->content_type = NULL;
	request_info->content_length = 0;
	SG(sapi_headers).http_response_code = 200;

	/* if script_path_translated is not set, then there is no point to carry on
	 * as the response is 404 and there is no further processing. */
	if (script_path_translated) {
		const char *auth;
		char *content_length = FCGI_GETENV(request, "CONTENT_LENGTH");
		char *content_type = FCGI_GETENV(request, "CONTENT_TYPE");
		char *env_path_info = FCGI_GETENV(request, "PATH_INFO");
		char *env_script_name = FCGI_GETENV(request, "SCRIPT_NAME");

		/* Hack for buggy IIS that sets incorrect PATH_INFO */
		char *env_server_software = FCGI_GETENV(request, "SERVER_SOFTWARE");
		if (env_server_software &&
			env_script_name &&
			env_path_info &&
			strncmp(env_server_software, "Microsoft-IIS", sizeof("Microsoft-IIS") - 1) == 0 &&
			strncmp(env_path_info, env_script_name, strlen(env_script_name)) == 0
		) {
			env_path_info = FCGI_PUTENV(request, "ORIG_PATH_INFO", env_path_info);
			env_path_info += strlen(env_script_name);
			if (*env_path_info == 0) {
				env_path_info = NULL;
			}
			env_path_info = FCGI_PUTENV(request, "PATH_INFO", env_path_info);
		}

#define APACHE_PROXY_FCGI_PREFIX "proxy:fcgi://"
#define APACHE_PROXY_BALANCER_PREFIX "proxy:balancer://"
		/* Fix proxy URLs in SCRIPT_FILENAME generated by Apache mod_proxy_fcgi and mod_proxy_balancer:
		 *     proxy:fcgi://localhost:9000/some-dir/info.php/test?foo=bar
		 *     proxy:balancer://localhost:9000/some-dir/info.php/test?foo=bar
		 * should be changed to:
		 *     /some-dir/info.php/test
		 * See: http://bugs.php.net/bug.php?id=54152
		 *      http://bugs.php.net/bug.php?id=62172
		 *      https://issues.apache.org/bugzilla/show_bug.cgi?id=50851
		 */
		if (env_script_filename &&
			strncasecmp(env_script_filename, APACHE_PROXY_FCGI_PREFIX, sizeof(APACHE_PROXY_FCGI_PREFIX) - 1) == 0) {
			/* advance to first character of hostname */
			char *p = env_script_filename + (sizeof(APACHE_PROXY_FCGI_PREFIX) - 1);
			while (*p != '\0' && *p != '/') {
				p++;	/* move past hostname and port */
			}
			if (*p != '\0') {
				/* Copy path portion in place to avoid memory leak.  Note
				 * that this also affects what script_path_translated points
				 * to. */
				memmove(env_script_filename, p, strlen(p) + 1);
				apache_was_here = 1;
			}
			/* ignore query string if sent by Apache (RewriteRule) */
			p = strchr(env_script_filename, '?');
			if (p) {
				*p =0;
			}
		}

		if (env_script_filename &&
			strncasecmp(env_script_filename, APACHE_PROXY_BALANCER_PREFIX, sizeof(APACHE_PROXY_BALANCER_PREFIX) - 1) == 0) {
			/* advance to first character of hostname */
			char *p = env_script_filename + (sizeof(APACHE_PROXY_BALANCER_PREFIX) - 1);
			while (*p != '\0' && *p != '/') {
				p++;	/* move past hostname and port */
			}
			if (*p != '\0') {
				/* Copy path portion in place to avoid memory leak.  Note
				 * that this also affects what script_path_translated points
				 * to. */
				memmove(env_script_filename, p, strlen(p) + 1);
				apache_was_here = 1;
			}
			/* ignore query string if sent by Apache (RewriteRule) */
			p = strchr(env_script_filename, '?');
			if (p) {
				*p =0;
			}
		}

		if (CGIG(fix_pathinfo)) {
			struct stat st;
			char *real_path = NULL;
			char *env_redirect_url = FCGI_GETENV(request, "REDIRECT_URL");
			char *env_document_root = FCGI_GETENV(request, "DOCUMENT_ROOT");
			char *orig_path_translated = env_path_translated;
			char *orig_path_info = env_path_info;
			char *orig_script_name = env_script_name;
			char *orig_script_filename = env_script_filename;
			int script_path_translated_len;

			if (!env_document_root && PG(doc_root)) {
				env_document_root = FCGI_PUTENV(request, "DOCUMENT_ROOT", PG(doc_root));
			}

			if (!apache_was_here && env_path_translated != NULL && env_redirect_url != NULL &&
			    env_path_translated != script_path_translated &&
			    strcmp(env_path_translated, script_path_translated) != 0) {
				/*
				 * pretty much apache specific.  If we have a redirect_url
				 * then our script_filename and script_name point to the
				 * php executable
				 * we don't want to do this for the new mod_proxy_fcgi approach,
				 * where redirect_url may also exist but the below will break
				 * with rewrites to PATH_INFO, hence the !apache_was_here check
				 */
				script_path_translated = env_path_translated;
				/* we correct SCRIPT_NAME now in case we don't have PATH_INFO */
				env_script_name = env_redirect_url;
			}

#ifdef __riscos__
			/* Convert path to unix format*/
			__riscosify_control |= __RISCOSIFY_DONT_CHECK_DIR;
			script_path_translated = __unixify(script_path_translated, 0, NULL, 1, 0);
#endif

			/*
			 * if the file doesn't exist, try to extract PATH_INFO out
			 * of it by stat'ing back through the '/'
			 * this fixes url's like /info.php/test
			 */
			if (script_path_translated &&
				(script_path_translated_len = strlen(script_path_translated)) > 0 &&
				(script_path_translated[script_path_translated_len-1] == '/' ||
				(real_path = tsrm_realpath(script_path_translated, NULL)) == NULL)
			) {
				char *pt = estrndup(script_path_translated, script_path_translated_len);
				int len = script_path_translated_len;
				char *ptr;

				if (pt) {
					while ((ptr = strrchr(pt, '/')) || (ptr = strrchr(pt, '\\'))) {
						*ptr = 0;
						if (stat(pt, &st) == 0 && S_ISREG(st.st_mode)) {
							/*
							 * okay, we found the base script!
							 * work out how many chars we had to strip off;
							 * then we can modify PATH_INFO
							 * accordingly
							 *
							 * we now have the makings of
							 * PATH_INFO=/test
							 * SCRIPT_FILENAME=/docroot/info.php
							 *
							 * we now need to figure out what docroot is.
							 * if DOCUMENT_ROOT is set, this is easy, otherwise,
							 * we have to play the game of hide and seek to figure
							 * out what SCRIPT_NAME should be
							 */
							int ptlen = strlen(pt);
							int slen = len - ptlen;
							int pilen = env_path_info ? strlen(env_path_info) : 0;
							int tflag = 0;
							char *path_info;
							if (apache_was_here) {
								/* recall that PATH_INFO won't exist */
								path_info = script_path_translated + ptlen;
								tflag = (slen != 0 && (!orig_path_info || strcmp(orig_path_info, path_info) != 0));
							} else {
								path_info = (env_path_info && pilen > slen) ? env_path_info + pilen - slen : NULL;
								tflag = path_info && (orig_path_info != path_info);
							}

							if (tflag) {
								if (orig_path_info) {
									char old;

									FCGI_PUTENV(request, "ORIG_PATH_INFO", orig_path_info);
									old = path_info[0];
									path_info[0] = 0;
									if (!orig_script_name ||
										strcmp(orig_script_name, env_path_info) != 0) {
										if (orig_script_name) {
											FCGI_PUTENV(request, "ORIG_SCRIPT_NAME", orig_script_name);
										}
										request_info->request_uri = FCGI_PUTENV(request, "SCRIPT_NAME", env_path_info);
									} else {
										request_info->request_uri = orig_script_name;
									}
									path_info[0] = old;
								} else if (apache_was_here && env_script_name) {
									/* Using mod_proxy_fcgi and ProxyPass, apache cannot set PATH_INFO
									 * As we can extract PATH_INFO from PATH_TRANSLATED
									 * it is probably also in SCRIPT_NAME and need to be removed
									 */
									int snlen = strlen(env_script_name);
									if (snlen>slen && !strcmp(env_script_name+snlen-slen, path_info)) {
										FCGI_PUTENV(request, "ORIG_SCRIPT_NAME", orig_script_name);
										env_script_name[snlen-slen] = 0;
										request_info->request_uri = FCGI_PUTENV(request, "SCRIPT_NAME", env_script_name);
									}
								}
								env_path_info = FCGI_PUTENV(request, "PATH_INFO", path_info);
							}
							if (!orig_script_filename ||
								strcmp(orig_script_filename, pt) != 0) {
								if (orig_script_filename) {
									FCGI_PUTENV(request, "ORIG_SCRIPT_FILENAME", orig_script_filename);
								}
								script_path_translated = FCGI_PUTENV(request, "SCRIPT_FILENAME", pt);
							}

							/* figure out docroot
							 * SCRIPT_FILENAME minus SCRIPT_NAME
							 */
							if (env_document_root) {
								int l = strlen(env_document_root);
								int path_translated_len = 0;
								char *path_translated = NULL;

								if (l && env_document_root[l - 1] == '/') {
									--l;
								}

								/* we have docroot, so we should have:
								 * DOCUMENT_ROOT=/docroot
								 * SCRIPT_FILENAME=/docroot/info.php
								 */

								/* PATH_TRANSLATED = DOCUMENT_ROOT + PATH_INFO */
								path_translated_len = l + (env_path_info ? strlen(env_path_info) : 0);
								path_translated = (char *) emalloc(path_translated_len + 1);
								memcpy(path_translated, env_document_root, l);
								if (env_path_info) {
									memcpy(path_translated + l, env_path_info, (path_translated_len - l));
								}
								path_translated[path_translated_len] = '\0';
								if (orig_path_translated) {
									FCGI_PUTENV(request, "ORIG_PATH_TRANSLATED", orig_path_translated);
								}
								env_path_translated = FCGI_PUTENV(request, "PATH_TRANSLATED", path_translated);
								efree(path_translated);
							} else if (	env_script_name &&
										strstr(pt, env_script_name)
							) {
								/* PATH_TRANSLATED = PATH_TRANSLATED - SCRIPT_NAME + PATH_INFO */
								int ptlen = strlen(pt) - strlen(env_script_name);
								int path_translated_len = ptlen + (env_path_info ? strlen(env_path_info) : 0);
								char *path_translated = NULL;

								path_translated = (char *) emalloc(path_translated_len + 1);
								memcpy(path_translated, pt, ptlen);
								if (env_path_info) {
									memcpy(path_translated + ptlen, env_path_info, path_translated_len - ptlen);
								}
								path_translated[path_translated_len] = '\0';
								if (orig_path_translated) {
									FCGI_PUTENV(request, "ORIG_PATH_TRANSLATED", orig_path_translated);
								}
								env_path_translated = FCGI_PUTENV(request, "PATH_TRANSLATED", path_translated);
								efree(path_translated);
							}
							break;
						}
					}
				} else {
					ptr = NULL;
				}
				if (!ptr) {
					/*
					 * if we stripped out all the '/' and still didn't find
					 * a valid path... we will fail, badly. of course we would
					 * have failed anyway... we output 'no input file' now.
					 */
					if (orig_script_filename) {
						FCGI_PUTENV(request, "ORIG_SCRIPT_FILENAME", orig_script_filename);
					}
					script_path_translated = FCGI_PUTENV(request, "SCRIPT_FILENAME", NULL);
					SG(sapi_headers).http_response_code = 404;
				}
				if (!request_info->request_uri) {
					if (!orig_script_name ||
						strcmp(orig_script_name, env_script_name) != 0) {
						if (orig_script_name) {
							FCGI_PUTENV(request, "ORIG_SCRIPT_NAME", orig_script_name);
						}
						request_info->request_uri = FCGI_PUTENV(request, "SCRIPT_NAME", env_script_name);
					} else {
						request_info->request_uri = orig_script_name;
					}
				}
				if (pt) {
					efree(pt);
				}
			} else {
				/* make sure original values are remembered in ORIG_ copies if we've changed them */
				if (!orig_script_filename ||
					(script_path_translated != orig_script_filename &&
					strcmp(script_path_translated, orig_script_filename) != 0)) {
					if (orig_script_filename) {
						FCGI_PUTENV(request, "ORIG_SCRIPT_FILENAME", orig_script_filename);
					}
					script_path_translated = FCGI_PUTENV(request, "SCRIPT_FILENAME", script_path_translated);
				}
				if (!apache_was_here && env_redirect_url) {
					/* if we used PATH_TRANSLATED to work around Apache mod_fastcgi (but not mod_proxy_fcgi,
					 * hence !apache_was_here) weirdness, strip info accordingly */
					if (orig_path_info) {
						FCGI_PUTENV(request, "ORIG_PATH_INFO", orig_path_info);
						FCGI_PUTENV(request, "PATH_INFO", NULL);
					}
					if (orig_path_translated) {
						FCGI_PUTENV(request, "ORIG_PATH_TRANSLATED", orig_path_translated);
						FCGI_PUTENV(request, "PATH_TRANSLATED", NULL);
					}
				}
				if (env_script_name != orig_script_name) {
					if (orig_script_name) {
						FCGI_PUTENV(request, "ORIG_SCRIPT_NAME", orig_script_name);
					}
					request_info->request_uri = FCGI_PUTENV(request, "SCRIPT_NAME", env_script_name);
				} else {
					request_info->request_uri = env_script_name;
				}
				efree(real_path);
			}
		} else {
			/* pre 4.3 behaviour, shouldn't be used but provides BC */
			if (env_path_info) {
				request_info->request_uri = env_path_info;
			} else {
				request_info->request_uri = env_script_name;
			}
			if (!CGIG(discard_path) && env_path_translated) {
				script_path_translated = env_path_translated;
			}
		}

		if (is_valid_path(script_path_translated)) {
			request_info->path_translated = estrdup(script_path_translated);
		}

		/* FIXME - Work out proto_num here */
		request_info->query_string = FCGI_GETENV(request, "QUERY_STRING");
		request_info->content_type = (content_type ? content_type : "" );
		request_info->content_length = (content_length ? atol(content_length) : 0);

		/* The CGI RFC allows servers to pass on unvalidated Authorization data */
		auth = FCGI_GETENV(request, "HTTP_AUTHORIZATION");
		php_handle_auth_data(auth);
	}
}
/* }}} */

PHP_INI_BEGIN()
	STD_PHP_INI_ENTRY("cgi.rfc2616_headers",     "0",  PHP_INI_ALL,    OnUpdateBool,   rfc2616_headers, php_cgi_globals_struct, php_cgi_globals)
	STD_PHP_INI_ENTRY("cgi.nph",                 "0",  PHP_INI_ALL,    OnUpdateBool,   nph, php_cgi_globals_struct, php_cgi_globals)
	STD_PHP_INI_ENTRY("cgi.force_redirect",      "1",  PHP_INI_SYSTEM, OnUpdateBool,   force_redirect, php_cgi_globals_struct, php_cgi_globals)
	STD_PHP_INI_ENTRY("cgi.redirect_status_env", NULL, PHP_INI_SYSTEM, OnUpdateString, redirect_status_env, php_cgi_globals_struct, php_cgi_globals)
	STD_PHP_INI_ENTRY("cgi.fix_pathinfo",        "1",  PHP_INI_SYSTEM, OnUpdateBool,   fix_pathinfo, php_cgi_globals_struct, php_cgi_globals)
	STD_PHP_INI_ENTRY("cgi.discard_path",        "0",  PHP_INI_SYSTEM, OnUpdateBool,   discard_path, php_cgi_globals_struct, php_cgi_globals)
	STD_PHP_INI_ENTRY("fastcgi.logging",         "1",  PHP_INI_SYSTEM, OnUpdateBool,   fcgi_logging, php_cgi_globals_struct, php_cgi_globals)
	STD_PHP_INI_ENTRY("fastcgi.error_header",    NULL, PHP_INI_SYSTEM, OnUpdateString, error_header, php_cgi_globals_struct, php_cgi_globals)
PHP_INI_END()

/* {{{ php_cgi_globals_ctor
 */
static void php_cgi_globals_ctor(php_cgi_globals_struct *php_cgi_globals)
{
	php_cgi_globals->rfc2616_headers = 0;
	php_cgi_globals->nph = 0;
	php_cgi_globals->force_redirect = 1;
	php_cgi_globals->redirect_status_env = NULL;
	php_cgi_globals->fix_pathinfo = 1;
	php_cgi_globals->discard_path = 0;
	php_cgi_globals->fcgi_logging = 1;
	zend_hash_init(&php_cgi_globals->user_config_cache, 0, NULL, user_config_cache_entry_dtor, 1);
	php_cgi_globals->error_header = NULL;
	php_cgi_globals->body_fd = -1;
	php_cgi_globals->is_accept = 0;
	php_cgi_globals->response_length = 0;
}
/* }}} */

/* {{{ php_cgi_globals_dtor
 */
static void php_cgi_globals_dtor(php_cgi_globals_struct *php_cgi_globals)
{
	// php_cgi_globals->redirect_status_env = NULL;
	// php_cgi_globals->error_header = NULL;
	zend_hash_destroy(&php_cgi_globals->user_config_cache);
}
/* }}} */

static long le_ts_var_descriptor;
#define PHP_TS_VAR_DESCRIPTOR "ts_var_t"

static void php_destroy_ts_var(zend_resource *rsrc) {
	ts_hash_table_destroy(rsrc->ptr);
	
	dprintf("RESOURCE %p destroy(ts var)\n", rsrc->ptr);
}

/* {{{ PHP_MINIT_FUNCTION
 */
static PHP_MINIT_FUNCTION(cgi)
{
	ts_allocate_id(&php_cgi_globals_id, sizeof(php_cgi_globals_struct), (ts_allocate_ctor) php_cgi_globals_ctor, (ts_allocate_dtor) php_cgi_globals_dtor);
	le_ts_var_descriptor = zend_register_list_destructors_ex(php_destroy_ts_var, NULL, PHP_TS_VAR_DESCRIPTOR, module_number);
	REGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
static PHP_MSHUTDOWN_FUNCTION(cgi)
{
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
static PHP_MINFO_FUNCTION(cgi)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "php-fpm", "active");
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */

ZEND_BEGIN_ARG_INFO(cgi_fcgi_sapi_no_arginfo, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(fastcgi_finish_request) /* {{{ */
{
	fcgi_request *request = (fcgi_request*) SG(server_context);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	if (!fcgi_is_closed(request)) {
		php_output_end_all();
		php_header();

		fcgi_end(request);
		fcgi_close(request, 0, 0);
		RETURN_TRUE;
	}

	RETURN_FALSE;

}
/* }}} */

PHP_FUNCTION(apache_request_headers) /* {{{ */
{
	fcgi_request *request;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	array_init(return_value);
	if ((request = (fcgi_request*) SG(server_context))) {
		fcgi_loadenv(request, sapi_add_request_header, return_value);
	}
} /* }}} */

// ===========================================================================================================

static hash_table_t *share_var_ht = NULL;
static pthread_mutex_t share_var_rlock;
static pthread_mutex_t share_var_wlock;
static volatile int share_var_locks = 0;

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_exists, 0, 0, 1)
ZEND_ARG_VARIADIC_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_get, 0, 0, 0)
ZEND_ARG_VARIADIC_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_get_and_del, 0, 0, 0)
ZEND_ARG_VARIADIC_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_put, 0, 0, 1)
ZEND_ARG_VARIADIC_INFO(0, keys)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_inc, 0, 0, 2)
ZEND_ARG_VARIADIC_INFO(0, keys)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_set, 0, 0, 2)
ZEND_ARG_VARIADIC_INFO(0, keys)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_set_ex, 0, 0, 3)
ZEND_ARG_VARIADIC_INFO(0, keys)
ZEND_ARG_INFO(0, value)
ZEND_ARG_TYPE_INFO(0, expire, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_del, 0, 0, 1)
ZEND_ARG_VARIADIC_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_clean, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_share_var_count, 0, 0, 0)
ZEND_ARG_VARIADIC_INFO(0, keys)
ZEND_END_ARG_INFO()

#define SHARE_VAR_RLOCK() \
	pthread_mutex_lock(&share_var_rlock); \
	if ((++(share_var_locks)) == 1) { \
		pthread_mutex_lock(&share_var_wlock); \
	} \
	pthread_mutex_unlock(&share_var_rlock)

#define SHARE_VAR_RUNLOCK() \
	pthread_mutex_lock(&share_var_rlock); \
	if ((--(share_var_locks)) == 0) { \
		pthread_mutex_unlock(&share_var_wlock); \
	} \
	pthread_mutex_unlock(&share_var_rlock)

#define SHARE_VAR_WLOCK() pthread_mutex_lock(&share_var_wlock)
#define SHARE_VAR_WUNLOCK() pthread_mutex_unlock(&share_var_wlock)

//---------------------------------------------------------------------------------------

#define __NULL (void)0

#define SERIALIZE(z,ok) SERIALIZE_EX(z,__NULL,ok,__NULL,__NULL)
#define SERIALIZE_EX(z,r1,ok,r2,r3) \
	do { \
		php_serialize_data_t var_hash; \
		smart_str buf = {0}; \
		PHP_VAR_SERIALIZE_INIT(var_hash); \
		php_var_serialize(&buf, z, &var_hash); \
		PHP_VAR_SERIALIZE_DESTROY(var_hash); \
		if (EG(exception)) { \
			smart_str_free(&buf); \
			r1; \
		} else if (buf.s) { \
			ok; \
			smart_str_free(&buf); \
			r2; \
		} else { \
			r3; \
		} \
	} while(0)

#define UNSERIALIZE(s,l,ok) UNSERIALIZE_EX(s,l,__NULL,ok,__NULL)
#define UNSERIALIZE_EX(s,l,r,ok,ok2) \
	do { \
		php_unserialize_data_t var_hash; \
		char *__buf = s; \
		const unsigned char *__p = (const unsigned char *) __buf; \
		size_t __buflen = l; \
		PHP_VAR_UNSERIALIZE_INIT(var_hash); \
		zval *retval = var_tmp_var(&var_hash); \
		if(!php_var_unserialize(retval, &__p, __p + __buflen, &var_hash)) { \
			if (!EG(exception)) { \
				php_error_docref(NULL, E_NOTICE, "Error at offset " ZEND_LONG_FMT " of %zd bytes", (zend_long)((char*)__p - __buf), __buflen); \
			} \
			r; \
		} else { \
			ok;ok2; \
		} \
		PHP_VAR_UNSERIALIZE_DESTROY(var_hash); \
	} while(0)

static void share_var_init()
{
	pthread_mutex_init(&share_var_rlock, NULL);
	pthread_mutex_init(&share_var_wlock, NULL);
	share_var_ht = (hash_table_t*) malloc(sizeof(hash_table_t));

	hash_table_init(share_var_ht, 128);
}

static PHP_FUNCTION(share_var_exists)
{
	zval *arguments;
	int arg_num = ZEND_NUM_ARGS(), i;
	if(arg_num <= 0) return;

	arguments = (zval *) safe_emalloc(sizeof(zval), arg_num, 0);
	if(zend_get_parameters_array_ex(arg_num, arguments) == FAILURE) goto end;

	SHARE_VAR_RLOCK();
	value_t v1 = {.type=HT_T,.ptr=share_var_ht,.expire=0}, v2 = {.type=NULL_T,.expire=0};
	RETVAL_FALSE;
	for(i=0; i<arg_num && v1.type == HT_T; i++) {
		if(i+1 == arg_num) {
			if(Z_TYPE(arguments[i]) == IS_LONG) {
				RETVAL_BOOL(hash_table_index_exists((hash_table_t*) v1.ptr, Z_LVAL(arguments[i])));
			} else {
				convert_to_string(&arguments[i]);
				RETVAL_BOOL(hash_table_exists((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i])));
			}
		} else if(Z_TYPE(arguments[i]) == IS_LONG) {
			if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE) break;
		} else {
			convert_to_string(&arguments[i]);
			if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE) break;
		}
		v1 = v2;
	}
	SHARE_VAR_RUNLOCK();

	end:
	efree(arguments);
}

static int hash_table_to_zval(bucket_t *p, zval *a) {
	if(p->nKeyLength == 0) {
		switch(p->value.type) {
			case NULL_T:
				add_index_null(a, p->h);
				break;
			case BOOL_T:
				add_index_bool(a, p->h, p->value.b);
				break;
			case LONG_T:
				add_index_long(a, p->h, p->value.l);
				break;
			case DOUBLE_T:
				add_index_double(a, p->h, p->value.d);
				break;
			case STR_T:
				add_index_stringl(a, p->h, p->value.str->str, p->value.str->len);
				break;
			case HT_T: {
				zval z;
				array_init_size(&z, hash_table_num_elements(p->value.ptr));
				hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_to_zval, &z);
				add_index_zval(a, p->h, &z);
				break;
			}
			case SERI_T: {
				zval rv;
				UNSERIALIZE_EX(p->value.str->str, p->value.str->len, __NULL, ZVAL_COPY(&rv, retval), add_index_zval(a, p->h, &rv));
				break;
			}
			case TS_HT_T: {
				zval z;
				array_init_size(&z, hash_table_num_elements(p->value.ptr));
				ts_hash_table_rd_lock(p->value.ptr);
				hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_to_zval, &z);
				ts_hash_table_rd_unlock(p->value.ptr);
				add_index_zval(a, p->h, &z);
				break;
			}
		}
	} else {
		switch(p->value.type) {
			case NULL_T:
				add_assoc_null_ex(a, p->arKey, p->nKeyLength);
				break;
			case BOOL_T:
				add_assoc_bool_ex(a, p->arKey, p->nKeyLength, p->value.b);
				break;
			case LONG_T:
				add_assoc_long_ex(a, p->arKey, p->nKeyLength, p->value.l);
				break;
			case DOUBLE_T:
				add_assoc_double_ex(a, p->arKey, p->nKeyLength, p->value.d);
				break;
			case STR_T:
				add_assoc_stringl_ex(a, p->arKey, p->nKeyLength, p->value.str->str, p->value.str->len);
				break;
			case HT_T: {
				zval z;
				array_init_size(&z, hash_table_num_elements(p->value.ptr));
				hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_to_zval, &z);
				add_assoc_zval_ex(a, p->arKey, p->nKeyLength, &z);
				break;
			}
			case SERI_T: {
				zval rv;
				UNSERIALIZE_EX(p->value.str->str, p->value.str->len, __NULL, ZVAL_COPY(&rv, retval), add_assoc_zval_ex(a, p->arKey, p->nKeyLength, &rv));
				break;
			}
			case TS_HT_T: {
				zval z;
				array_init_size(&z, hash_table_num_elements(p->value.ptr));
				ts_hash_table_rd_lock(p->value.ptr);
				hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_to_zval, &z);
				ts_hash_table_rd_unlock(p->value.ptr);
				add_assoc_zval_ex(a, p->arKey, p->nKeyLength, &z);
				break;
			}
		}
	}
	
	return HASH_TABLE_APPLY_KEEP;
}

void value_to_zval(value_t *v, zval *return_value) {
	switch(v->type) {
		case BOOL_T:
			RETVAL_BOOL(v->b);
			break;
		case LONG_T:
			RETVAL_LONG(v->l);
			break;
		case DOUBLE_T:
			RETVAL_DOUBLE(v->d);
			break;
		case STR_T:
			RETVAL_STRINGL(v->str->str, v->str->len);
			break;
		case HT_T:
			array_init_size(return_value, hash_table_num_elements(v->ptr));
			hash_table_apply_with_argument(v->ptr, (hash_apply_func_arg_t) hash_table_to_zval, return_value);
			break;
		case SERI_T: {
			UNSERIALIZE(v->str->str, v->str->len, ZVAL_COPY(return_value, retval));
			break;
		}
		case TS_HT_T:
			array_init_size(return_value, hash_table_num_elements(v->ptr));
			ts_hash_table_rd_lock(v->ptr);
			hash_table_apply_with_argument(v->ptr, (hash_apply_func_arg_t) hash_table_to_zval, return_value);
			ts_hash_table_rd_unlock(v->ptr);
			break;
		default:
			RETVAL_NULL();
			break;
	}
}

static PHP_FUNCTION(share_var_get)
{
	zval *arguments;
	int arg_num = ZEND_NUM_ARGS(), i;

	if(arg_num <= 0) {
		SHARE_VAR_RLOCK();
		array_init_size(return_value, hash_table_num_elements(share_var_ht));
		hash_table_apply_with_argument(share_var_ht, (hash_apply_func_arg_t) hash_table_to_zval, return_value);
		SHARE_VAR_RUNLOCK();
		return;
	}

	arguments = (zval *) safe_emalloc(sizeof(zval), arg_num, 0);
	if(zend_get_parameters_array_ex(arg_num, arguments) == FAILURE) goto end;

	SHARE_VAR_RLOCK();
	value_t v1 = {.type=HT_T,.ptr=share_var_ht,.expire=0}, v2 = {.type=NULL_T,.expire=0};
	for(i=0; i<arg_num && v1.type == HT_T; i++) {
		if(Z_TYPE(arguments[i]) == IS_LONG) {
			if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE) break;
		} else {
			convert_to_string(&arguments[i]);
			if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE) break;
		}
		if(i == arg_num - 1) value_to_zval(&v2, return_value);
		else v1 = v2;
	}
	SHARE_VAR_RUNLOCK();

	end:
	efree(arguments);
}

static PHP_FUNCTION(share_var_get_and_del)
{
	zval *arguments;
	int arg_num = ZEND_NUM_ARGS(), i;

	if(arg_num <= 0) {
		SHARE_VAR_WLOCK();
		array_init_size(return_value, hash_table_num_elements(share_var_ht));
		hash_table_apply_with_argument(share_var_ht, (hash_apply_func_arg_t) hash_table_to_zval, return_value);
		hash_table_clean(share_var_ht);
		SHARE_VAR_WUNLOCK();
		return;
	}

	arguments = (zval *) safe_emalloc(sizeof(zval), arg_num, 0);
	if(zend_get_parameters_array_ex(arg_num, arguments) == FAILURE) goto end;

	SHARE_VAR_WLOCK();
	value_t v1 = {.type=HT_T,.ptr=share_var_ht,.expire=0}, v2 = {.type=NULL_T,.expire=0};
	for(i=0; i<arg_num && v1.type == HT_T; i++) {
		if(Z_TYPE(arguments[i]) == IS_LONG) {
			if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE) break;

			if(i == arg_num - 1) {
				value_to_zval(&v2, return_value);
				hash_table_index_del((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]));
			}
		} else {
			convert_to_string(&arguments[i]);
			if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE) break;
			
			if(i == arg_num - 1) {
				value_to_zval(&v2, return_value);
				hash_table_del((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]));
			}
		}

		v1 = v2;
	}
	SHARE_VAR_WUNLOCK(); // if(i!=arg_num) {printf("TYPE: %d,%d,%d\n", v1.type, v2.type, i);php_var_dump(&arguments[0], 0);php_var_dump(&arguments[i], 0);}

	end:
	efree(arguments);
}

static int zval_array_to_hash_table(zval *pDest, int num_args, va_list args, zend_hash_key *hash_key);
static void zval_to_value(zval *z, value_t *v) {
	v->expire = 0;
	switch(Z_TYPE_P(z)) {
		case IS_FALSE:
		case IS_TRUE:
			v->type = BOOL_T;
			v->b = Z_TYPE_P(z) == IS_TRUE;
			break;
		case IS_LONG:
			v->type = LONG_T;
			v->l = Z_LVAL_P(z);
			break;
		case IS_DOUBLE:
			v->type = DOUBLE_T;
			v->d = Z_DVAL_P(z);
			break;
		case IS_STRING:
			v->type = STR_T;
			v->str = (string_t*) malloc(sizeof(string_t)+Z_STRLEN_P(z));
			memcpy(v->str->str, Z_STRVAL_P(z), Z_STRLEN_P(z));
			v->str->str[Z_STRLEN_P(z)] = '\0';
			v->str->len = Z_STRLEN_P(z);
			break;
		case IS_ARRAY:
			v->type = HT_T;
			v->ptr = malloc(sizeof(hash_table_t));
			hash_table_init((hash_table_t*) v->ptr, 2);
			zend_hash_apply_with_arguments(Z_ARR_P(z), zval_array_to_hash_table, 1, v->ptr);
			break;
		case IS_OBJECT:
			#define __SERI_OK2 \
				v->type = SERI_T; \
				v->str = (string_t*) malloc(sizeof(string_t)+ZSTR_LEN(buf.s)); \
				memcpy(v->str->str, ZSTR_VAL(buf.s), ZSTR_LEN(buf.s)); \
				v->str->str[ZSTR_LEN(buf.s)] = '\0'; \
				v->str->len = ZSTR_LEN(buf.s)
			SERIALIZE(z, __SERI_OK2);
			#undef __SERI_OK2
			break;
		default:
			v->type = NULL_T;
			v->l = 0;
			break;
	}
}

static int zval_array_to_hash_table(zval *pDest, int num_args, va_list args, zend_hash_key *hash_key) {
	value_t v={.type=NULL_T,.expire=0};
	hash_table_t *ht = va_arg(args, hash_table_t*);

	if(hash_key->key) {
		if(Z_TYPE_P(pDest) == IS_ARRAY) {
			if(hash_table_find(ht, ZSTR_VAL(hash_key->key), ZSTR_LEN(hash_key->key), &v) == FAILURE || v.type != HT_T) {
				zval_to_value(pDest, &v);
				hash_table_update(ht, ZSTR_VAL(hash_key->key), ZSTR_LEN(hash_key->key), &v, NULL);
			} else {
				zend_hash_apply_with_arguments(Z_ARR_P(pDest), zval_array_to_hash_table, 1, v.ptr);
			}
		} else {
			zval_to_value(pDest, &v);
			hash_table_update(ht, ZSTR_VAL(hash_key->key), ZSTR_LEN(hash_key->key), &v, NULL);
		}
	} else {
		if(Z_TYPE_P(pDest) == IS_ARRAY) {
			if(hash_table_index_find(ht, hash_key->h, &v) == FAILURE || v.type != HT_T) {
				zval_to_value(pDest, &v);
				hash_table_index_update(ht, hash_key->h, &v, NULL);
			} else {
				zend_hash_apply_with_arguments(Z_ARR_P(pDest), zval_array_to_hash_table, 1, v.ptr);
			}
		} else {
			zval_to_value(pDest, &v);
			hash_table_index_update(ht, hash_key->h, &v, NULL);
		}
	}

	return ZEND_HASH_APPLY_KEEP;
}

static PHP_FUNCTION(share_var_put)
{
	zval *arguments;
	int arg_num = ZEND_NUM_ARGS(), i;
	if(arg_num <= 0) return;

	arguments = (zval *) safe_emalloc(sizeof(zval), arg_num, 0);
	if(zend_get_parameters_array_ex(arg_num, arguments) == FAILURE) goto end;

	SHARE_VAR_WLOCK();
	if(arg_num == 1) {
		if(Z_TYPE(arguments[0]) == IS_ARRAY) {
			zend_hash_apply_with_arguments(Z_ARR(arguments[0]), zval_array_to_hash_table, 1, share_var_ht);
			RETVAL_TRUE;
		} else {
			value_t v3;
			zval_to_value(&arguments[0], &v3);
			RETVAL_BOOL(hash_table_next_index_insert(share_var_ht, &v3, NULL) == SUCCESS);
		}
	} else {
		value_t v1 = {.type=HT_T,.ptr=share_var_ht,.expire=0}, v2;
		RETVAL_FALSE;
		for(i=0; i<arg_num; i++) {
			v2.type = NULL_T;
			if(i+2 == arg_num) {
				if(Z_TYPE(arguments[i+1]) == IS_ARRAY) {
					if(Z_TYPE(arguments[i]) == IS_LONG) {
						if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE || v2.type != HT_T) {
							zval_to_value(&arguments[i+1], &v2);
							RETVAL_BOOL(hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL) == SUCCESS);
						} else {
							zend_hash_apply_with_arguments(Z_ARR(arguments[i+1]), zval_array_to_hash_table, 1, v2.ptr);
							RETVAL_TRUE;
						}
					} else {
						convert_to_string(&arguments[i]);
						if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE || v2.type != HT_T) {
							zval_to_value(&arguments[i+1], &v2);
							RETVAL_BOOL(hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL) == SUCCESS);
						} else {
							zend_hash_apply_with_arguments(Z_ARR(arguments[i+1]), zval_array_to_hash_table, 1, v2.ptr);
							RETVAL_TRUE;
						}
					}
				} else {
					zval_to_value(&arguments[i+1], &v2);
					if(Z_TYPE(arguments[i]) == IS_LONG) {
						RETVAL_BOOL(hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL) == SUCCESS);
					} else {
						convert_to_string(&arguments[i]);
						RETVAL_BOOL(hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL) == SUCCESS);
					}
				}
				break;
			} else if(Z_TYPE(arguments[i]) == IS_LONG) {
				if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE) {
					v2.type = HT_T;
					v2.ptr = malloc(sizeof(hash_table_t));
					hash_table_init(v2.ptr, 2);
					hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL);
				} else {
					if(v2.type != HT_T) {
						v2.type = HT_T;
						v2.ptr = malloc(sizeof(hash_table_t));
						hash_table_init(v2.ptr, 2);
						hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL);
					}
				}
			} else {
				convert_to_string(&arguments[i]);
				if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE) {
					v2.type = HT_T;
					v2.ptr = malloc(sizeof(hash_table_t));
					hash_table_init(v2.ptr, 2);
					hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL);
				} else {
					if(v2.type != HT_T) {
						v2.type = HT_T;
						v2.ptr = malloc(sizeof(hash_table_t));
						hash_table_init(v2.ptr, 2);
						hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL);
					}
				}
			}
			v1 = v2;
		}
	}
	SHARE_VAR_WUNLOCK();

	end:
	efree(arguments);
}

#define VALUE_ADD(k,v,t) \
	switch(dst->type) { \
		case BOOL_T: \
			dst->v = dst->b + src->k;\
			dst->type = t;\
			break; \
		case LONG_T: \
			dst->l = dst->l + src->k;\
			break; \
		case DOUBLE_T: \
			dst->d = dst->d + src->k;\
			break; \
		default: \
			dst->v = src->k; \
			dst->type = t; \
			break; \
	}

static void value_add(value_t *dst, value_t *src) {
	if(dst->type == HT_T) {
		hash_table_next_index_insert(dst->ptr, src, NULL);
	} else {
		switch(src->type) {
			case BOOL_T:
				VALUE_ADD(b,l,LONG_T);
				break;
			case LONG_T:
				VALUE_ADD(l,l,LONG_T);
				break;
			case DOUBLE_T:
				VALUE_ADD(d,d,DOUBLE_T);
				break;
			case STR_T:
				if(dst->type == STR_T) {
					string_t *s = (string_t*) malloc(sizeof(string_t)+dst->str->len+src->str->len);
					s->len = dst->str->len+src->str->len;
					memcpy(s->str, dst->str->str, dst->str->len);
					memcpy(s->str + dst->str->len, src->str->str, src->str->len);
					s->str[s->len] = '\0';
					//free(dst->str);
					dst->str = s;
					hash_table_value_free(src);
				} else {
					dst->type = STR_T;
					dst->str = src->str;
				}
				break;
			default:
				hash_table_value_free(src);
				break;
		}
	}
}

static PHP_FUNCTION(share_var_inc)
{
	zval *arguments;
	int arg_num = ZEND_NUM_ARGS(), i;
	if(arg_num <= 1) return;

	arguments = (zval *) safe_emalloc(sizeof(zval), arg_num, 0);
	if(zend_get_parameters_array_ex(arg_num, arguments) == FAILURE) goto end;

	RETVAL_FALSE;

	SHARE_VAR_WLOCK();
	{
		value_t v1 = {.type=HT_T,.ptr=share_var_ht,.expire=0}, v2, v3 = {.type=NULL_T,.expire=0};
		ulong h;
		for(i=0; i<arg_num; i++) {
			v2.type = NULL_T;
			if(i+2 == arg_num) {
				zval_to_value(&arguments[i+1], &v2);
				if(Z_TYPE(arguments[i]) == IS_LONG) {
					if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v3) == FAILURE) {
						if(hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL) == SUCCESS) {
							value_to_zval(&v2, return_value);
						}
					} else {
						value_add(&v3, &v2);
						if(v3.type != HT_T) {
							if(hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v3, NULL) == SUCCESS) {
								value_to_zval(&v3, return_value);
							}
						} else RETVAL_LONG(hash_table_num_elements(v3.ptr));
					}
				} else {
					h = zend_get_hash_value(Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]));
					if(hash_table_quick_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), h, &v3) == FAILURE) {
						if(hash_table_quick_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), h, &v2, NULL) == SUCCESS) {
							value_to_zval(&v2, return_value);
						}
					} else {
						value_add(&v3, &v2);
						if(v3.type != HT_T) {
							if(hash_table_quick_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), h, &v3, NULL) == SUCCESS) {
								value_to_zval(&v3, return_value);
							}
						} else RETVAL_LONG(hash_table_num_elements(v3.ptr));
					}
				}
				break;
			} else if(Z_TYPE(arguments[i]) == IS_LONG) {
				if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE) {
					v2.type = HT_T;
					v2.ptr = malloc(sizeof(hash_table_t));
					hash_table_init(v2.ptr, 2);
					hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL);
				} else {
					if(v2.type != HT_T) {
						v2.type = HT_T;
						v2.ptr = malloc(sizeof(hash_table_t));
						hash_table_init(v2.ptr, 2);
						hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL);
					}
				}
			} else {
				convert_to_string(&arguments[i]);
				if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE) {
					v2.type = HT_T;
					v2.ptr = malloc(sizeof(hash_table_t));
					hash_table_init(v2.ptr, 2);
					hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL);
				} else {
					if(v2.type != HT_T) {
						v2.type = HT_T;
						v2.ptr = malloc(sizeof(hash_table_t));
						hash_table_init(v2.ptr, 2);
						hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL);
					}
				}
			}
			v1 = v2;
		}
	}
	SHARE_VAR_WUNLOCK();

	end:
	efree(arguments);
}

static PHP_FUNCTION(share_var_set)
{
	zval *arguments;
	int arg_num = ZEND_NUM_ARGS(), i;
	if(arg_num <= 1) return;

	arguments = (zval *) safe_emalloc(sizeof(zval), arg_num, 0);
	if(zend_get_parameters_array_ex(arg_num, arguments) == FAILURE) goto end;

	SHARE_VAR_WLOCK();
	value_t v1 = {.type=HT_T,.ptr=share_var_ht,.expire=0}, v2 = {.type=NULL_T,.expire=0};
	RETVAL_FALSE;
	for(i=0; i<arg_num && v1.type == HT_T; i++) {
		if(i+2 == arg_num) {
			zval_to_value(&arguments[i+1], &v2);
			if(Z_TYPE(arguments[i]) == IS_LONG) {
				RETVAL_BOOL(hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL) == SUCCESS);
			} else {
				convert_to_string(&arguments[i]);
				RETVAL_BOOL(hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL) == SUCCESS);
			}
			break;
		} else if(Z_TYPE(arguments[i]) == IS_LONG) {
			if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE) {
				v2.type = HT_T;
				v2.ptr = malloc(sizeof(hash_table_t));
				hash_table_init(v2.ptr, 2);
				hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL);
			} else {
				if(v2.type != HT_T) {
					v2.type = HT_T;
					v2.ptr = malloc(sizeof(hash_table_t));
					hash_table_init(v2.ptr, 2);
					hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL);
				}
			}
		} else {
			convert_to_string(&arguments[i]);
			if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE) {
				v2.type = HT_T;
				v2.ptr = malloc(sizeof(hash_table_t));
				hash_table_init(v2.ptr, 2);
				hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL);
			} else {
				if(v2.type != HT_T) {
					v2.type = HT_T;
					v2.ptr = malloc(sizeof(hash_table_t));
					hash_table_init(v2.ptr, 2);
					hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL);
				}
			}
		}
		v1 = v2;
	}
	SHARE_VAR_WUNLOCK();

	end:
	efree(arguments);
}

static PHP_FUNCTION(share_var_set_ex)
{
	zval *arguments;
	int arg_num = ZEND_NUM_ARGS(), i;
	if(arg_num <= 2) return;

	arguments = (zval *) safe_emalloc(sizeof(zval), arg_num, 0);
	if(zend_get_parameters_array_ex(arg_num, arguments) == FAILURE) goto end;

	SHARE_VAR_WLOCK();
	value_t v1 = {.type=HT_T,.ptr=share_var_ht,.expire=0}, v2 = {.type=NULL_T,.expire=0};
	RETVAL_FALSE;
	for(i=0; i<arg_num && v1.type == HT_T; i++) {
		if(i+3 == arg_num) {
			zval_to_value(&arguments[i+1], &v2);
			v2.expire = (int) Z_LVAL(arguments[i+2]);
			if(Z_TYPE(arguments[i]) == IS_LONG) {
				RETVAL_BOOL(hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL) == SUCCESS);
			} else {
				convert_to_string(&arguments[i]);
				RETVAL_BOOL(hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL) == SUCCESS);
			}
			break;
		} else if(Z_TYPE(arguments[i]) == IS_LONG) {
			if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE) {
				v2.type = HT_T;
				v2.ptr = malloc(sizeof(hash_table_t));
				hash_table_init(v2.ptr, 2);
				hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL);
			} else {
				if(v2.type != HT_T) {
					v2.type = HT_T;
					v2.ptr = malloc(sizeof(hash_table_t));
					hash_table_init(v2.ptr, 2);
					hash_table_index_update((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2, NULL);
				}
			}
		} else {
			convert_to_string(&arguments[i]);
			if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE) {
				v2.type = HT_T;
				v2.ptr = malloc(sizeof(hash_table_t));
				hash_table_init(v2.ptr, 2);
				hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL);
			} else {
				if(v2.type != HT_T) {
					v2.type = HT_T;
					v2.ptr = malloc(sizeof(hash_table_t));
					hash_table_init(v2.ptr, 2);
					hash_table_update((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2, NULL);
				}
			}
		}
		v1 = v2;
	}
	SHARE_VAR_WUNLOCK();

	end:
	efree(arguments);
}

static PHP_FUNCTION(share_var_del)
{
	zval *arguments;
	int arg_num = ZEND_NUM_ARGS(), i;
	if(arg_num <= 0) return;

	arguments = (zval *) safe_emalloc(sizeof(zval), arg_num, 0);
	if(zend_get_parameters_array_ex(arg_num, arguments) == FAILURE) goto end;

	SHARE_VAR_WLOCK();
	value_t v1 = {.type=HT_T,.ptr=share_var_ht,.expire=0}, v2 = {.type=NULL_T,.expire=0};
	RETVAL_FALSE;
	for(i=0; i<arg_num && v1.type == HT_T; i++) {
		if(i+1 == arg_num) {
			if(Z_TYPE(arguments[i]) == IS_LONG) {
				RETVAL_BOOL(hash_table_index_del((hash_table_t*) v1.ptr, Z_LVAL(arguments[i])) == SUCCESS);
			} else {
				convert_to_string(&arguments[i]);
				RETVAL_BOOL(hash_table_del((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i])) == SUCCESS);
			}
		} else if(Z_TYPE(arguments[i]) == IS_LONG) {
			if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE) break;
		} else {
			convert_to_string(&arguments[i]);
			if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE) break;
		}
		v1 = v2;
	}
	SHARE_VAR_WUNLOCK();

	end:
	efree(arguments);
}

static PHP_FUNCTION(share_var_clean)
{
	int n;
	SHARE_VAR_WLOCK();
	n = hash_table_num_elements(share_var_ht);
	hash_table_clean(share_var_ht);
	SHARE_VAR_WUNLOCK();

	RETVAL_LONG(n);
}

static PHP_FUNCTION(share_var_count)
{
	zval *arguments;
	int arg_num = ZEND_NUM_ARGS(), i;

	if(arg_num <= 0) {
		SHARE_VAR_RLOCK();
		RETVAL_LONG(hash_table_num_elements(share_var_ht));
		SHARE_VAR_RUNLOCK();
		return;
	}

	arguments = (zval *) safe_emalloc(sizeof(zval), arg_num, 0);
	if(zend_get_parameters_array_ex(arg_num, arguments) == FAILURE) goto end;

	SHARE_VAR_RLOCK();
	value_t v1 = {.type=HT_T,.ptr=share_var_ht,.expire=0}, v2 = {.type=NULL_T,.expire=0};
	for(i=0; i<arg_num && v1.type == HT_T; i++) {
		if(Z_TYPE(arguments[i]) == IS_LONG) {
			if(hash_table_index_find((hash_table_t*) v1.ptr, Z_LVAL(arguments[i]), &v2) == FAILURE) break;
		} else {
			convert_to_string(&arguments[i]);
			if(hash_table_find((hash_table_t*) v1.ptr, Z_STRVAL(arguments[i]), Z_STRLEN(arguments[i]), &v2) == FAILURE) break;
		}
		if(i == arg_num - 1) {
			switch(v2.type) {
				case STR_T:
					RETVAL_LONG(- (zend_long) v2.str->len);
					break;
				case SERI_T:
					RETVAL_TRUE;
					break;
				case HT_T:
					RETVAL_LONG(hash_table_num_elements(v2.ptr));
					break;
				default:
					RETVAL_FALSE;
					break;
			}
		} else v1 = v2;
	}
	SHARE_VAR_RUNLOCK();

	end:
	efree(arguments);
}

static int hash_table_clean_ex(bucket_t *p, int *ex) {
	if(p->value.expire && p->value.expire < *ex) {
		return HASH_TABLE_APPLY_REMOVE;
	} else if(p->value.type == HT_T) {
		hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_clean_ex, ex);
	} else if(p->value.type == TS_HT_T) {
		ts_hash_table_wr_lock(p->value.ptr);
		hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_clean_ex, ex);
		ts_hash_table_wr_unlock(p->value.ptr);
	}
	
	return HASH_TABLE_APPLY_KEEP;
}

static int share_var_clean_ex()
{
	int n;

	SHARE_VAR_WLOCK();
	n = (int) time(NULL);
	hash_table_apply_with_argument(share_var_ht, (hash_apply_func_arg_t) hash_table_clean_ex, &n);
	n = hash_table_num_elements(share_var_ht);
	SHARE_VAR_WUNLOCK();

	return n;
}

static void share_var_destory()
{
	pthread_mutex_destroy(&share_var_rlock);
	pthread_mutex_destroy(&share_var_wlock);
	hash_table_destroy(share_var_ht);
	
	free(share_var_ht);
	share_var_ht = NULL;
}

// -----------------------------------------------------------------------------------------------------------

void socket_import_fd(int fd, zval *return_value) {
	php_socket *sock;
	
	if(fd <= 0) RETURN_FALSE;

#if PHP_VERSION_ID >= 80000	
	object_init_ex(return_value, socket_ce);
	sock = Z_SOCKET_P(return_value);
	if (!socket_import_file_descriptor(fd, sock)) {
		zval_ptr_dtor(return_value);
		RETURN_FALSE;
	}
#else
	sock = socket_import_file_descriptor(fd);
	if(sock) {
		RETURN_RES(zend_register_resource(sock, php_sockets_le_socket()));
	} else RETURN_FALSE;
#endif
}

#if PHP_VERSION_ID < 80000
ZEND_BEGIN_ARG_INFO_EX(arginfo_ts_var_fd_close, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, socket, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_fd_close) {
	zval *zv;
	php_socket *sock;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_RESOURCE(zv)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((sock = (php_socket *) zend_fetch_resource_ex(zv, php_sockets_le_socket_name, php_sockets_le_socket())) == NULL) {
		RETURN_FALSE;
	}
	
	RETVAL_LONG(sock->bsd_socket);
	
	sock->bsd_socket = -1;
}
#else
ZEND_BEGIN_ARG_INFO_EX(arginfo_ts_var_fd_close, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, socket, Socket, 0)
ZEND_ARG_TYPE_INFO(0, is_close, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_fd_close) {
	zval *zsocket;
	php_socket *socket;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "O", &zsocket, socket_ce) == FAILURE) {
		RETURN_THROWS();
	}

	socket = Z_SOCKET_P(zsocket);
	ENSURE_SOCKET_VALID(socket);
	
	RETVAL_LONG(socket->bsd_socket);
	
	socket->bsd_socket = -1;
}
#endif

// -----------------------------------------------------------------------------------------------------------

static int hash_table_to_zval_wr(bucket_t *p, zval *a) {
	if(p->nKeyLength == 0) {
		switch(p->value.type) {
			case NULL_T:
				add_index_null(a, p->h);
				break;
			case BOOL_T:
				add_index_bool(a, p->h, p->value.b);
				break;
			case LONG_T:
				add_index_long(a, p->h, p->value.l);
				break;
			case DOUBLE_T:
				add_index_double(a, p->h, p->value.d);
				break;
			case STR_T:
				add_index_stringl(a, p->h, p->value.str->str, p->value.str->len);
				break;
			case HT_T: {
				zval z;
				array_init_size(&z, hash_table_num_elements(p->value.ptr));
				hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_to_zval, &z);
				add_index_zval(a, p->h, &z);
				break;
			}
			case SERI_T: {
				zval rv;
				UNSERIALIZE_EX(p->value.str->str, p->value.str->len, __NULL, ZVAL_COPY(&rv, retval), add_index_zval(a, p->h, &rv));
				break;
			}
			case TS_HT_T: {
				zval z;
				array_init_size(&z, hash_table_num_elements(p->value.ptr));
				ts_hash_table_wr_lock(p->value.ptr);
				hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_to_zval_wr, &z);
				ts_hash_table_wr_unlock(p->value.ptr);
				add_index_zval(a, p->h, &z);
				break;
			}
		}
	} else {
		switch(p->value.type) {
			case NULL_T:
				add_assoc_null_ex(a, p->arKey, p->nKeyLength);
				break;
			case BOOL_T:
				add_assoc_bool_ex(a, p->arKey, p->nKeyLength, p->value.b);
				break;
			case LONG_T:
				add_assoc_long_ex(a, p->arKey, p->nKeyLength, p->value.l);
				break;
			case DOUBLE_T:
				add_assoc_double_ex(a, p->arKey, p->nKeyLength, p->value.d);
				break;
			case STR_T:
				add_assoc_stringl_ex(a, p->arKey, p->nKeyLength, p->value.str->str, p->value.str->len);
				break;
			case HT_T: {
				zval z;
				array_init_size(&z, hash_table_num_elements(p->value.ptr));
				hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_to_zval, &z);
				add_assoc_zval_ex(a, p->arKey, p->nKeyLength, &z);
				break;
			}
			case SERI_T: {
				zval rv;
				UNSERIALIZE_EX(p->value.str->str, p->value.str->len, __NULL, ZVAL_COPY(&rv, retval), add_assoc_zval_ex(a, p->arKey, p->nKeyLength, &rv));
				break;
			}
			case TS_HT_T: {
				zval z;
				array_init_size(&z, hash_table_num_elements(p->value.ptr));
				ts_hash_table_wr_lock(p->value.ptr);
				hash_table_apply_with_argument(p->value.ptr, (hash_apply_func_arg_t) hash_table_to_zval_wr, &z);
				ts_hash_table_wr_unlock(p->value.ptr);
				add_assoc_zval_ex(a, p->arKey, p->nKeyLength, &z);
				break;
			}
		}
	}
	
	return HASH_TABLE_APPLY_KEEP;
}

void value_to_zval_wr(value_t *v, zval *return_value) {
	switch(v->type) {
		case BOOL_T:
			RETVAL_BOOL(v->b);
			break;
		case LONG_T:
			RETVAL_LONG(v->l);
			break;
		case DOUBLE_T:
			RETVAL_DOUBLE(v->d);
			break;
		case STR_T:
			RETVAL_STRINGL(v->str->str, v->str->len);
			break;
		case HT_T:
			array_init_size(return_value, hash_table_num_elements(v->ptr));
			hash_table_apply_with_argument(v->ptr, (hash_apply_func_arg_t) hash_table_to_zval, return_value);
			break;
		case SERI_T: {
			UNSERIALIZE(v->str->str, v->str->len, ZVAL_COPY(return_value, retval));
			break;
		}
		case TS_HT_T:
			array_init_size(return_value, hash_table_num_elements(v->ptr));
			ts_hash_table_wr_lock(v->ptr);
			hash_table_apply_with_argument(v->ptr, (hash_apply_func_arg_t) hash_table_to_zval_wr, return_value);
			ts_hash_table_wr_unlock(v->ptr);
			break;
		default:
			RETVAL_NULL();
			break;
	}
}

static ts_hash_table_t ts_var;

int ts_var_clean_ex() {
	int n;

	ts_hash_table_wr_lock(&ts_var);
	n = (int) time(NULL);
	hash_table_apply_with_argument(&ts_var.ht, (hash_apply_func_arg_t) hash_table_clean_ex, &n);
	n = hash_table_num_elements(&ts_var.ht);
	ts_hash_table_wr_unlock(&ts_var);

	return n;
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_declare, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 1)
ZEND_ARG_TYPE_INFO(0, is_fd, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_declare) {
	zend_string *key = NULL;
	zend_long index = 0;
	zend_bool is_null = 0;
	zval *zv = NULL;
	zend_bool is_fd = 0;

	ts_hash_table_t *ts_ht;
	value_t v = {.expire=0};

	ZEND_PARSE_PARAMETERS_START(1, 3)
		Z_PARAM_STR_OR_LONG_OR_NULL(key, index, is_null);
		Z_PARAM_OPTIONAL
		Z_PARAM_RESOURCE_OR_NULL(zv)
		Z_PARAM_BOOL(is_fd)
	ZEND_PARSE_PARAMETERS_END();
	
	if(zv) {
		if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
			RETURN_FALSE;
		}
	} else {
		ts_ht = &ts_var;
	}

	if(is_null) {
		ts_hash_table_rd_lock(ts_ht);
		ts_hash_table_ref(ts_ht);
		ts_hash_table_rd_unlock(ts_ht);
	} else {
		ts_hash_table_wr_lock(ts_ht);
		if(key) {
			zend_long h = zend_get_hash_value(ZSTR_VAL(key), ZSTR_LEN(key));
			if(hash_table_quick_find(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h, &v) == FAILURE || v.type != TS_HT_T) {
				v.type = TS_HT_T;
				v.ptr = (ts_hash_table_t *) malloc(sizeof(ts_hash_table_t));
				ts_hash_table_init(v.ptr, 2);
				hash_table_quick_update(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h, &v, NULL);
			}
		} else {
			if(hash_table_index_find(&ts_ht->ht, index, &v) == FAILURE || v.type != TS_HT_T) {
				v.type = TS_HT_T;
				v.ptr = (ts_hash_table_t *) malloc(sizeof(ts_hash_table_t));
				ts_hash_table_init(v.ptr, 2);
				hash_table_index_update(&ts_ht->ht, index, &v, NULL);
			}
		}
		ts_hash_table_ref(v.ptr);
		ts_hash_table_wr_unlock(ts_ht);

		ts_ht = (ts_hash_table_t*) v.ptr;
	}

	if(is_fd) {
		ts_hash_table_lock(ts_ht);
		if(!ts_ht->fds[0] && !ts_ht->fds[1] && socketpair(AF_UNIX, SOCK_STREAM, 0, ts_ht->fds) != 0) {
			ts_ht->fds[0] = 0;
			ts_ht->fds[1] = 0;
		}
		ts_hash_table_unlock(ts_ht);
	}

	RETURN_RES(zend_register_resource(ts_ht, le_ts_var_descriptor));
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_fd, 1)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_TYPE_INFO(0, is_write, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_fd) {
	zval *zv;
	zend_bool is_write = 0;
	
	ts_hash_table_t *ts_ht;
	php_shutdown_function_entry shutdown_function_entry;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(is_write)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}

	if(is_write) {
		socket_import_fd(ts_ht->fds[1], return_value);
	} else {
		socket_import_fd(ts_ht->fds[0], return_value);
	}
	
	if(Z_TYPE_P(return_value) != IS_FALSE) {
		ZVAL_STRING(&shutdown_function_entry.function_name, "ts_var_fd_close");
		shutdown_function_entry.arg_count = 1;
		shutdown_function_entry.arguments = (zval *) safe_emalloc(sizeof(zval), shutdown_function_entry.arg_count, 0);
		ZVAL_ZVAL(&shutdown_function_entry.arguments[0], return_value, 1, 0);
		
		append_user_shutdown_function(&shutdown_function_entry);
	}
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_expire, 2)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_TYPE_INFO(0, expire, IS_LONG, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_expire) {
	zval *zv;
	zend_long expire = 0;
	
	ts_hash_table_t *ts_ht;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_LONG(expire)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}

	ts_hash_table_wr_lock(ts_ht);
	ts_ht->expire = expire;
	ts_hash_table_wr_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_exists, 1)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_exists) {
	zval *zv;
	zend_string *key = NULL;
	zend_long index = 0;
	
	ts_hash_table_t *ts_ht;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_STR_OR_LONG(key, index);
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}

	ts_hash_table_rd_lock(ts_ht);
	if(key) {
		RETVAL_BOOL(hash_table_exists(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key)));
	} else {
		RETVAL_BOOL(hash_table_index_exists(&ts_ht->ht, index));
	}
	ts_hash_table_rd_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_set, 3)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, val)
ZEND_ARG_TYPE_INFO(0, expire, IS_LONG, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_set) {
	zval *zv;
	zend_string *key = NULL;
	zend_long index = 0;
	zend_bool is_null = 0;
	zval *val;
	zend_long expire = 0;
	
	ts_hash_table_t *ts_ht;
	value_t v;

	ZEND_PARSE_PARAMETERS_START(3, 4)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_STR_OR_LONG_OR_NULL(key, index, is_null)
		Z_PARAM_ZVAL(val)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(expire);
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}
	
	zval_to_value(val, &v);
	v.expire = expire;

	ts_hash_table_wr_lock(ts_ht);
	if(is_null) {
		RETVAL_BOOL(hash_table_next_index_insert(&ts_ht->ht, &v, NULL) == SUCCESS);
	} else if(key) {
		RETVAL_BOOL(hash_table_update(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), &v, NULL) == SUCCESS);
	} else {
		RETVAL_BOOL(hash_table_index_update(&ts_ht->ht, index, &v, NULL) == SUCCESS);
	}
	ts_hash_table_wr_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_push, 2)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_INFO(0, val)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_push) {
	zval *zv;
	zval *args;
	int i, argc, n = 0;
	
	ts_hash_table_t *ts_ht;
	value_t v;

	ZEND_PARSE_PARAMETERS_START(2, -1)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}
	
	ts_hash_table_wr_lock(ts_ht);
	for(i=0; i<argc; i++) {
		zval_to_value(&args[i], &v);
		if(hash_table_next_index_insert(&ts_ht->ht, &v, NULL) == SUCCESS) n++;
		else hash_table_value_free(&v);
	}
	ts_hash_table_wr_unlock(ts_ht);

	RETURN_LONG(n);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_pop, 1)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_INFO(1, key)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_pop) {
	zval *zv;
	zval *key = NULL;
	
	ts_hash_table_t *ts_ht;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_OPTIONAL
		Z_PARAM_ZVAL(key)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}
	
	ts_hash_table_wr_lock(ts_ht);
	if(ts_ht->ht.pListTail) {
		value_to_zval_wr(&ts_ht->ht.pListTail->value, return_value);
		if(key) {
			if(ts_ht->ht.pListTail->nKeyLength == 0) {
				ZEND_TRY_ASSIGN_REF_LONG(key, ts_ht->ht.pListTail->h);
			} else {
				ZEND_TRY_ASSIGN_REF_STRINGL(key, ts_ht->ht.pListTail->arKey, ts_ht->ht.pListTail->nKeyLength);
			}
		}
		hash_table_bucket_delete(&ts_ht->ht, ts_ht->ht.pListTail);
	}
	ts_hash_table_wr_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_shift, 1)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_INFO(1, key)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_shift) {
	zval *zv;
	zval *key = NULL;
	
	ts_hash_table_t *ts_ht;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_OPTIONAL
		Z_PARAM_ZVAL(key)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}
	
	ts_hash_table_wr_lock(ts_ht);
	if(ts_ht->ht.pListHead) {
		value_to_zval_wr(&ts_ht->ht.pListHead->value, return_value);
		if(key) {
			if(ts_ht->ht.pListHead->nKeyLength == 0) {
				ZEND_TRY_ASSIGN_REF_LONG(key, ts_ht->ht.pListHead->h);
			} else {
				ZEND_TRY_ASSIGN_REF_STRINGL(key, ts_ht->ht.pListHead->arKey, ts_ht->ht.pListHead->nKeyLength);
			}
		}
		hash_table_bucket_delete(&ts_ht->ht, ts_ht->ht.pListHead);
	}
	ts_hash_table_wr_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_minmax, 1)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_TYPE_INFO(0, is_max, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, is_key, _IS_BOOL, 0)
ZEND_ARG_INFO(1, key)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_minmax) {
	zval *zv;
	zval *key = NULL;
	zend_bool is_max = 0, is_key = 0;
	
	ts_hash_table_t *ts_ht;
	bucket_t *p = NULL;

	ZEND_PARSE_PARAMETERS_START(1, 4)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(is_max)
		Z_PARAM_BOOL(is_key)
		Z_PARAM_ZVAL_DEREF(key)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}
	
	ts_hash_table_rd_lock(ts_ht);
	if(hash_table_minmax(&ts_ht->ht, is_key ? compare_key : compare_value, is_max, &p) == SUCCESS) {
		value_to_zval(&p->value, return_value);
		if(key) {
			zval_ptr_dtor(key);
			if(p->nKeyLength == 0) {
				ZVAL_LONG(key, p->h);
			} else {
				ZVAL_STRINGL(key, p->arKey, p->nKeyLength);
			}
		}
	} else {
		RETVAL_FALSE;
	}
	ts_hash_table_rd_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_get, 1)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_TYPE_INFO(0, is_del, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_get) {
	zval *zv;
	zend_string *key = NULL;
	zend_long index = 0;
	zend_bool is_null = 1;
	zend_bool is_del = 0;
	
	ts_hash_table_t *ts_ht;
	value_t v;

	ZEND_PARSE_PARAMETERS_START(1, 3)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_OPTIONAL
		Z_PARAM_STR_OR_LONG_OR_NULL(key, index, is_null)
		Z_PARAM_BOOL(is_del)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}
	
	if(is_null) {
		ts_hash_table_rd_lock(ts_ht);
		array_init_size(return_value, hash_table_num_elements(&ts_ht->ht));
		hash_table_apply_with_argument(&ts_ht->ht, (hash_apply_func_arg_t) hash_table_to_zval, return_value);
		ts_hash_table_rd_unlock(ts_ht);
	} else if(is_del) {
		ts_hash_table_wr_lock(ts_ht);
		if(key) {
			zend_long h = zend_get_hash_value(ZSTR_VAL(key), ZSTR_LEN(key));
			if(hash_table_quick_find(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h, &v) == SUCCESS) {
				value_to_zval_wr(&v, return_value);
				hash_table_quick_del(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h);
			}
		} else {
			if(hash_table_index_find(&ts_ht->ht, index, &v) == SUCCESS) {
				value_to_zval_wr(&v, return_value);
				hash_table_index_del(&ts_ht->ht, index);
			}
		}
		ts_hash_table_wr_unlock(ts_ht);
	} else {
		ts_hash_table_rd_lock(ts_ht);
		if(key) {
			if(hash_table_find(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), &v) == SUCCESS) {
				value_to_zval(&v, return_value);
			}
		} else {
			if(hash_table_index_find(&ts_ht->ht, index, &v) == SUCCESS) {
				value_to_zval(&v, return_value);
			}
		}
		ts_hash_table_rd_unlock(ts_ht);
	}
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_get_or_set, 3)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, callback)
ZEND_ARG_TYPE_INFO(0, expire, IS_LONG, 0)
ZEND_ARG_VARIADIC_INFO(0, parameters)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_get_or_set) {
	zval *zv;
	zend_string *key = NULL;
	zend_long index = 0;

	zval retval;
	zend_fcall_info fci;
	zend_fcall_info_cache fci_cache;

	zend_long expire = 0;
	
	ts_hash_table_t *ts_ht;
	value_t v;

	ZEND_PARSE_PARAMETERS_START(3, -1)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_STR_OR_LONG(key, index)
		Z_PARAM_FUNC(fci, fci_cache)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(expire);
	#if PHP_VERSION_ID >= 80000
		Z_PARAM_VARIADIC_WITH_NAMED(fci.params, fci.param_count, fci.named_params)
	#else
		Z_PARAM_VARIADIC('*', fci.params, fci.param_count)
	#endif
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}
	
	fci.retval = &retval;

	ts_hash_table_rd_lock(ts_ht);
	if(key) {
		zend_long h = zend_get_hash_value(ZSTR_VAL(key), ZSTR_LEN(key));
		if(hash_table_quick_find(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h, &v) == SUCCESS) {
			value_to_zval(&v, return_value);
			ts_hash_table_rd_unlock(ts_ht);
		} else {
			ts_hash_table_rd_unlock(ts_ht);
			ts_hash_table_wr_lock(ts_ht);
			if(hash_table_quick_find(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h, &v) == SUCCESS) {
				value_to_zval(&v, return_value);
			} else {
				zend_try {
					if (zend_call_function(&fci, &fci_cache) == SUCCESS && Z_TYPE(retval) != IS_UNDEF) {
						if (Z_ISREF(retval)) {
							zend_unwrap_reference(&retval);
						}
						zval_to_value(&retval, &v);
						v.expire = expire;
						hash_table_quick_update(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h, &v, NULL);
						ZVAL_COPY_VALUE(return_value, &retval);
					}
				} zend_catch {
					EG(exit_status) = 0;
				} zend_end_try();
			}
			ts_hash_table_wr_unlock(ts_ht);
		}
	} else {
		if(hash_table_index_find(&ts_ht->ht, index, &v) == SUCCESS) {
			value_to_zval(&v, return_value);
			ts_hash_table_rd_unlock(ts_ht);
		} else {
			ts_hash_table_rd_unlock(ts_ht);
			ts_hash_table_wr_lock(ts_ht);
			if(hash_table_index_find(&ts_ht->ht, index, &v) == SUCCESS) {
				value_to_zval(&v, return_value);
			} else {
				zend_try {
					if (zend_call_function(&fci, &fci_cache) == SUCCESS && Z_TYPE(retval) != IS_UNDEF) {
						if (Z_ISREF(retval)) {
							zend_unwrap_reference(&retval);
						}
						zval_to_value(&retval, &v);
						v.expire = expire;
						hash_table_index_update(&ts_ht->ht, index, &v, NULL);
						ZVAL_COPY_VALUE(return_value, &retval);
					}
				} zend_catch {
					EG(exit_status) = 0;
				} zend_end_try();
			}
			ts_hash_table_wr_unlock(ts_ht);
		}
	}
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_del, 2)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_del) {
	zval *zv;
	zend_string *key = NULL;
	zend_long index = 0;
	
	ts_hash_table_t *ts_ht;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_STR_OR_LONG(key, index)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}

	ts_hash_table_wr_lock(ts_ht);
	if(key) {
		RETVAL_BOOL(hash_table_del(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key)) == SUCCESS);
	} else {
		RETVAL_BOOL(hash_table_index_del(&ts_ht->ht, index) == SUCCESS);
	}
	ts_hash_table_wr_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_inc, 3)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, val)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_inc) {
	zval *zv;
	zend_string *key = NULL;
	zend_long index = 0;
	zval *val;
	zend_bool is_null = 0;
	
	ts_hash_table_t *ts_ht;
	value_t v1,v2;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_STR_OR_LONG_OR_NULL(key, index, is_null)
		Z_PARAM_ZVAL(val)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}

	zval_to_value(val, &v1);

	ts_hash_table_wr_lock(ts_ht);
	if(is_null) {
		RETVAL_BOOL(hash_table_next_index_insert(&ts_ht->ht, &v1, NULL) == SUCCESS);
	} else if(key) {
		zend_long h = zend_get_hash_value(ZSTR_VAL(key), ZSTR_LEN(key));
		if(hash_table_quick_find(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h, &v2) == FAILURE) {
			if(hash_table_quick_update(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h, &v1, NULL) == SUCCESS) {
				value_to_zval_wr(&v1, return_value);
			}
		} else {
			value_add(&v2, &v1);
			if(v2.type != HT_T) {
				if(hash_table_quick_update(&ts_ht->ht, ZSTR_VAL(key), ZSTR_LEN(key), h, &v2, NULL) == SUCCESS) {
					value_to_zval_wr(&v2, return_value);
				}
			} else RETVAL_LONG(hash_table_num_elements(v2.ptr));
		}
	} else {
		if(hash_table_index_find(&ts_ht->ht, index, &v2) == FAILURE) {
			if(hash_table_index_update(&ts_ht->ht, index, &v1, NULL) == SUCCESS) {
				value_to_zval_wr(&v1, return_value);
			}
		} else {
			value_add(&v2, &v1);
			if(v2.type != HT_T) {
				if(hash_table_index_update(&ts_ht->ht, index, &v2, NULL) == SUCCESS) {
					value_to_zval_wr(&v2, return_value);
				}
			} else RETVAL_LONG(hash_table_num_elements(v2.ptr));
		}
	}
	ts_hash_table_wr_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_count, 1)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_count) {
	zval *zv;
	
	ts_hash_table_t *ts_ht;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_RESOURCE(zv)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}

	ts_hash_table_rd_lock(ts_ht);
	RETVAL_LONG(hash_table_num_elements(&ts_ht->ht));
	ts_hash_table_rd_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_clean, 1)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_TYPE_INFO(0, expire, IS_LONG, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_clean) {
	zval *zv;
	zend_long expire = 0;
	
	ts_hash_table_t *ts_ht;
	int n;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(expire)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}
	
	n = (int) expire;

	ts_hash_table_wr_lock(ts_ht);
	if(expire) hash_table_apply_with_argument(&ts_ht->ht, (hash_apply_func_arg_t) hash_table_clean_ex, &n);
	RETVAL_LONG(hash_table_num_elements(&ts_ht->ht));
	if(expire == 0) hash_table_clean(&ts_ht->ht);
	ts_hash_table_wr_unlock(ts_ht);
}

ZEND_BEGIN_ARG_INFO(arginfo_ts_var_reindex, 1)
ZEND_ARG_TYPE_INFO(0, res, IS_RESOURCE, 0)
ZEND_ARG_TYPE_INFO(0, only_integer_keys, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

static PHP_FUNCTION(ts_var_reindex) {
	zval *zv;
	zend_bool only_integer_keys = 0;
	
	ts_hash_table_t *ts_ht;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_RESOURCE(zv)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(only_integer_keys)
	ZEND_PARSE_PARAMETERS_END();
	
	if ((ts_ht = (ts_hash_table_t *) zend_fetch_resource_ex(zv, PHP_TS_VAR_DESCRIPTOR, le_ts_var_descriptor)) == NULL) {
		RETURN_FALSE;
	}
	
	ts_hash_table_wr_lock(ts_ht);
	hash_table_reindex(&ts_ht->ht, only_integer_keys);
	ts_hash_table_wr_unlock(ts_ht);

	RETURN_TRUE;
}

// ===========================================================================================================

static const zend_function_entry cgi_fcgi_sapi_functions[] = {
	PHP_FE(fastcgi_finish_request,                    cgi_fcgi_sapi_no_arginfo)
	PHP_FE(apache_request_headers,                    cgi_fcgi_sapi_no_arginfo)
	PHP_FALIAS(getallheaders, apache_request_headers, cgi_fcgi_sapi_no_arginfo)
	
	PHP_FE(share_var_exists, arginfo_share_var_exists)
	PHP_FE(share_var_get, arginfo_share_var_get)
	PHP_FE(share_var_get_and_del, arginfo_share_var_get_and_del)
	PHP_FE(share_var_put, arginfo_share_var_put)
	PHP_FE(share_var_inc, arginfo_share_var_inc)
	PHP_FE(share_var_set, arginfo_share_var_set)
	PHP_FE(share_var_set_ex, arginfo_share_var_set_ex)
	PHP_FE(share_var_del, arginfo_share_var_del)
	PHP_FE(share_var_clean, arginfo_share_var_clean)
	PHP_FE(share_var_count, arginfo_share_var_count)
	
	PHP_FE(ts_var_fd_close, arginfo_ts_var_fd_close)

	PHP_FE(ts_var_declare, arginfo_ts_var_declare)
	PHP_FE(ts_var_fd, arginfo_ts_var_fd)
	PHP_FE(ts_var_expire, arginfo_ts_var_expire)
	PHP_FE(ts_var_exists, arginfo_ts_var_exists)
	PHP_FE(ts_var_set, arginfo_ts_var_set)
	PHP_FALIAS(ts_var_put, ts_var_set, arginfo_ts_var_set)
	PHP_FE(ts_var_push, arginfo_ts_var_push)
	PHP_FE(ts_var_pop, arginfo_ts_var_pop)
	PHP_FE(ts_var_shift, arginfo_ts_var_shift)
	PHP_FE(ts_var_minmax, arginfo_ts_var_minmax)
	PHP_FE(ts_var_get, arginfo_ts_var_get)
	PHP_FE(ts_var_get_or_set, arginfo_ts_var_get_or_set)
	PHP_FE(ts_var_del, arginfo_ts_var_del)
	PHP_FE(ts_var_inc, arginfo_ts_var_inc)
	PHP_FE(ts_var_count, arginfo_ts_var_count)
	PHP_FE(ts_var_clean, arginfo_ts_var_clean)
	PHP_FE(ts_var_reindex, arginfo_ts_var_reindex)
	
	PHP_FE_END
};

static zend_module_entry cgi_module_entry = {
	STANDARD_MODULE_HEADER,
	"cgi-fcgi",
	cgi_fcgi_sapi_functions,
	PHP_MINIT(cgi),
	PHP_MSHUTDOWN(cgi),
	NULL,
	NULL,
	PHP_MINFO(cgi),
	PHP_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#define MICRO_IN_SEC 1000000.00

double microtime() {
	struct timeval tp = {0};

	if (gettimeofday(&tp, NULL)) {
		return 0;
	}

	return (double)(tp.tv_sec + tp.tv_usec / MICRO_IN_SEC) * 1000;
}

void thread_sigmask() {
	register int sig;
	sigset_t set;

	sigemptyset(&set);

	for(sig=SIGHUP; sig<=SIGSYS; sig++) {
		sigaddset(&set, sig);
	}

	pthread_sigmask(SIG_SETMASK, &set, NULL);
}

typedef struct _thread_arg_t {
	unsigned long int id;
	fcgi_request *request;
	int fd;
	double t;
	struct _thread_arg_t *next;
} thread_arg_t;

static int fcgi_fd = 0;
static unsigned int nthreads = 0, naccepts = 0;
static pthread_mutex_t lock, wlock;
static pthread_cond_t cond;
static sem_t rsem;
static unsigned int nrequests = 0;
static unsigned int requests = 0;
static thread_arg_t *head_request = NULL, *tail_request = NULL;
static thread_arg_t *head_wait = NULL, *tail_wait = NULL;
static zend_bool isRun = 1;
static zend_bool isReload = 0;
static zend_bool isAccess = 0;
static zend_bool isRealpath = 0;
static int idleseconds = 5;

static int max_threads = 64;
static unsigned long int req_id = 0;
static unsigned long int max_requests = 10000000;

static void *thread_request(void*_) {
	thread_arg_t *arg;
	zend_file_handle file_handle;
	char reqinfo[4096];
	char pidstr[20], tidstr[20];
	size_t pidlen = snprintf(pidstr, sizeof(pidstr), "Pid: %d", pthread_pid);
	size_t tidlen = snprintf(tidstr, sizeof(tidstr), "Tid: %d", pthread_tid);
	double t, t2, t3, t4, t5;
	struct timespec ts;
	char path[PATH_MAX], name[32];
	sapi_request_info *request_info;

	thread_sigmask();

	ts_resource(0);

	dprintf("thread begin\n");

	request_info = &SG(request_info);

	while(1) {
		if(!clock_gettime(CLOCK_REALTIME, &ts)) {
			ts.tv_sec += idleseconds;
			if(sem_timedwait(&rsem, &ts) && errno == EINTR) break;
		} else sem_wait(&rsem);

		pthread_mutex_lock(&lock);
		arg = head_request;
		if(arg) {
			if(arg == tail_request) {
				head_request = NULL;
				tail_request = NULL;
			} else {
				head_request = arg->next;
			}
		}
		pthread_mutex_unlock(&lock);
		
		if(arg == NULL) {
			break;
		}

		SG(server_context) = arg->request;

		dprintf("running request %lu %.3fms\n", arg->id, microtime() - arg->t);
		
		t = t2 = t3 = microtime();
		CGIG(body_fd) = -1;
		CGIG(response_length) = 0;
		init_request_info();

	    snprintf(name, sizeof(name), "%s %s", request_info->request_method, FCGI_GETENV(arg->request, "REQUEST_URI"));
	    prctl(PR_SET_NAME, (unsigned long) name);

		/* request startup only after we've done all we can to
		 *            get path_translated */
		if (UNEXPECTED(php_request_startup() == FAILURE)) {
			SG(server_context) = NULL;

			goto err;
		}

		/* check if request_method has been sent.
		 * if not, it's certainly not an HTTP over fcgi request */
		if (UNEXPECTED(!request_info->request_method)) {
			goto fastcgi_request_done;
		}

		/* If path_translated is NULL, terminate here with a 404 */
		if (UNEXPECTED(!request_info->path_translated)) {
			zend_first_try {
				fprintf(stderr, "Primary script unknown\n");
				SG(sapi_headers).http_response_code = 404;
				PUTS("File not found.\n");
			} zend_catch {
			} zend_end_try();
			goto fastcgi_request_done;
		}
		
	#ifndef THREADFPM_DEBUG
		if(UNEXPECTED(isAccess)) {
	#endif
			snprintf(reqinfo, sizeof(reqinfo), "[%s] %s %s %s %ld", FCGI_GETENV(arg->request, "SERVER_NAME"), FCGI_GETENV(arg->request, "REMOTE_ADDR"), request_info->request_method, FCGI_GETENV(arg->request, "REQUEST_URI"), request_info->content_length);

	#ifndef THREADFPM_DEBUG
		}
	#endif
		
		if(PG(expose_php)) {
			sapi_add_header(pidstr, pidlen, 1);
			sapi_add_header(tidstr, tidlen, 1);
		}

		t2 = microtime();

		zend_first_try {
			if(isRealpath) {
				if(realpath(request_info->path_translated, path)) {
					efree(request_info->path_translated);
					request_info->path_translated = estrdup(path);
				} else {
					goto noexists;
				}
			}

			if (UNEXPECTED(php_fopen_primary_script(&file_handle) == FAILURE)) {
				noexists:
				if (errno == EACCES) {
					SG(sapi_headers).http_response_code = 403;
					PUTS("Access denied.\n");
				} else {
					SG(sapi_headers).http_response_code = 404;
					PUTS("No input file specified.\n");
				}
			} else {
				php_execute_script(&file_handle);
			}
		} zend_end_try();

	fastcgi_request_done:
		t3 = microtime();

		if (UNEXPECTED(CGIG(body_fd) != -1)) {
			close(CGIG(body_fd));
		}
		CGIG(body_fd) = -2;

		if (UNEXPECTED(EG(exit_status) == 255)) {
			if (CGIG(error_header) && *CGIG(error_header)) {
				sapi_header_line ctr = {0};

				ctr.line = CGIG(error_header);
				ctr.line_len = strlen(CGIG(error_header));
				sapi_header_op(SAPI_HEADER_REPLACE, &ctr);
			}
		}

		efree(request_info->path_translated);
		request_info->path_translated = NULL;

		php_request_shutdown((void *) 0);

	err:
		t4 = microtime();
		
		pthread_mutex_lock(&lock);
		requests++;
		nrequests--;
		pthread_mutex_unlock(&lock);

		if(!fcgi_is_closed(arg->request)) {
			dprintf("is closed\n");
			zend_first_try {
				fcgi_accept_request(arg->request);
			} zend_end_try();
		}
		
		t5 = microtime();

		if(UNEXPECTED(isAccess)) {
			dprintf("%s %lu %.3f+%.3f+%.3f+%.3f+%.3f=%.3fms\n", reqinfo, CGIG(response_length), t - arg->t, t2 - t, t3 - t2, t4 - t3, t5 - t4, t5 - arg->t);
			printf("[%s] %d %s %lu %.3f+%.3f+%.3f+%.3f+%.3f=%.3fms\n", gettimeofstr(), pthread_tid, reqinfo, CGIG(response_length), t - arg->t, t2 - t, t3 - t2, t4 - t3, t5 - t4, t5 - arg->t);
			fflush(stdout);
		}

		arg->fd = -1;
		arg->next = NULL;
		
		pthread_mutex_lock(&wlock);
		if(head_wait) {
			arg->next = head_wait;
			head_wait = arg;
		} else {
			head_wait = arg;
			tail_wait = arg;
		}
		pthread_mutex_unlock(&wlock);
	}

	dprintf("thread end\n");

	ts_free_thread();

	pthread_mutex_lock(&lock);
	nthreads--;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);

	pthread_exit(NULL);
}

static void on_accept() {
	if(CGIG(is_accept) == 0) zend_bailout();

	dprintf("%s\n", __func__);
}

static void on_read() {
	dprintf("%s\n", __func__);
}

static void on_close() {
	dprintf("%s\n", __func__);
}

static zend_bool create_thread(void*(*handler)(void*), void* arg) {
	pthread_t thread;
	pthread_attr_t attr;
	int ret;
#ifdef THREADFPM_DEBUG
	double t = 0;
#endif

	dprintf("pthread_create begin\n");

#ifdef THREADFPM_DEBUG
	if(UNEXPECTED(isDebug)) t = microtime();
#endif
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&thread, &attr, handler, arg);
	if(ret) {
		errno = ret;
		perror("pthread_create() is error");
		errno = 0;
	}
	pthread_attr_destroy(&attr);

	dprintf("pthread_create end %.3fms\n", microtime() - t);

	return ret == 0;
}

static void *thread_accept(void*_i) {
	thread_arg_t *arg;
	char name[32];

	snprintf(name, sizeof(name), "accept%d", (int)_i);
	prctl(PR_SET_NAME, (unsigned long) name);
	
	pthread_mutex_lock(&lock);
	naccepts++;
	pthread_mutex_unlock(&lock);

	thread_sigmask();

	ts_resource(0);
	
	CGIG(is_accept) = 1;
	
	dprintf("thread begin\n");

	while(isRun) {
		pthread_mutex_lock(&wlock);
		arg = head_wait;
		if(arg) {
			if(arg == tail_wait) {
				head_wait = NULL;
				tail_wait = NULL;
			} else {
				head_wait = arg->next;
			}
			arg->id = req_id++;
		}
		pthread_mutex_unlock(&wlock);

		if(arg == NULL) {
			usleep(100);
			continue;
		}

		arg->t = microtime();
		arg->next = NULL;
		arg->fd = fcgi_accept_request(arg->request);
		
		if(arg->fd <= 0) {
			break;
		}

		dprintf("accepted request %lu %.3fms %d\n", arg->id, microtime() - arg->t, arg->fd);

		pthread_mutex_lock(&lock);
		nrequests++;
		if(tail_request) {
			tail_request->next = arg;
			tail_request = arg;
		} else {
			head_request = arg;
			tail_request = arg;
		}
		pthread_mutex_unlock(&lock);
		
		sem_post(&rsem);

		pthread_mutex_lock(&lock);
		if(nthreads < max_threads && nrequests > nthreads) {
		#ifdef THREADFPM_DEBUG
			if(nthreads == 0) {
				dprintf("\n\n======================================\n\n");
			}
		#endif
			
			nthreads++;
			pthread_mutex_unlock(&lock);
			
			if(!create_thread(thread_request, NULL)) {
				pthread_mutex_lock(&lock);
				nthreads--;
				pthread_mutex_unlock(&lock);
			}
		} else pthread_mutex_unlock(&lock);
	}
	
	dprintf("thread end\n");

	ts_free_thread();
	
	pthread_mutex_lock(&lock);
	naccepts--;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);

	pthread_exit(NULL);
}

static void signal_handler(int sig) {
	switch(sig) {
		case SIGINT:
			dprintf("signal SIGINT\n");
			break;
		case SIGTERM:
			dprintf("signal SIGTERM\n");
			break;
		case SIGUSR1:
			dprintf("signal SIGUSR1\n");
			break;
		case SIGUSR2:
			dprintf("signal SIGUSR2\n");
			break;
	}
	
	isRun = 0;
	
	if(!isReload) isReload = (sig == SIGUSR1 || sig == SIGUSR2);
}

/* {{{ main
 */
int main(int argc, char *argv[])
{
	int exit_status = FPM_EXIT_OK;
	int cgi = 0, c, use_extended_info = 0;

	/* temporary locals */
	int orig_optind = php_optind;
	char *orig_optarg = php_optarg;
	int ini_entries_len = 0;
	/* end of temporary locals */

	int php_information = 0;

	int max_accepts = 4;

	const char *path = "127.0.0.1:9000";
	int backlog = 256;

	int ret;

	sigset_t waitset;
	siginfo_t waitinfo;
	struct timespec timeout;

	char *pidfile = NULL;

	unsigned int reqs, nreqs, threads, accepts, nwaits;
	unsigned long int max_reqs = 0;
	double t;
	
	thread_arg_t *wargs;

	const int REQC = 10;
	unsigned int reqv[REQC], reqc = 0, reqi = 0, reqn = 0;

#if defined(SIGPIPE) && defined(SIG_IGN)
	signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE in standalone mode so
								that sockets created via fsockopen()
								don't kill PHP if the remote site
								closes it.  in apache|apxs mode apache
								does that for us!  thies@thieso.net
								20000419 */
#endif

	php_tsrm_startup();

	zend_signal_startup();

	sapi_startup(&cgi_sapi_module);
	cgi_sapi_module.php_ini_path_override = NULL;
	cgi_sapi_module.php_ini_ignore_cwd = 1;

#ifndef HAVE_ATTRIBUTE_WEAK
	fcgi_set_logger(fpm_fcgi_log);
#endif

	fcgi_init();

	while ((c = php_getopt(argc, argv, OPTIONS, &php_optarg, &php_optind, 0, 2)) != -1) {
		switch (c) {
			case 'c':
				if (cgi_sapi_module.php_ini_path_override) {
					free(cgi_sapi_module.php_ini_path_override);
				}
				cgi_sapi_module.php_ini_path_override = strdup(php_optarg);
				break;

			case 'n':
				cgi_sapi_module.php_ini_ignore = 1;
				break;

			case 'd': {
				/* define ini entries on command line */
				int len = strlen(php_optarg);
				char *val;

				if ((val = strchr(php_optarg, '='))) {
					val++;
					if (!isalnum(*val) && *val != '"' && *val != '\'' && *val != '\0') {
						cgi_sapi_module.ini_entries = realloc(cgi_sapi_module.ini_entries, ini_entries_len + len + sizeof("\"\"\n\0"));
						memcpy(cgi_sapi_module.ini_entries + ini_entries_len, php_optarg, (val - php_optarg));
						ini_entries_len += (val - php_optarg);
						memcpy(cgi_sapi_module.ini_entries + ini_entries_len, "\"", 1);
						ini_entries_len++;
						memcpy(cgi_sapi_module.ini_entries + ini_entries_len, val, len - (val - php_optarg));
						ini_entries_len += len - (val - php_optarg);
						memcpy(cgi_sapi_module.ini_entries + ini_entries_len, "\"\n\0", sizeof("\"\n\0"));
						ini_entries_len += sizeof("\n\0\"") - 2;
					} else {
						cgi_sapi_module.ini_entries = realloc(cgi_sapi_module.ini_entries, ini_entries_len + len + sizeof("\n\0"));
						memcpy(cgi_sapi_module.ini_entries + ini_entries_len, php_optarg, len);
						memcpy(cgi_sapi_module.ini_entries + ini_entries_len + len, "\n\0", sizeof("\n\0"));
						ini_entries_len += len + sizeof("\n\0") - 2;
					}
				} else {
					cgi_sapi_module.ini_entries = realloc(cgi_sapi_module.ini_entries, ini_entries_len + len + sizeof("=1\n\0"));
					memcpy(cgi_sapi_module.ini_entries + ini_entries_len, php_optarg, len);
					memcpy(cgi_sapi_module.ini_entries + ini_entries_len + len, "=1\n\0", sizeof("=1\n\0"));
					ini_entries_len += len + sizeof("=1\n\0") - 2;
				}
				break;
			}

			case 'e': /* enable extended info output */
				use_extended_info = 1;
				break;

			case 'm': /* list compiled in modules */
				cgi_sapi_module.startup(&cgi_sapi_module);
				php_output_activate();
				SG(headers_sent) = 1;
				php_printf("[PHP Modules]\n");
				print_modules();
				php_printf("\n[Zend Modules]\n");
				print_extensions();
				php_printf("\n");
				php_output_end_all();
				php_output_deactivate();
				fcgi_shutdown();
				exit_status = FPM_EXIT_OK;
				goto out;

			case 'i': /* php info & quit */
				php_information = 1;
				break;

			case 'R':
				isRealpath = 1;
				break;

			case 'P':
				pidfile = php_optarg;
				break;

			case 'u': {
				pid_t pid = fork();
				if(pid < 0) {
					perror("fork");
					break;
				} else if(pid > 0) {
					if(pidfile) {
						FILE *fp = fopen(pidfile, "wb");
						if(fp) {
							fprintf(fp, "%d", pid);
							fclose(fp);
						} else {
							fprintf(stderr, "fopen(%s): %s\n", pidfile, strerror(errno));
							fflush(stderr);
						}
					}
					goto out;
				}
				struct passwd *pwnam;
				pwnam = getpwnam(php_optarg);

				if (!pwnam) {
					perror("getpwnam");
					break;
				}

				if(setuid(pwnam->pw_uid)) perror("setuid");
				// if(setgid(pwnam->pw_gid)) perror("setgid");
				if (setsid() < 0) perror("setsid");
				break;
			}

			case 'a':
				max_accepts = atoi(php_optarg);
				if(max_accepts < 1) {
					max_accepts = 1;
				}
				break;

			case 't':
				max_threads = atoi(php_optarg);
				if(max_threads < 1) {
					max_threads = 1;
				}
				break;

			case 'I':
				idleseconds = atoi(php_optarg);
				if(idleseconds < 1) {
					idleseconds = 1;
				}
				break;
				
			case 'r':
				max_requests = strtol(php_optarg, NULL, 10);
				if(max_requests < 100) {
					max_requests = 100;
				}
				break;

			case 'p':
				path = php_optarg;
				break;

			case 'b':
				backlog = atoi(php_optarg);
				break;

		#ifdef THREADFPM_DEBUG
			case 'D':
				isDebug = 1;
				break;
		#endif
		
			case 'A':
				isAccess = 1;
				break;

			default:
			case 'h':
			case '?':
			case PHP_GETOPT_INVALID_ARG:
				cgi_sapi_module.startup(&cgi_sapi_module);
				php_output_activate();
				SG(headers_sent) = 1;
				php_cgi_usage(argv[0]);
				php_output_end_all();
				php_output_deactivate();
				fcgi_shutdown();
				exit_status = (c != PHP_GETOPT_INVALID_ARG) ? FPM_EXIT_OK : FPM_EXIT_USAGE;
				goto out;

			case 'v': /* show php version & quit */
				cgi_sapi_module.startup(&cgi_sapi_module);
				if (php_request_startup() == FAILURE) {
					SG(server_context) = NULL;
					php_module_shutdown();
					return FPM_EXIT_SOFTWARE;
				}
				SG(headers_sent) = 1;
				SG(request_info).no_headers = 1;

#if ZEND_DEBUG
				php_printf("PHP %s (%s) (built: %s %s) (DEBUG)\nCopyright (c) The PHP Group\n%s", PHP_VERSION, sapi_module.name, __DATE__,        __TIME__, get_zend_version());
#else
				php_printf("PHP %s (%s) (built: %s %s)\nCopyright (c) The PHP Group\n%s", PHP_VERSION, sapi_module.name, __DATE__, __TIME__,      get_zend_version());
#endif
				php_request_shutdown((void *) 0);
				fcgi_shutdown();
				exit_status = FPM_EXIT_OK;
				goto out;
		}
	}

	if (php_information) {
		cgi_sapi_module.phpinfo_as_text = 1;
		cgi_sapi_module.startup(&cgi_sapi_module);
		if (php_request_startup() == FAILURE) {
			SG(server_context) = NULL;
			php_module_shutdown();
			return FPM_EXIT_SOFTWARE;
		}
		SG(headers_sent) = 1;
		SG(request_info).no_headers = 1;
		php_print_info(0xFFFFFFFF);
		php_request_shutdown((void *) 0);
		fcgi_shutdown();
		exit_status = FPM_EXIT_OK;
		goto out;
	}

	/* No other args are permitted here as there is no interactive mode */
	if (argc != php_optind) {
		cgi_sapi_module.startup(&cgi_sapi_module);
		php_output_activate();
		SG(headers_sent) = 1;
		php_cgi_usage(argv[0]);
		php_output_end_all();
		php_output_deactivate();
		fcgi_shutdown();
		exit_status = FPM_EXIT_USAGE;
		goto out;
	}

	php_optind = orig_optind;
	php_optarg = orig_optarg;

	SG(request_info).path_translated = NULL;

	cgi_sapi_module.additional_functions = NULL;
	cgi_sapi_module.executable_location = argv[0];

	/* startup after we get the above ini override se we get things right */
	if (cgi_sapi_module.startup(&cgi_sapi_module) == FAILURE) {
		tsrm_shutdown();
		return FPM_EXIT_SOFTWARE;
	}

	if (use_extended_info) {
		CG(compiler_options) |= ZEND_COMPILE_EXTENDED_INFO;
	}

	/* check force_cgi after startup, so we have proper output */
	if (cgi && CGIG(force_redirect)) {
		/* Apache will generate REDIRECT_STATUS,
		 * Netscape and redirect.so will generate HTTP_REDIRECT_STATUS.
		 * redirect.so and installation instructions available from
		 * http://www.koehntopp.de/php.
		 *   -- kk@netuse.de
		 */
		if (!getenv("REDIRECT_STATUS") &&
			!getenv ("HTTP_REDIRECT_STATUS") &&
			/* this is to allow a different env var to be configured
			 * in case some server does something different than above */
			(!CGIG(redirect_status_env) || !getenv(CGIG(redirect_status_env)))
		) {
			zend_try {
				SG(sapi_headers).http_response_code = 400;
				PUTS("<b>Security Alert!</b> The PHP CGI cannot be accessed directly.\n\n\
<p>This PHP CGI binary was compiled with force-cgi-redirect enabled.  This\n\
means that a page will only be served up if the REDIRECT_STATUS CGI variable is\n\
set, e.g. via an Apache Action directive.</p>\n\
<p>For more information as to <i>why</i> this behaviour exists, see the <a href=\"http://php.net/security.cgi-bin\">\
manual page for CGI security</a>.</p>\n\
<p>For more information about changing this behaviour or re-enabling this webserver,\n\
consult the installation file that came with this distribution, or visit \n\
<a href=\"http://php.net/install.windows\">the manual page</a>.</p>\n");
			} zend_catch {
			} zend_end_try();
#ifndef PHP_DEBUG
			/* XXX we're crashing here in msvc6 debug builds at
			 * php_message_handler_for_zend:839 because
			 * SG(request_info).path_translated is an invalid pointer.
			 * It still happens even though I set it to null, so something
			 * weird is going on.
			 */
			tsrm_shutdown();
#endif
			return FPM_EXIT_SOFTWARE;
		}
	}

	fpm_is_running = 1;

	fcgi_fd = fcgi_listen(path, backlog);
	parent = 0;

	if(fcgi_fd <= 0) goto out;

	/* make php call us to get _ENV vars */
	php_php_import_environment_variables = php_import_environment_variables;
	php_import_environment_variables = cgi_php_import_environment_variables;

	pthread_mutex_init(&lock, NULL);
	pthread_mutex_init(&wlock, NULL);
	pthread_cond_init(&cond, NULL);
	sem_init(&rsem, 0, 0);

	share_var_init();
	ts_hash_table_init(&ts_var, 2);

	thread_sigmask();
	
	sigemptyset(&waitset);
	sigaddset(&waitset, SIGINT);
	sigaddset(&waitset, SIGTERM);
	sigaddset(&waitset, SIGUSR1);
	sigaddset(&waitset, SIGUSR2);
	
	nwaits = max_accepts + max_threads * 2 + backlog;
	wargs = (thread_arg_t*)malloc(sizeof(thread_arg_t) * nwaits);
	head_wait = &wargs[0];
	wargs[0].request = fcgi_init_request(fcgi_fd, on_accept, on_read, on_close);
	wargs[0].fd = -1;
	wargs[0].id = 0;
	wargs[0].t = 0;
	for(c=1; c<nwaits; c++) {
		wargs[c].request = fcgi_init_request(fcgi_fd, on_accept, on_read, on_close);
		wargs[c].fd = -1;
		wargs[c].id = 0;
		wargs[c].t = 0;
		wargs[c-1].next = &wargs[c];
	}
	tail_wait = &wargs[nwaits-1];
	tail_wait->next = NULL;

	for(ret=0; ret<max_accepts; ret++) {
		create_thread(thread_accept, NULL + ret);
	}
	
	fprintf(stderr, "[%s] The server running for listen %s backlog %d\n", gettimeofstr(), path, backlog);
	fflush(stderr);
	
	memset(reqv, 0, sizeof(reqv));

	t = microtime();
	while(isRun) {
		sigprocmask(SIG_BLOCK, &waitset, NULL);
		timeout.tv_sec = 0;
		timeout.tv_nsec = 1000000000lu - (microtime() - t) * 1000000;
		if(sigtimedwait(&waitset, &waitinfo, &timeout) > 0) {
			signal_handler(waitinfo.si_signo);
		}
		t = microtime();
		
	    pthread_mutex_lock(&lock);
	    reqs = requests; // complete of requests
	    nreqs = nrequests; // running of requests
		requests = 0;
		threads = nthreads;
		accepts = naccepts;
    	pthread_mutex_unlock(&lock);
    	
    	reqc -= reqv[reqi];
    	reqc += reqs;
    	reqv[reqi++] = reqs;
    	
    	if(reqi == REQC) {
    		reqi = 0;
    		reqn = REQC;
    	} else if(reqn < REQC) {
    		reqn = reqi;
    	}

		fprintf(stderr, "[%s] STAT: Running %u requests, completed %u requests/second, avg %.1f requests/second, %u worker threads, %u accept threads, %d share vars\n", gettimeofstr(), nreqs, reqs, (float) reqc / (float) reqn, threads, accepts, share_var_clean_ex() + ts_var_clean_ex());
		fflush(stderr);
		
		max_reqs += reqs;
		
		if(threads == 0 && max_reqs >= max_requests) {
			isRun = 0;
			isReload = 1;
			break;
		}
	}

	shutdown(fcgi_fd, SHUT_RDWR);
	close(fcgi_fd);
	fcgi_fd = -1;
	
	pthread_mutex_lock(&lock);
	for(ret=0; ret<nthreads; ret++) sem_post(&rsem);
	while(nthreads > 0 || naccepts > 0) pthread_cond_wait(&cond, &lock);
	pthread_mutex_unlock(&lock);

	for(c=0; c<nwaits; c++) {
		fcgi_destroy_request(wargs[c].request);
		if(wargs[c].fd > 0) {
			shutdown(wargs[c].fd, SHUT_RDWR);
			close(wargs[c].fd);
		}
	}
	free(wargs);

	fprintf(stderr, "[%s] The server stoped\n", gettimeofstr());
	fflush(stderr);
	
	ts_hash_table_destroy_ex(&ts_var, 0);
	share_var_destory();

	fcgi_shutdown();

	if (cgi_sapi_module.php_ini_path_override) {
		free(cgi_sapi_module.php_ini_path_override);
	}
	if (cgi_sapi_module.ini_entries) {
		free(cgi_sapi_module.ini_entries);
	}

	pthread_cond_destroy(&cond);
	pthread_mutex_destroy(&wlock);
	pthread_mutex_destroy(&lock);
	sem_destroy(&rsem);

	if(isReload) {
		fprintf(stderr, "[%s] The server reloading\n", gettimeofstr());
		fflush(stderr);

		char **args = (char**) malloc(sizeof(char*)*(argc+1));
		memcpy(args, argv, sizeof(char*)*argc);
		args[argc] = NULL;
		char path[PATH_MAX];
		size_t sz = readlink("/proc/self/exe", path, PATH_MAX);
		path[sz] = '\0';
		execv(path, args);
		perror("execv");
	}

out:

	SG(server_context) = NULL;
	php_module_shutdown();

	if (parent) {
		sapi_shutdown();
	}

	tsrm_shutdown();

	return exit_status;
}
/* }}} */
