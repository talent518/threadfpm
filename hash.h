#ifndef _HASH_H
#define _HASH_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <php.h>
#include <zend_types.h>

typedef unsigned long int ulong;

typedef struct string_t {
	unsigned int len;
	char str[1];
} string_t;

typedef enum {
	NULL_T=0,
	BOOL_T,
	LONG_T,
	DOUBLE_T,
	STR_T,
	HT_T,
	SERI_T,
	TS_HT_T
} type_t;

typedef struct value_t {
	type_t type;
	int expire;
	union {
		zend_bool b;
		long int l;
		double d;
		string_t *str;
		void *ptr;
	};
} value_t;

typedef struct bucket_t {
	ulong h;						/* Used for numeric indexing */
	value_t value;
	struct bucket_t *pListNext;
	struct bucket_t *pListLast;
	struct bucket_t *pNext;
	struct bucket_t *pLast;
	uint nKeyLength;
	char arKey[1];
} bucket_t;

typedef void (*hash_dtor_func_t)(value_t *pDest);

typedef struct hash_table_t {
	uint nTableSize;
	uint nTableMask;
	uint nNumOfElements;
	ulong nNextFreeElement;
	bucket_t *pListHead;
	bucket_t *pListTail;
	bucket_t **arBuckets;
	hash_dtor_func_t pDestructor;
} hash_table_t;

void hash_table_value_free(value_t *value);

/* startup/shutdown */
int _hash_table_init(hash_table_t *ht, uint nSize, hash_dtor_func_t pDestructor);
void hash_table_destroy(hash_table_t *ht);
void hash_table_clean(hash_table_t *ht);
#define hash_table_init(ht, nSize)                  _hash_table_init((ht), (nSize), hash_table_value_free)
#define hash_table_init_ex(ht, nSize, pDestructor)  _hash_table_init((ht), (nSize), (pDestructor))

#define HASH_TABLE_ADD           1
#define HASH_TABLE_UPDATE        2
#define HASH_TABLE_NEXT_INSERT   4

/* additions/updates/changes */
int _hash_table_add_or_update(hash_table_t *ht, const char *arKey, uint nKeyLength, value_t *pData, int flag);
#define hash_table_update(ht, arKey, nKeyLength, pData, pDest) \
		_hash_table_add_or_update(ht, arKey, nKeyLength, pData, HASH_TABLE_UPDATE)
#define hash_table_add(ht, arKey, nKeyLength, pData, pDest) \
		_hash_table_add_or_update(ht, arKey, nKeyLength, pData, HASH_TABLE_ADD)

int _hash_table_quick_add_or_update(hash_table_t *ht, const char *arKey, uint nKeyLength, ulong h, value_t *pData, int flag);
#define hash_table_quick_update(ht, arKey, nKeyLength, h, pData, pDest) \
		_hash_table_quick_add_or_update(ht, arKey, nKeyLength, h, pData, HASH_TABLE_UPDATE)
#define hash_table_quick_add(ht, arKey, nKeyLength, h, pData, pDest) \
		_hash_table_quick_add_or_update(ht, arKey, nKeyLength, h, pData, HASH_TABLE_ADD)

int _hash_table_index_update_or_next_insert(hash_table_t *ht, ulong h, value_t *pData, int flag);
#define hash_table_index_update(ht, h, pData, pDest) \
		_hash_table_index_update_or_next_insert(ht, h, pData, HASH_TABLE_UPDATE)
#define hash_table_next_index_insert(ht, pData, pDest) \
		_hash_table_index_update_or_next_insert(ht, 0, pData, HASH_TABLE_NEXT_INSERT)

#define HASH_TABLE_APPLY_KEEP				1
#define HASH_TABLE_APPLY_REMOVE				2
#define HASH_TABLE_APPLY_STOP				4

typedef int (*hash_apply_func_t)(bucket_t *pDest);
typedef int (*hash_apply_func_arg_t)(bucket_t *pDest, void *argument);
typedef int (*hash_apply_func_args_t)(bucket_t *pDest, int num_args, va_list args);

void hash_table_apply(hash_table_t *ht, hash_apply_func_t apply_func);
void hash_table_apply_with_argument(hash_table_t *ht, hash_apply_func_arg_t apply_func, void *);
void hash_table_apply_with_arguments(hash_table_t *ht, hash_apply_func_args_t apply_func, int, ...);

#define HASH_TABLE_DEL_KEY             1
#define HASH_TABLE_DEL_KEY_QUICK       2
#define HASH_TABLE_DEL_INDEX           4

/* Deletes */
int hash_table_del_key_or_index(hash_table_t *ht, const char *arKey, uint nKeyLength, ulong h, int flag);
#define hash_table_del(ht, arKey, nKeyLength) \
		hash_table_del_key_or_index(ht, arKey, nKeyLength, 0, HASH_TABLE_DEL_KEY)
#define hash_table_quick_del(ht, arKey, nKeyLength, h) \
		hash_table_del_key_or_index(ht, arKey, nKeyLength, h, HASH_TABLE_DEL_KEY_QUICK)
#define hash_table_index_del(ht, h) \
		hash_table_del_key_or_index(ht, NULL, 0, h, HASH_TABLE_DEL_INDEX)
#define zend_get_hash_value(s,l) hash_table_func(s,l)

/* Data retreival */
int hash_table_find(const hash_table_t *ht, const char *arKey, uint nKeyLength, value_t *pData);
int hash_table_quick_find(const hash_table_t *ht, const char *arKey, uint nKeyLength, ulong h, value_t *pData);
int hash_table_index_find(const hash_table_t *ht, ulong h, value_t *pData);

/* Misc */
int hash_table_exists(const hash_table_t *ht, const char *arKey, uint nKeyLength);
int hash_table_quick_exists(const hash_table_t *ht, const char *arKey, uint nKeyLength, ulong h);
int hash_table_index_exists(const hash_table_t *ht, ulong h);
ulong hash_table_next_free_element(const hash_table_t *ht);

int hash_table_num_elements(const hash_table_t *ht);

void hash_table_reindex(hash_table_t *ht, zend_bool only_integer_keys);

ulong hash_table_func(const char *arKey, uint nKeyLength);

static zend_always_inline void hash_table_bucket_delete(hash_table_t *ht, bucket_t *p) {
	if (p->pLast) {
		p->pLast->pNext = p->pNext;
	} else {
		ht->arBuckets[p->h & ht->nTableMask] = p->pNext;
	}
	if (p->pNext) {
		p->pNext->pLast = p->pLast;
	}
	if (p->pListLast != NULL) {
		p->pListLast->pListNext = p->pListNext;
	} else {
		/* Deleting the head of the list */
		ht->pListHead = p->pListNext;
	}
	if (p->pListNext != NULL) {
		p->pListNext->pListLast = p->pListLast;
	} else {
		/* Deleting the tail of the list */
		ht->pListTail = p->pListLast;
	}
	ht->nNumOfElements--;
	if (ht->pDestructor) {
		ht->pDestructor(&p->value);
	}
	free(p);
}

typedef int (*hash_compare_func_t)(const bucket_t *a, const bucket_t *b);

int compare_key(const bucket_t *a, const bucket_t *b);
int compare_value(const bucket_t *a, const bucket_t *b);
int hash_table_minmax(const hash_table_t *ht, hash_compare_func_t compar, int flag, bucket_t **ret);
int hash_table_sort(hash_table_t *ht, hash_compare_func_t compar, int reverse);

// ===========================================================================================================

#include <pthread.h>
#include <time.h>
#include <zend_exceptions.h>

#if defined(LOCK_TIMEOUT) && LOCK_TIMEOUT <= 0
#undef LOCK_TIMEOUT
#endif

#ifdef LOCK_TIMEOUT
typedef struct _tskey_hash_table_t {
	hash_table_t ht;
	pthread_mutex_t lock;
} tskey_hash_table_t;
#endif

typedef struct ts_hash_table_t {
	hash_table_t ht;
	int expire;
	volatile unsigned short rd_count;
	volatile unsigned short ref_count; // reference count
	pthread_mutex_t wlock;
	pthread_mutex_t rlock;
	int fds[2];
#ifdef LOCK_TIMEOUT
	tskey_hash_table_t *tsht;
	ulong h;
#endif
} ts_hash_table_t;

static zend_always_inline int _ts_hash_table_init(ts_hash_table_t *ts_ht, uint nSize, hash_dtor_func_t pDestructor) {
	ts_ht->rd_count = 0;
	ts_ht->ref_count = 1;
	ts_ht->fds[0] = 0;
	ts_ht->fds[1] = 0;
	ts_ht->expire = 0;
#ifdef LOCK_TIMEOUT
	ts_ht->tsht = NULL;
	ts_ht->h = hash_table_func((const char*) &ts_ht, sizeof(void*));
#endif
	pthread_mutex_init(&ts_ht->rlock, NULL);
	pthread_mutex_init(&ts_ht->wlock, NULL);
	return _hash_table_init(&ts_ht->ht, nSize, pDestructor);
}

#define ts_hash_table_init(ht, nSize)                  _ts_hash_table_init((ht), (nSize), hash_table_value_free)
#define ts_hash_table_init_ex(ht, nSize, pDestructor)  _ts_hash_table_init((ht), (nSize), (pDestructor))

static zend_always_inline void ts_hash_table_lock(ts_hash_table_t *ts_ht) {
	pthread_mutex_lock(&ts_ht->rlock);
}

static zend_always_inline void ts_hash_table_unlock(ts_hash_table_t *ts_ht) {
	pthread_mutex_unlock(&ts_ht->rlock);
}

#ifdef LOCK_TIMEOUT
extern pthread_key_t tskey;
void ts_table_table_tid_destroy(void *hh);
long int ts_table_table_tid_inc(ts_hash_table_t *hh);
long int ts_table_table_tid_dec_ex(tskey_hash_table_t *tsht, ts_hash_table_t *hh);
#define ts_table_table_tid_dec(ht) ts_table_table_tid_dec_ex(pthread_getspecific(tskey), ht)
const char *gettimeofstr();
void ts_hash_table_deadlock(const char *msg);
#endif

static zend_always_inline void ts_hash_table_wr_lock(ts_hash_table_t *ts_ht) {
#ifndef LOCK_TIMEOUT
	pthread_mutex_lock(&ts_ht->wlock);
#else
	// printf("%p   lock\n", ts_ht);
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += LOCK_TIMEOUT;
	if(pthread_mutex_timedlock(&ts_ht->wlock, &ts)) {
		if(ts_table_table_tid_inc(ts_ht) == 1) {
			ts_hash_table_deadlock("Deadlock caused by shared variables");
		} else {
			ts_hash_table_deadlock("Repeated locking of shared variables");
		}
		pthread_mutex_lock(&ts_ht->wlock);
	} else {
		ts_table_table_tid_inc(ts_ht);
	}
	ts_ht->tsht = pthread_getspecific(tskey);
#endif
}

static zend_always_inline void ts_hash_table_wr_unlock(ts_hash_table_t *ts_ht) {
#ifndef LOCK_TIMEOUT
	pthread_mutex_unlock(&ts_ht->wlock);
#else
	long int i = ts_table_table_tid_dec(ts_ht);
	if(i == 0) {
		ts_ht->tsht = NULL;
		// printf("%p unlock\n", ts_ht);
		pthread_mutex_unlock(&ts_ht->wlock);
	} else if(i < 0) {
		i = ts_table_table_tid_dec_ex(ts_ht->tsht, ts_ht);
		if(i == 0) {
			ts_ht->tsht = NULL;
			// printf("%p unlock\n", ts_ht);
			pthread_mutex_unlock(&ts_ht->wlock);
		} else if(i < 0) {
			ts_hash_table_deadlock("Shared variable unlocking exception");
		}
	}
#endif
}

static zend_always_inline void ts_hash_table_rd_lock(ts_hash_table_t *ts_ht) {
	pthread_mutex_lock(&ts_ht->rlock);
	if((++ts_ht->rd_count) == 1) ts_hash_table_wr_lock(ts_ht);
	pthread_mutex_unlock(&ts_ht->rlock);
}

static zend_always_inline void ts_hash_table_rd_unlock(ts_hash_table_t *ts_ht) {
	pthread_mutex_lock(&ts_ht->rlock);
	if((--ts_ht->rd_count) == 0) ts_hash_table_wr_unlock(ts_ht);
	pthread_mutex_unlock(&ts_ht->rlock);
}

static zend_always_inline void ts_hash_table_ref(ts_hash_table_t *ts_ht) {
	ts_hash_table_lock(ts_ht);
	ts_ht->ref_count++;
	ts_hash_table_unlock(ts_ht);
}

#define ts_hash_table_unref(ts_ht) ts_hash_table_destroy(ts_ht)

static zend_always_inline void ts_hash_table_destroy_ex(ts_hash_table_t *ts_ht, int is_free) {
	ts_hash_table_lock(ts_ht);
	if(--ts_ht->ref_count == 0) {
		ts_hash_table_unlock(ts_ht);

		if(ts_ht->fds[0] > 0) close(ts_ht->fds[0]);
		if(ts_ht->fds[1] > 0) close(ts_ht->fds[1]);

		pthread_mutex_destroy(&ts_ht->rlock);
		pthread_mutex_destroy(&ts_ht->wlock);
		hash_table_destroy(&ts_ht->ht);
		
		if(is_free) free(ts_ht);
	} else ts_hash_table_unlock(ts_ht);
}

#define ts_hash_table_destroy(ts_ht) ts_hash_table_destroy_ex(ts_ht, 1)

#endif							/* _HASH_H */
