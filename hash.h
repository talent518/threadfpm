#ifndef _HASH_H
#define _HASH_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zend_types.h>

typedef unsigned long int ulong;

typedef struct string_t {
	unsigned int len;
	char str[1];
} string_t;

typedef enum {
	NULL_T=0,
	BOOL_T,
	CHAR_T,
	SHORT_T,
	INT_T,
	LONG_T,
	FLOAT_T,
	DOUBLE_T,
	STR_T,
	HT_T,
	PTR_T,
	SERI_T,
} type_t;

typedef struct value_t {
	type_t type;
	union {
		zend_bool b;
		char c;
		short s;
		int i;
		long int l;
		float f;
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
	bucket_t *pInternalPointer;	/* Used for element traversal */
	bucket_t *pListHead;
	bucket_t *pListTail;
	bucket_t **arBuckets;
	hash_dtor_func_t pDestructor;
	unsigned char nApplyCount;
	zend_bool bApplyProtection;
} hash_table_t;

void hash_table_value_free(value_t *value);

/* startup/shutdown */
int _hash_table_init(hash_table_t *ht, uint nSize, hash_dtor_func_t pDestructor, zend_bool bApplyProtection);
void hash_table_destroy(hash_table_t *ht);
void hash_table_clean(hash_table_t *ht);
#define hash_table_init(ht, nSize)                                       _hash_table_init((ht), (nSize), hash_table_value_free, 0)
#define hash_table_init_ex(ht, nSize, pDestructor, bApplyProtection)     _hash_table_init((ht), (nSize), (pDestructor), (bApplyProtection))

void hash_table_set_apply_protection(hash_table_t *ht, zend_bool bApplyProtection);

#define HASH_TABLE_ADD           1
#define HASH_TABLE_UPDATE        2
#define HASH_TABLE_NEXT_INSERT   4

/* additions/updates/changes */
int _hash_table_add_or_update(hash_table_t *ht, const char *arKey, uint nKeyLength, value_t *pData, value_t *pDest, int flag);
#define hash_table_update(ht, arKey, nKeyLength, pData, pDest) \
		_hash_table_add_or_update(ht, arKey, nKeyLength, pData, pDest, HASH_TABLE_UPDATE)
#define hash_table_add(ht, arKey, nKeyLength, pData, pDest) \
		_hash_table_add_or_update(ht, arKey, nKeyLength, pData, pDest, HASH_TABLE_ADD)

int _hash_table_quick_add_or_update(hash_table_t *ht, const char *arKey, uint nKeyLength, ulong h, value_t *pData, value_t *pDest, int flag);
#define hash_table_quick_update(ht, arKey, nKeyLength, h, pData, pDest) \
		_hash_table_quick_add_or_update(ht, arKey, nKeyLength, h, pData, pDest, HASH_TABLE_UPDATE)
#define hash_table_quick_add(ht, arKey, nKeyLength, h, pData, pDest) \
		_hash_table_quick_add_or_update(ht, arKey, nKeyLength, h, pData, pDest, HASH_TABLE_ADD)

int _hash_table_index_update_or_next_insert(hash_table_t *ht, ulong h, value_t *pData, value_t *pDest, int flag);
#define hash_table_index_update(ht, h, pData, pDest) \
		_hash_table_index_update_or_next_insert(ht, h, pData, pDest, HASH_TABLE_UPDATE)
#define hash_table_next_index_insert(ht, pData, pDest) \
		_hash_table_index_update_or_next_insert(ht, 0, pData, pDest, HASH_TABLE_NEXT_INSERT)

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

int hash_table_rehash(hash_table_t *ht);
void hash_table_reindex(hash_table_t *ht, zend_bool only_integer_keys);

ulong hash_table_func(const char *arKey, uint nKeyLength);

#endif							/* _HASH_H */
