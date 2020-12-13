/*
 +----------------------------------------------------------------------+
 | Zend Engine                                                          |
 +----------------------------------------------------------------------+
 | Copyright (c) 1998-2016 Zend Technologies Ltd. (http://www.zend.com) |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.00 of the Zend license,     |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.zend.com/license/2_00.txt.                                |
 | If you did not receive a copy of the Zend license and are unable to  |
 | obtain it through the world-wide-web, please send a note to          |
 | license@zend.com so we can mail you a copy immediately.              |
 +----------------------------------------------------------------------+
 | Authors: Andi Gutmans <andi@zend.com>                                |
 |          Zeev Suraski <zeev@zend.com>                                |
 +----------------------------------------------------------------------+
 */

/* $Id$ */

#include <limits.h>

#include "hash.h"

#define CONNECT_TO_BUCKET_DLLIST(element, list_head)		\
	(element)->pNext = (list_head);							\
	(element)->pLast = NULL;								\
	if ((element)->pNext) {									\
		(element)->pNext->pLast = (element);				\
	}

#define CONNECT_TO_GLOBAL_DLLIST_EX(element, ht, last, next)\
	(element)->pListLast = (last);							\
	(element)->pListNext = (next);							\
	if ((last) != NULL) {									\
		(last)->pListNext = (element);						\
	} else {												\
		(ht)->pListHead = (element);						\
	}														\
	if ((next) != NULL) {									\
		(next)->pListLast = (element);						\
	} else {												\
		(ht)->pListTail = (element);						\
	}														\

#define CONNECT_TO_GLOBAL_DLLIST(element, ht)									\
	CONNECT_TO_GLOBAL_DLLIST_EX(element, ht, (ht)->pListTail, (bucket_t *) NULL);	\
	if ((ht)->pInternalPointer == NULL) {										\
		(ht)->pInternalPointer = (element);										\
	}

#define HASH_PROTECT_RECURSION(ht)														\
	if ((ht)->bApplyProtection) {														\
		if ((ht)->nApplyCount++ >= 3) {													\
			fprintf(stderr, "Nesting level too deep - recursive dependency?\n");		\
		}																				\
	}

#define HASH_UNPROTECT_RECURSION(ht)													\
	if ((ht)->bApplyProtection) {														\
		(ht)->nApplyCount--;															\
	}

#define HASH_TABLE_IF_FULL_DO_RESIZE(ht)				\
	if ((ht)->nNumOfElements > (ht)->nTableSize) {	\
		hash_table_do_resize(ht);					\
	}

#define CHECK_INIT(ht) do {															\
	if (UNEXPECTED((ht)->nTableMask == 0)) {										\
		(ht)->arBuckets = (bucket_t **) calloc((ht)->nTableSize, sizeof(bucket_t *));	\
		(ht)->nTableMask = (ht)->nTableSize - 1;									\
	}																				\
} while (0)

void hash_table_value_free(value_t *value) {
	switch(value->type) {
	case STR_T:
	case SERI_T:
		free(value->str);
		break;
	case HT_T:
		hash_table_destroy((hash_table_t*) value->ptr);
		free(value->ptr);
		break;
	case PTR_T:
		break;
	default:
		break;
	}
	value->type = NULL_T;
	value->expire = 0;
}

static zend_always_inline int hash_table_rehash(hash_table_t *ht) {
	register bucket_t *p;
	register uint nIndex;

	if (UNEXPECTED(ht->nNumOfElements == 0)) {
		return SUCCESS;
	}

	memset(ht->arBuckets, 0, ht->nTableSize * sizeof(bucket_t *));
	for (p = ht->pListHead; p != NULL; p = p->pListNext) {
		nIndex = p->h & ht->nTableMask;
		CONNECT_TO_BUCKET_DLLIST(p, ht->arBuckets[nIndex]);
		ht->arBuckets[nIndex] = p;
	}
	return SUCCESS;
}

void hash_table_reindex(hash_table_t *ht, zend_bool only_integer_keys) {
	register bucket_t *p;
	register uint nIndex;
	register ulong offset = 0;

	if (UNEXPECTED(ht->nNumOfElements == 0)) {
		ht->nNextFreeElement = 0;
		return;
	}

	memset(ht->arBuckets, 0, ht->nTableSize * sizeof(bucket_t *));
	for (p = ht->pListHead; p != NULL; p = p->pListNext) {
		if (!only_integer_keys || p->nKeyLength == 0) {
			p->h = offset++;
			p->nKeyLength = 0;
		}

		nIndex = p->h & ht->nTableMask;
		CONNECT_TO_BUCKET_DLLIST(p, ht->arBuckets[nIndex]);
		ht->arBuckets[nIndex] = p;
	}
	ht->nNextFreeElement = offset;
}

static void hash_table_do_resize(hash_table_t *ht) {
	if ((ht->nTableSize << 1) > 0) { /* Let's double the table size */
		ht->arBuckets = (bucket_t **) realloc(ht->arBuckets, (ht->nTableSize << 1) * sizeof(bucket_t *));
		ht->nTableSize = (ht->nTableSize << 1);
		ht->nTableMask = ht->nTableSize - 1;
		hash_table_rehash(ht);
	}
}

ulong hash_table_func(register const char *arKey, register uint nKeyLength) {
	register ulong hash = 5381;

	/* variant with the hash unrolled eight times */
	for (; nKeyLength >= 8; nKeyLength -= 8) {
		hash = ((hash << 5) + hash) + *arKey++;
		hash = ((hash << 5) + hash) + *arKey++;
		hash = ((hash << 5) + hash) + *arKey++;
		hash = ((hash << 5) + hash) + *arKey++;
		hash = ((hash << 5) + hash) + *arKey++;
		hash = ((hash << 5) + hash) + *arKey++;
		hash = ((hash << 5) + hash) + *arKey++;
		hash = ((hash << 5) + hash) + *arKey++;
	}
	switch (nKeyLength) {
		case 7:
			hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
			/* no break */
		case 6:
			hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
			/* no break */
		case 5:
			hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
			/* no break */
		case 4:
			hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
			/* no break */
		case 3:
			hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
			/* no break */
		case 2:
			hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
			/* no break */
		case 1:
			hash = ((hash << 5) + hash) + *arKey++;
			break;
		case 0:
			break;
	}
	return hash;
}

static const bucket_t *uninitialized_bucket = NULL;

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
	if (ht->pInternalPointer == p) {
		ht->pInternalPointer = p->pListNext;
	}
	ht->nNumOfElements--;
	if (ht->pDestructor) {
		ht->pDestructor(&p->value);
	}
	free(p);
}

int _hash_table_init(hash_table_t *ht, uint nSize, hash_dtor_func_t pDestructor, zend_bool bApplyProtection) {
	uint i = 3;

	memset(ht, 0, sizeof(hash_table_t));
	if (nSize >= 0x80000000) {
		/* prevent overflow */
		ht->nTableSize = 0x80000000;
	} else {
		while ((1U << i) < nSize) {
			i++;
		}
		ht->nTableSize = 1 << i;
	}

	ht->pDestructor = pDestructor;
	ht->arBuckets = (bucket_t**) &uninitialized_bucket;
	ht->bApplyProtection = bApplyProtection;
	return SUCCESS;
}

void hash_table_set_apply_protection(hash_table_t *ht, zend_bool bApplyProtection) {
	ht->bApplyProtection = bApplyProtection;
}

int _hash_table_add_or_update(hash_table_t *ht, const char *arKey, uint nKeyLength, value_t *pData, value_t *pDest, int flag) {
	ulong h;
	uint nIndex;
	bucket_t *p;

	ZEND_ASSERT(nKeyLength != 0);

	CHECK_INIT(ht);

	h = hash_table_func(arKey, nKeyLength);
	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if (p->arKey == arKey || ((p->h == h) && (p->nKeyLength == nKeyLength) && !memcmp(p->arKey, arKey, nKeyLength))) {
			if (flag & HASH_TABLE_ADD) return FAILURE;

			if (ht->pDestructor) ht->pDestructor(&p->value);
			if (pDest) {
				*pDest = p->value;
			}
			p->value = *pData;
			return SUCCESS;
		}
		p = p->pNext;
	}

	p = (bucket_t *) malloc(sizeof(bucket_t) + nKeyLength);
	memcpy(p->arKey, arKey, nKeyLength);
	p->arKey[nKeyLength] = '\0';

	p->nKeyLength = nKeyLength;
	p->value = *pData;
	p->h = h;
	CONNECT_TO_BUCKET_DLLIST(p, ht->arBuckets[nIndex]);
	if (pDest) {
		pDest->type = NULL_T;
	}

	CONNECT_TO_GLOBAL_DLLIST(p, ht);
	ht->arBuckets[nIndex] = p;

	ht->nNumOfElements++;
	HASH_TABLE_IF_FULL_DO_RESIZE(ht); /* If the Hash table is full, resize it */
	return SUCCESS;
}

int _hash_table_quick_add_or_update(hash_table_t *ht, const char *arKey, uint nKeyLength, ulong h, value_t *pData, value_t *pDest, int flag) {
	uint nIndex;
	bucket_t *p;

	ZEND_ASSERT(nKeyLength != 0);

	CHECK_INIT(ht);
	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if (p->arKey == arKey || ((p->h == h) && (p->nKeyLength == nKeyLength) && !memcmp(p->arKey, arKey, nKeyLength))) {
			if (flag & HASH_TABLE_ADD) {
				return FAILURE;
			}
			if (ht->pDestructor) ht->pDestructor(&p->value);
			if (pDest) *pDest = p->value;
			p->value = *pData;
			return SUCCESS;
		}
		p = p->pNext;
	}

	p = (bucket_t *) malloc(sizeof(bucket_t) + nKeyLength);
	memcpy(p->arKey, arKey, nKeyLength);
	p->arKey[nKeyLength] = '\0';

	p->nKeyLength = nKeyLength;
	p->value = *pData;
	p->h = h;
	if (pDest) pDest->type = NULL_T;

	CONNECT_TO_BUCKET_DLLIST(p, ht->arBuckets[nIndex]);

	ht->arBuckets[nIndex] = p;
	CONNECT_TO_GLOBAL_DLLIST(p, ht);

	ht->nNumOfElements++;
	HASH_TABLE_IF_FULL_DO_RESIZE(ht); /* If the Hash table is full, resize it */
	return SUCCESS;
}

int _hash_table_index_update_or_next_insert(hash_table_t *ht, ulong h, value_t *pData, value_t *pDest, int flag) {
	uint nIndex;
	bucket_t *p;

	CHECK_INIT(ht);

	if (flag & HASH_TABLE_NEXT_INSERT) {
		h = ht->nNextFreeElement;
	}
	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if ((p->nKeyLength == 0) && (p->h == h)) {
			if ((flag & HASH_TABLE_NEXT_INSERT) || (flag & HASH_TABLE_ADD)) {
				return FAILURE;
			}
			if (ht->pDestructor) ht->pDestructor(&p->value);
			if (pDest) *pDest = p->value;
			p->value = *pData;
			return SUCCESS;
		}
		p = p->pNext;
	}
	p = (bucket_t *) malloc(sizeof(bucket_t));
	p->arKey[0] = '\0';
	p->nKeyLength = 0; /* Numeric indices are marked by making the nKeyLength == 0 */
	p->h = h;
	p->value = *pData;
	if (pDest) pDest->type = NULL_T;

	CONNECT_TO_BUCKET_DLLIST(p, ht->arBuckets[nIndex]);

	ht->arBuckets[nIndex] = p;
	CONNECT_TO_GLOBAL_DLLIST(p, ht);

	if ((long) h >= (long) ht->nNextFreeElement) {
		ht->nNextFreeElement = h < LONG_MAX ? h + 1 : LONG_MAX;
	}
	ht->nNumOfElements++;
	HASH_TABLE_IF_FULL_DO_RESIZE(ht);
	return SUCCESS;
}

int hash_table_del_key_or_index(hash_table_t *ht, const char *arKey, uint nKeyLength, ulong h, int flag) {
	uint nIndex;
	bucket_t *p;

	if (flag == HASH_TABLE_DEL_KEY) {
		h = hash_table_func(arKey, nKeyLength);
	}
	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if ((p->h == h) && (p->nKeyLength == nKeyLength) && ((p->nKeyLength == 0) /* Numeric index (short circuits the memcmp() check) */
		|| !memcmp(p->arKey, arKey, nKeyLength))) { /* String index */
			hash_table_bucket_delete(ht, p);
			return SUCCESS;
		}
		p = p->pNext;
	}
	return FAILURE;
}

void hash_table_destroy(hash_table_t *ht) {
	bucket_t *p, *q;

	p = ht->pListHead;
	while (p != NULL) {
		q = p;
		p = p->pListNext;
		if (ht->pDestructor) {
			ht->pDestructor(&q->value);
		}
		free(q);
	}
	if (ht->nTableMask) {
		free(ht->arBuckets);
	}
}

void hash_table_clean(hash_table_t *ht) {
	bucket_t *p, *q;

	p = ht->pListHead;

	if (ht->nTableMask) {
		memset(ht->arBuckets, 0, ht->nTableSize * sizeof(bucket_t *));
	}
	ht->pListHead = NULL;
	ht->pListTail = NULL;
	ht->nNumOfElements = 0;
	ht->nNextFreeElement = 0;
	ht->pInternalPointer = NULL;

	while (p != NULL) {
		q = p;
		p = p->pListNext;
		if (ht->pDestructor) ht->pDestructor(&q->value);
		free(q);
	}
}

/* This is used to recurse elements and selectively delete certain entries 
 * from a hash_table_t. apply_func() receives the data and decides if the entry
 * should be deleted or recursion should be stopped. The following three 
 * return codes are possible:
 * HASH_TABLE_APPLY_KEEP   - continue
 * HASH_TABLE_APPLY_STOP   - stop iteration
 * HASH_TABLE_APPLY_REMOVE - delete the element, combineable with the former
 */

void hash_table_apply(hash_table_t *ht, hash_apply_func_t apply_func) {
	bucket_t *p;

	HASH_PROTECT_RECURSION(ht);
	p = ht->pListHead;
	while (p != NULL) {
		int result = apply_func(p);

		bucket_t *p_next = p->pListNext;
		if (result & HASH_TABLE_APPLY_REMOVE) {
			hash_table_bucket_delete(ht, p);
		}
		p = p_next;

		if (result & HASH_TABLE_APPLY_STOP) {
			break;
		}
	}
	HASH_UNPROTECT_RECURSION(ht);
}

void hash_table_apply_with_argument(hash_table_t *ht, hash_apply_func_arg_t apply_func, void *argument) {
	bucket_t *p;

	HASH_PROTECT_RECURSION(ht);
	p = ht->pListHead;
	while (p != NULL) {
		int result = apply_func(p, argument);

		bucket_t *p_next = p->pListNext;
		if (result & HASH_TABLE_APPLY_REMOVE) {
			hash_table_bucket_delete(ht, p);
		}
		p = p_next;

		if (result & HASH_TABLE_APPLY_STOP) {
			break;
		}
	}
	HASH_UNPROTECT_RECURSION(ht);
}

void hash_table_apply_with_arguments(hash_table_t *ht, hash_apply_func_args_t apply_func, int num_args, ...) {
	bucket_t *p;
	va_list args;

	HASH_PROTECT_RECURSION(ht);

	p = ht->pListHead;
	while (p != NULL) {
		int result;
		bucket_t *p_next;

		va_start(args, num_args);
		result = apply_func(p, num_args, args);

		p_next = p->pListNext;
		if (result & HASH_TABLE_APPLY_REMOVE) {
			hash_table_bucket_delete(ht, p);
		}
		p = p_next;

		if (result & HASH_TABLE_APPLY_STOP) {
			va_end(args);
			break;
		}
		va_end(args);
	}

	HASH_UNPROTECT_RECURSION(ht);
}

/* Returns SUCCESS if found and FAILURE if not. The pointer to the
 * data is returned in pData. The reason is that there's no reason
 * someone using the hash table might not want to have NULL data
 */
int hash_table_find(const hash_table_t *ht, const char *arKey, uint nKeyLength, value_t *pData) {
	ulong h;
	uint nIndex;
	bucket_t *p;

	h = hash_table_func(arKey, nKeyLength);
	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if (p->arKey == arKey || ((p->h == h) && (p->nKeyLength == nKeyLength) && !memcmp(p->arKey, arKey, nKeyLength))) {
			*pData = p->value;
			return SUCCESS;
		}
		p = p->pNext;
	}
	return FAILURE;
}

int hash_table_quick_find(const hash_table_t *ht, const char *arKey, uint nKeyLength, ulong h, value_t *pData) {
	uint nIndex;
	bucket_t *p;

	ZEND_ASSERT(nKeyLength != 0);

	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if (p->arKey == arKey || ((p->h == h) && (p->nKeyLength == nKeyLength) && !memcmp(p->arKey, arKey, nKeyLength))) {
			*pData = p->value;
			return SUCCESS;
		}
		p = p->pNext;
	}
	return FAILURE;
}

int hash_table_exists(const hash_table_t *ht, const char *arKey, uint nKeyLength) {
	ulong h;
	uint nIndex;
	bucket_t *p;

	h = hash_table_func(arKey, nKeyLength);
	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if (p->arKey == arKey || ((p->h == h) && (p->nKeyLength == nKeyLength) && !memcmp(p->arKey, arKey, nKeyLength))) {
			return 1;
		}
		p = p->pNext;
	}
	return 0;
}

int hash_table_quick_exists(const hash_table_t *ht, const char *arKey, uint nKeyLength, ulong h) {
	uint nIndex;
	bucket_t *p;

	ZEND_ASSERT(nKeyLength != 0);

	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if (p->arKey == arKey || ((p->h == h) && (p->nKeyLength == nKeyLength) && !memcmp(p->arKey, arKey, nKeyLength))) {
			return 1;
		}
		p = p->pNext;
	}
	return 0;

}

int hash_table_index_find(const hash_table_t *ht, ulong h, value_t *pData) {
	uint nIndex;
	bucket_t *p;

	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if ((p->h == h) && (p->nKeyLength == 0)) {
			*pData = p->value;
			return SUCCESS;
		}
		p = p->pNext;
	}
	return FAILURE;
}

int hash_table_index_exists(const hash_table_t *ht, ulong h) {
	uint nIndex;
	bucket_t *p;

	nIndex = h & ht->nTableMask;

	p = ht->arBuckets[nIndex];
	while (p != NULL) {
		if ((p->h == h) && (p->nKeyLength == 0)) {
			return 1;
		}
		p = p->pNext;
	}
	return 0;
}

int hash_table_num_elements(const hash_table_t *ht) {
	return ht->nNumOfElements;
}

ulong hash_table_next_free_element(const hash_table_t *ht) {
	return ht->nNextFreeElement;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * End:
 */
