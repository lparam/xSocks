#define _GNU_SOURCE
/*
 * Original Author:  Oliver Lorenz (ol), olli@olorenz.org, https://olorenz.org
 * License:  This is licensed under the same terms as uthash itself
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "cache.h"

int
cache_create(struct cache **dst, const size_t capacity,
                 void (*free_cb)(void *element)) {
    struct cache *new = NULL;

    if (!dst) {
        return EINVAL;
    }

    if ((new = malloc(sizeof(*new))) == NULL) {
        return ENOMEM;
    }

    new->max_entries = capacity;
    new->entries = NULL;
    new->free_cb = free_cb;
    *dst = new;
    return 0;

}

int
cache_delete(struct cache *cache, int keep_data) {
    struct cache_entry *entry, *tmp;

    if (!cache) {
        return EINVAL;
    }

    if (keep_data) {
        HASH_CLEAR(hh, cache->entries);
    } else {
        HASH_ITER(hh, cache->entries, entry, tmp){
            HASH_DEL(cache->entries, entry);
            if (cache->free_cb) {
                cache->free_cb(entry->data);
            }
            free(entry);
        }
    }

    free(cache);
    cache = NULL;
    return 0;
}

int
cache_remove(struct cache *cache, char *key) {
    struct cache_entry *tmp;

    if (!cache || !key) {
        return EINVAL;
    }

    HASH_FIND_STR(cache->entries, key, tmp);

    if (tmp) {
        HASH_DEL(cache->entries, tmp);
        if (cache->free_cb) {
            cache->free_cb(tmp->data);
        }
        free(tmp);
    }

    return 0;
}

int
cache_removeall(struct cache *cache, void *opaque, int (*select_cb)(void *element, void *opaque)) {
    struct cache_entry *entry, *tmp;

    if (!cache) {
        return EINVAL;
    }

    HASH_ITER(hh, cache->entries, entry, tmp){
        if (select_cb(entry->data, opaque)) {
            HASH_DEL(cache->entries, entry);
            if (cache->free_cb) {
                cache->free_cb(entry->data);
            }
            free(entry);
        }
    }

    return 0;
}

/** Checks if a given key is in the cache

    @param cache
    The cache object

    @param key
    The key to look-up

    @param result
    Where to store the result if key is found.

    A warning: Even though result is just a pointer,
    you have to call this function with a **ptr,
    otherwise this will blow up in your face.

    @return EINVAL if cache is NULL, 0 otherwise
 */
int
cache_lookup(struct cache *cache, char *key, void *result)
{
    struct cache_entry *tmp = NULL;
    char **dirty_hack = result;

    if (!cache || !key || !result) {
        return EINVAL;
    }

    HASH_FIND_STR(cache->entries, key, tmp);
    if (tmp) {
        size_t key_len = strnlen(tmp->key, KEY_MAX_LENGTH);
        HASH_DELETE(hh, cache->entries, tmp);
        HASH_ADD_KEYPTR(hh, cache->entries, tmp->key, key_len, tmp);
        *dirty_hack = tmp->data;
    } else {
        *dirty_hack = result = NULL;
    }

    return 0;
}

int
cache_insert(struct cache *cache, char *key, void *data) {
    struct cache_entry *entry = NULL;
    struct cache_entry *tmp_entry = NULL;
    size_t key_len = 0;

    if (!cache || !data) {
        return EINVAL;
    }

    if ((entry = malloc(sizeof(*entry))) == NULL) {
        return ENOMEM;
    }

    entry->key = key;
    entry->data = data;
    key_len = strnlen(entry->key, KEY_MAX_LENGTH);
    HASH_ADD_KEYPTR(hh, cache->entries, entry->key, key_len, entry);

    if (HASH_COUNT(cache->entries) >= cache->max_entries) {
        HASH_ITER(hh, cache->entries, entry, tmp_entry){
            HASH_DELETE(hh, cache->entries, entry);
            if (cache->free_cb) {
                cache->free_cb(entry->data);
            } else {
                free(entry->data);
            }
            /* free(key->key) if data has been copied */
            free(entry);
            break;
        }
    }

    return 0;
}
