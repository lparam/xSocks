/*
 * Original Author:  Oliver Lorenz (ol), olli@olorenz.org, https://olorenz.org
 * License:  This is licensed under the same terms as uthash itself
 */

#ifndef CACHE_H
#define CACHE_H

#include "uthash.h"

#define KEY_MAX_LENGTH          32

/**
 * A cache entry
 */
struct cache_entry {
    char *key;         /**<The key */
    void *data;        /**<Payload */
    UT_hash_handle hh; /**<Hash Handle for uthash */
};

/**
 * A cache object
 */
struct cache {
    size_t max_entries;              /**<Amount of entries this cache object can hold */
    struct cache_entry *entries;     /**<Head pointer for uthash */
    void (*free_cb) (void *element); /**<Callback function to free cache entries */
};


extern int cache_create(struct cache **dst, const size_t capacity, void (*free_cb)(void *element));
extern int cache_delete(struct cache *cache, int keep_data);
extern int cache_lookup(struct cache *cache, char *key, void *result);
extern int cache_insert(struct cache *cache, char *key, void *data);
extern int cache_remove(struct cache *cache, char *key);
extern int cache_removeall(struct cache *cache, void *opaque, int (*select_cb)(void *element, void *opaque));

#endif // for #ifndef CACHE_H
