/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
 *  Copyright (C) 2010, Jonathan Gonzalez V. <zeus@gnu.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef   	MK_BUCKET_QUEUE_H_
#define   	MK_BUCKET_QUEUE_H_

#include <stddef.h>
#include "mk_memory.h"
#include "mk_list.h"

struct mk_bucket_queue
{
    struct mk_list *buckets;
    size_t n_buckets;
    struct mk_list *top;
    size_t n_items;
};

static inline struct mk_bucket_queue *mk_bucket_queue_create(size_t priorities)
{
    size_t i;
    struct mk_bucket_queue *bucket_queue = (struct mk_bucket_queue *)
                                 mk_mem_alloc(sizeof(struct mk_bucket_queue));
    bucket_queue->buckets = (struct mk_list *) mk_mem_alloc(sizeof(struct mk_list) * priorities);
    for (i = 0; i < priorities; ++i) {
        mk_list_init(&bucket_queue->buckets[i]);
    }
    bucket_queue->n_buckets = priorities;
    bucket_queue->top = (bucket_queue->buckets + bucket_queue->n_buckets); /* one past the last element */
    bucket_queue->n_items = 0;
    return bucket_queue;
}

static inline int mk_bucket_queue_is_empty(struct mk_bucket_queue *bucket_queue)
{
    return bucket_queue->top == (bucket_queue->buckets + bucket_queue->n_buckets);
}

static inline int mk_bucket_queue_add(struct mk_bucket_queue *bucket_queue,
                                      struct mk_list *item, size_t priority)
{
    if (priority >= bucket_queue->n_buckets) {
        /* mk_err("Error: attempting to add item of priority %zu to bucket_queue out of "
               "priority range", priority); */
        return -1;
    }
    mk_list_add(item, &bucket_queue->buckets[priority]);
    if (&bucket_queue->buckets[priority] < bucket_queue->top) {
        bucket_queue->top = &bucket_queue->buckets[priority];
    }
    ++bucket_queue->n_items;
    return 0;
}

/* fifo based on priority */
static inline struct mk_list *mk_bucket_queue_find_min(struct mk_bucket_queue *bucket_queue)
{
    if (mk_bucket_queue_is_empty(bucket_queue)) {
        return NULL;
    }
    return bucket_queue->top->next;
}

static inline void mk_bucket_queue_delete_min(struct mk_bucket_queue *bucket_queue)
{
    if (mk_bucket_queue_is_empty(bucket_queue)) {
        return;
    }

    mk_list_del(bucket_queue->top->next);
    while (!mk_bucket_queue_is_empty(bucket_queue)
          && (mk_list_is_empty(bucket_queue->top) == 0)) {
        ++bucket_queue->top;
    }
    --bucket_queue->n_items;
}

static inline struct mk_list *mk_bucket_queue_pop_min(struct mk_bucket_queue *bucket_queue)
{
    struct mk_list *item;
    item = mk_bucket_queue_find_min(bucket_queue);
    mk_bucket_queue_delete_min(bucket_queue);
    return item;
}

static inline int mk_bucket_queue_destroy(
                                     struct mk_bucket_queue *bucket_queue)
{
    if (!mk_bucket_queue_is_empty(bucket_queue)) {
        /* mk_err("Error: attempting to destroy non empty bucket_queue. Remove all items "
                  "first."); */
        return -1;
    }
    mk_mem_free(bucket_queue->buckets);
    mk_mem_free(bucket_queue);
    return 0;
}

#endif /* !MK_BUCKET_QUEUE_H_ */
