#ifndef FLB_EVENT_LOOP_H
#define FLB_EVENT_LOOP_H

#include <monkey/mk_core/mk_event.h>
#include <monkey/mk_core/mk_bucket_queue.h>

/* priority queue utility */
static inline void flb_event_load_bucket_queue(struct mk_event *event,
                                      struct mk_bucket_queue *bktq,
                                      struct mk_event_loop *evl)
{
    mk_event_foreach(event, evl) {
        if (event->_priority_head.prev == NULL) {
            mk_bucket_queue_add(bktq, &event->_priority_head, event->priority);
        }
    }
}

#define flb_event_priority_live_foreach(event, bktq, evl, max_iter)                     \
    int __flb_event_priority_live_foreach_iter;                                         \
    for (                                                                               \
        /* init */                                                                      \
        __flb_event_priority_live_foreach_iter = 0,                                     \
        flb_event_load_bucket_queue(event, bktq, evl),                                  \
        event = mk_bucket_queue_find_min(bktq) ?                                        \
                mk_list_entry(                                                          \
                    mk_bucket_queue_pop_min(bktq), struct mk_event, _priority_head) :   \
                NULL;                                                                   \
                                                                                        \
        /* condition */                                                                 \
        event != NULL &&                                                                \
        (__flb_event_priority_live_foreach_iter < max_iter || max_iter == -1);          \
                                                                                        \
        /* update */                                                                    \
        ++__flb_event_priority_live_foreach_iter,                                       \
        mk_event_wait_2(evl, 0),                                                        \
        flb_event_load_bucket_queue(event, bktq, evl),                                  \
        event = mk_bucket_queue_find_min(bktq) ?                                        \
                mk_list_entry(                                                          \
                    mk_bucket_queue_pop_min(bktq), struct mk_event, _priority_head) :   \
                NULL                                                                    \
    )

#endif /* !FLB_EVENT_LOOP_H */
