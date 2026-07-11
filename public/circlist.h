#pragma once

#include "basic_defs.h"


struct circlist_item {
   struct circlist_item *prev;
   struct circlist_item *next;
};


#define CIRCLIST_CONTAINER(_p, _t, _m) \
    ((_t *)((char *)(_p) - offsetof(_t, _m)))

#define CIRCLIST_EMPTY(l)       ((l) == NULL)
#define CIRCLIST_FIRST(l)       (l)
#define CIRCLIST_LAST(l)        (CIRCLIST_EMPTY(l) ? NULL : (l)->prev)

#define CIRCLIST_SCAN(p, l) \
    for (p = CIRCLIST_FIRST(l); \
         (p) != NULL; \
         p = (((p)->next == CIRCLIST_FIRST(l)) ? NULL: (p)->next))

#define CIRCLIST_SCAN_BACK(p, l) \
    for (p = CIRCLIST_LAST(l); \
         (p) != NULL; \
         p = (((p)->prev == CIRCLIST_LAST(l)) ? NULL: (p)->prev))

#define CIRCLIST_SCAN_SAFE(p, pn, l) \
   if (!circlist_empty(l)) \
      for ((p) = CIRCLIST_FIRST(l), (pn) = circlist_next_item(p, l); \
           (p) != NULL; \
           (p) = (pn), (pn) = circlist_next_item(p, l))


/*
 *---------------------------------------------------------------------
 *
 * circlist_next_item --
 *
 *---------------------------------------------------------------------
 */

static inline struct circlist_item *
circlist_next_item(struct circlist_item *p,
                   const struct circlist_item *head)
{
   if (head == NULL || p == NULL) {
      return NULL;
   }
   p = p->next;
   return p == head ? NULL : p;
}


/*
 *---------------------------------------------------------------------
 *
 * circlist_prev_item --
 *
 *---------------------------------------------------------------------
 */

static inline struct circlist_item *
circlist_prev_item(struct circlist_item *p,
                   const struct circlist_item *head)
{
   if (head == NULL || p == NULL) {
      return NULL;
   }
   return p == head ? NULL : p->prev;
}


/*
 *---------------------------------------------------------------------
 *
 * circlist_empty --
 *
 *---------------------------------------------------------------------
 */

static inline bool
circlist_empty(const struct circlist_item *list)
{
   return list == NULL;
}


/*
 *---------------------------------------------------------------------
 *
 * circlist_init_item --
 *
 *---------------------------------------------------------------------
 */

static inline void
circlist_init_item(struct circlist_item *li)
{
   li->prev = NULL;
   li->next = NULL;
}


/*
 *---------------------------------------------------------------------
 *
 * circlist_queue_item --
 *
 *      Adds 'item' at the END of a circular list.
 *
 *---------------------------------------------------------------------
 */

static inline void
circlist_queue_item(struct circlist_item **list,
                    struct circlist_item *item)
{
   struct circlist_item *li = *list;

   if (circlist_empty(li)) {
      item->next = item->prev = item;
      *list = item;
   } else {
      item->prev = li->prev;
      item->next = li;
      item->prev->next = item;
      li->prev = item;
   }
}


/*
 *---------------------------------------------------------------------
 *
 * circlist_push_item --
 *
 *      Adds 'item' at the FRONT of a circular list.
 *
 *---------------------------------------------------------------------
 */

static inline void
circlist_push_item(struct circlist_item **list,
                   struct circlist_item *item)
{
   circlist_queue_item(list, item);
   *list = item;
}


/*
 *---------------------------------------------------------------------
 *
 * circlist_delete_item --
 *
 *---------------------------------------------------------------------
 */

static inline void
circlist_delete_item(struct circlist_item **list,
                     const struct circlist_item *item)
{
   if (item == item->next) {
      *list = NULL;
   } else {
      struct circlist_item *next;

      next       = item->next;
      next->prev = item->prev;
      item->prev->next = next;
      if (*list == item) {
         *list = next;
      }
   }
}

