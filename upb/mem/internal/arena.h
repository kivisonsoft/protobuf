// Protocol Buffers - Google's data interchange format
// Copyright 2023 Google LLC.  All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef UPB_MEM_INTERNAL_ARENA_H_
#define UPB_MEM_INTERNAL_ARENA_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "upb/mem/alloc.h"

// Must be last.
#include "upb/port/def.inc"

typedef struct _upb_MemBlock _upb_MemBlock;

// LINT.IfChange(struct_definition)
typedef struct {
  char *ptr, *end;
} _upb_ArenaHead;

struct upb_Arena {
  _upb_ArenaHead head;

  // upb_alloc* together with a low bit which signals if there is an initial
  // block.
  uintptr_t block_alloc;

  // When multiple arenas are fused together, each arena points to a parent
  // arena (root points to itself). The root tracks how many live arenas
  // reference it.

  // The low bit is tagged:
  //   0: pointer to parent
  //   1: count, left shifted by one
  UPB_ATOMIC(uintptr_t) parent_or_count;

  // All nodes that are fused together are in a singly-linked list.
  UPB_ATOMIC(struct upb_Arena*) next;  // NULL at end of list.

  // The last element of the linked list.  This is present only as an
  // optimization, so that we do not have to iterate over all members for every
  // fuse.  Only significant for an arena root.  In other cases it is ignored.
  UPB_ATOMIC(struct upb_Arena*) tail;  // == self when no other list members.

  // Linked list of blocks to free/cleanup.  Atomic only for the benefit of
  // upb_Arena_SpaceAllocated().
  UPB_ATOMIC(_upb_MemBlock*) blocks;
};
// LINT.ThenChange(//depot/google3/third_party/upb/bits/typescript/arena.ts)

#ifdef __cplusplus
extern "C" {
#endif

bool UPB_PRIVATE(_upb_Arena_AllocBlock)(struct upb_Arena* a, size_t size);

uint32_t UPB_PRIVATE(_upb_Arena_DebugRefCount)(struct upb_Arena* arena);
size_t UPB_PRIVATE(_upb_Arena_DebugSpaceAllocated)(struct upb_Arena* arena);

UPB_INLINE size_t UPB_PRIVATE(_upb_ArenaHas)(struct upb_Arena* a) {
  _upb_ArenaHead* h = (_upb_ArenaHead*)a;
  return (size_t)(h->end - h->ptr);
}

UPB_INLINE void* UPB_PRIVATE(_upb_Arena_Malloc)(struct upb_Arena* a,
                                                size_t size) {
  size = UPB_ALIGN_MALLOC(size);
  const size_t span = size + UPB_ASAN_GUARD_SIZE;

  if (UPB_UNLIKELY(UPB_PRIVATE(_upb_ArenaHas)(a) < span)) {
    if (!UPB_PRIVATE(_upb_Arena_AllocBlock)(a, size)) return NULL;  // OOM
  }

  // We have enough space to do a fast malloc.
  _upb_ArenaHead* h = (_upb_ArenaHead*)a;
  void* ret = h->ptr;
  UPB_ASSERT(UPB_ALIGN_MALLOC((uintptr_t)ret) == (uintptr_t)ret);
  UPB_ASSERT(UPB_ALIGN_MALLOC(size) == size);
  UPB_UNPOISON_MEMORY_REGION(ret, size);

  h->ptr += span;

  return ret;
}

UPB_INLINE void* UPB_PRIVATE(_upb_Arena_Realloc)(struct upb_Arena* a, void* ptr,
                                                 size_t oldsize, size_t size) {
  _upb_ArenaHead* h = (_upb_ArenaHead*)a;
  oldsize = UPB_ALIGN_MALLOC(oldsize);
  size = UPB_ALIGN_MALLOC(size);
  bool is_most_recent_alloc = (uintptr_t)ptr + oldsize == (uintptr_t)h->ptr;

  if (is_most_recent_alloc) {
    ptrdiff_t diff = size - oldsize;
    if ((ptrdiff_t)UPB_PRIVATE(_upb_ArenaHas)(a) >= diff) {
      h->ptr += diff;
      return ptr;
    }
  } else if (size <= oldsize) {
    return ptr;
  }

  void* ret = UPB_PRIVATE(_upb_Arena_Malloc)(a, size);

  if (ret && oldsize > 0) {
    memcpy(ret, ptr, UPB_MIN(oldsize, size));
  }
  return ret;
}

UPB_INLINE void UPB_PRIVATE(_upb_Arena_ShrinkLast)(struct upb_Arena* a,
                                                   void* ptr, size_t oldsize,
                                                   size_t size) {
  _upb_ArenaHead* h = (_upb_ArenaHead*)a;
  oldsize = UPB_ALIGN_MALLOC(oldsize);
  size = UPB_ALIGN_MALLOC(size);
  // Must be the last alloc.
  UPB_ASSERT((char*)ptr + oldsize == h->ptr - UPB_ASAN_GUARD_SIZE);
  UPB_ASSERT(size <= oldsize);
  h->ptr = (char*)ptr + size;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#include "upb/port/undef.inc"

#endif /* UPB_MEM_INTERNAL_ARENA_H_ */
