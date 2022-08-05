/*
 * Copyright 2013-2019 Software Radio Systems Limited
 *
 * This file is part of srsLTE.
 *
 * srsLTE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsLTE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include <string.h>
#include <stdlib.h>

#include "srslte/phy/utils/debug.h"
#include "srslte/phy/utils/ringbuffer.h"
#include "srslte/phy/utils/vector.h"

int srslte_ringbuffer_init(srslte_ringbuffer_t *q, int capacity)
{
  q->buffer = srslte_vec_malloc(capacity);
  if (!q->buffer) {
    return -1; 
  }
  q->active     = true;
  q->capacity   = capacity;
  pthread_mutex_init(&q->mutex, NULL); 
  pthread_cond_init(&q->cvar, NULL);
  srslte_ringbuffer_reset(q);

  return 0; 
}

void srslte_ringbuffer_free(srslte_ringbuffer_t *q)
{
  if (q) {
    srslte_ringbuffer_stop(q);
    if (q->buffer) {
      free(q->buffer);
      q->buffer = NULL; 
    }
    pthread_mutex_destroy(&q->mutex); 
    pthread_cond_destroy(&q->cvar);
  }
}

void srslte_ringbuffer_reset(srslte_ringbuffer_t *q)
{
  // Check first if it is initiated
  if (q->capacity != 0) {
    pthread_mutex_lock(&q->mutex);
    q->count = 0;
    q->wpm = 0;
    q->rpm = 0;
    pthread_mutex_unlock(&q->mutex);
  }
}

int srslte_ringbuffer_status(srslte_ringbuffer_t *q)
{
  return q->count;
}

int srslte_ringbuffer_space(srslte_ringbuffer_t *q)
{
  return q->capacity - q->count;
}

int srslte_ringbuffer_write(srslte_ringbuffer_t *q, void *p, int nof_bytes)
{
  uint8_t *ptr = (uint8_t*) p;
  int w_bytes = nof_bytes;
  pthread_mutex_lock(&q->mutex);
  if (!q->active) {
    pthread_mutex_unlock(&q->mutex);
    return 0;
  }
  if (q->count + w_bytes > q->capacity) {
    w_bytes = q->capacity - q->count;
    ERROR("Buffer overrun: lost %d bytes\n", nof_bytes - w_bytes);
  }
  if (w_bytes > q->capacity - q->wpm) {
    int x = q->capacity - q->wpm; 
    memcpy(&q->buffer[q->wpm], ptr, x);    
    memcpy(q->buffer, &ptr[x], w_bytes - x);    
  } else {
    memcpy(&q->buffer[q->wpm], ptr, w_bytes);    
  }
  q->wpm += w_bytes; 
  if (q->wpm >= q->capacity) {
    q->wpm -= q->capacity; 
  }
  q->count += w_bytes; 
  pthread_cond_broadcast(&q->cvar);
  pthread_mutex_unlock(&q->mutex);
  return w_bytes; 
}

int srslte_ringbuffer_read(srslte_ringbuffer_t *q, void *p, int nof_bytes)
{
  uint8_t *ptr = (uint8_t*) p;
  pthread_mutex_lock(&q->mutex);
  while(q->count < nof_bytes && q->active) {
    pthread_cond_wait(&q->cvar, &q->mutex);
  }
  if (!q->active) {
    pthread_mutex_unlock(&q->mutex);
    return 0;
  }
  if (nof_bytes + q->rpm > q->capacity) {
    int x = q->capacity - q->rpm; 
    memcpy(ptr, &q->buffer[q->rpm], x);
    memcpy(&ptr[x], q->buffer, nof_bytes - x);
  } else {         
    memcpy(ptr, &q->buffer[q->rpm], nof_bytes);
  }
  q->rpm += nof_bytes; 
  if (q->rpm >= q->capacity) {
    q->rpm -= q->capacity; 
  }
  q->count -= nof_bytes; 
  pthread_mutex_unlock(&q->mutex);
  return nof_bytes; 
}

int srslte_ringbuffer_read_timed(srslte_ringbuffer_t* q, void* p, int nof_bytes, uint32_t timeout_ms)
{
  int             ret = SRSLTE_SUCCESS;
  uint8_t*        ptr = (uint8_t*)p;
  struct timespec towait;
  struct timeval  now;

  // Get current time and update timeout
  gettimeofday(&now, NULL);
  towait.tv_sec  = now.tv_sec + timeout_ms / 1000U;
  towait.tv_nsec = (now.tv_usec + 1000UL * (timeout_ms % 1000U)) * 1000UL;

  // Lock mutex
  pthread_mutex_lock(&q->mutex);

  // Wait for having enough samples
  while (q->count < nof_bytes && q->active && ret == SRSLTE_SUCCESS) {
    ret = pthread_cond_timedwait(&q->cvar, &q->mutex, &towait);
  }

  if (ret == ETIMEDOUT) {
    ret = SRSLTE_ERROR_TIMEOUT;
  } else if (!q->active) {
    ret = SRSLTE_SUCCESS;
  } else if (ret == SRSLTE_SUCCESS) {
    if (nof_bytes + q->rpm > q->capacity) {
      int x = q->capacity - q->rpm;
      memcpy(ptr, &q->buffer[q->rpm], x);
      memcpy(&ptr[x], q->buffer, nof_bytes - x);
    } else {
      memcpy(ptr, &q->buffer[q->rpm], nof_bytes);
    }
    q->rpm += nof_bytes;
    if (q->rpm >= q->capacity) {
      q->rpm -= q->capacity;
    }
    q->count -= nof_bytes;
    ret = nof_bytes;
  } else {
    ret = SRSLTE_ERROR;
  }

  // Unlock mutex
  pthread_mutex_unlock(&q->mutex);

  return ret;
}

void srslte_ringbuffer_stop(srslte_ringbuffer_t *q) {
  pthread_mutex_lock(&q->mutex);
  q->active = false;
  pthread_cond_broadcast(&q->cvar);
  pthread_mutex_unlock(&q->mutex);
}

// Converts SC16 to cf_t
int srslte_ringbuffer_read_convert_conj(srslte_ringbuffer_t* q, cf_t* dst_ptr, float norm, int nof_samples)
{
  uint32_t nof_bytes = nof_samples * 4;

  pthread_mutex_lock(&q->mutex);
  while (q->count < nof_bytes && q->active) {
    pthread_cond_wait(&q->cvar, &q->mutex);
  }
  if (!q->active) {
    pthread_mutex_unlock(&q->mutex);
    return 0;
  }

  int16_t* src = (int16_t*)&q->buffer[q->rpm];
  float*   dst = (float*)dst_ptr;

  if (nof_bytes + q->rpm > q->capacity) {
    int x = (q->capacity - q->rpm);
    srslte_vec_convert_if(src, norm, dst, x / 2);
    srslte_vec_convert_if((int16_t*)q->buffer, norm, &dst[x], 2 * nof_samples - x / 2);
  } else {
    srslte_vec_convert_if(src, norm, dst, 2 * nof_samples);
  }
  srslte_vec_conj_cc(dst_ptr, dst_ptr, nof_samples);
  q->rpm += nof_bytes;
  if (q->rpm >= q->capacity) {
    q->rpm -= q->capacity;
  }
  q->count -= nof_bytes;
  pthread_mutex_unlock(&q->mutex);
  return nof_samples;
}

/* For this function, the ring buffer capacity must be multiple of block size */
int srslte_ringbuffer_read_block(srslte_ringbuffer_t* q, void** p, int nof_bytes)
{
  int ret = nof_bytes;
  pthread_mutex_lock(&q->mutex);

  /* Wait until enough data is in the buffer */
  while (q->count < nof_bytes && q->active) {
    pthread_cond_wait(&q->cvar, &q->mutex);
  }

  if (!q->active) {
    ret = 0;
  } else {
    *p = &q->buffer[q->rpm];

    q->count -= nof_bytes;
    q->rpm += nof_bytes;

    if (q->rpm >= q->capacity) {
      q->rpm -= q->capacity;
    }
  }
  pthread_mutex_unlock(&q->mutex);
  return ret;
}
