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

#ifndef SRSLTE_RLF_H
#define SRSLTE_RLF_H

#include <srslte/config.h>
#include <srslte/phy/common/timestamp.h>

typedef struct {
  uint32_t t_on_ms;
  uint32_t t_off_ms;
} srslte_channel_rlf_t;

#ifdef __cplusplus
extern "C" {
#endif

SRSLTE_API void srslte_channel_rlf_init(srslte_channel_rlf_t* q, uint32_t t_on_ms, uint32_t t_off_ms);

SRSLTE_API void srslte_channel_rlf_execute(
    srslte_channel_rlf_t* q, const cf_t* in, cf_t* out, uint32_t nsamples, const srslte_timestamp_t* ts);

SRSLTE_API void srslte_channel_rlf_free(srslte_channel_rlf_t* q);

#ifdef __cplusplus
}
#endif

#endif // SRSLTE_RLF_H
