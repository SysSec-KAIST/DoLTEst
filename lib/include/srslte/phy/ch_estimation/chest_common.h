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

#ifndef SRSLTE_CHEST_COMMON_H
#define SRSLTE_CHEST_COMMON_H

#include <stdint.h>
#include "srslte/config.h"

#define SRSLTE_CHEST_MAX_SMOOTH_FIL_LEN 64

typedef enum SRSLTE_API {
  SRSLTE_CHEST_FILTER_GAUSS = 0,
  SRSLTE_CHEST_FILTER_TRIANGLE,
  SRSLTE_CHEST_FILTER_NONE
} srslte_chest_filter_t;

SRSLTE_API void srslte_chest_average_pilots(
    cf_t* input, cf_t* output, float* filter, uint32_t nof_ref, uint32_t nof_symbols, uint32_t filter_len);

SRSLTE_API uint32_t srslte_chest_set_smooth_filter3_coeff(float* smooth_filter, float w);

SRSLTE_API float srslte_chest_estimate_noise_pilots(cf_t* noisy, cf_t* noiseless, cf_t* noise_vec, uint32_t nof_pilots);

SRSLTE_API uint32_t srslte_chest_set_triangle_filter(float* fil, int filter_len);

SRSLTE_API uint32_t srslte_chest_set_smooth_filter_gauss(float* filter, uint32_t order, float std_dev);

#endif // SRSLTE_CHEST_COMMON_H
