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

/******************************************************************************
 *  File:         resample_arb.h
 *
 *  Description:  Arbitrary rate resampler using a polyphase filter bank
 *                implementation.
 *
 *  Reference:    Multirate Signal Processing for Communication Systems
 *                fredric j. harris
 *****************************************************************************/

#ifndef SRSLTE_RESAMPLE_ARB_H
#define SRSLTE_RESAMPLE_ARB_H

#include <stdint.h>
#include <stdbool.h>
#include <complex.h>

#include "srslte/config.h"


#define SRSLTE_RESAMPLE_ARB_N_35 35 
#define SRSLTE_RESAMPLE_ARB_N    32  // Polyphase filter rows
#define SRSLTE_RESAMPLE_ARB_M    8   // Polyphase filter columns

typedef struct SRSLTE_API {
  float rate;                // Resample rate
  float step;                // Step increment through filter
  float acc;                 // Index into filter
  bool interpolate;
  cf_t reg[SRSLTE_RESAMPLE_ARB_M];  // Our window of samples
   
} srslte_resample_arb_t;

SRSLTE_API void srslte_resample_arb_init(srslte_resample_arb_t *q, 
                                         float rate, bool interpolate);

SRSLTE_API int srslte_resample_arb_compute(srslte_resample_arb_t *q, 
                                           cf_t *input, 
                                           cf_t *output, 
                                           int n_in);

#endif // SRSLTE_RESAMPLE_ARB_
