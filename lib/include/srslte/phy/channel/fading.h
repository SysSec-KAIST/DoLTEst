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

#ifndef SRSLTE_FADING_H
#define SRSLTE_FADING_H

#include "srslte/phy/dft/dft.h"
#include <inttypes.h>

#define SRSLTE_CHANNEL_FADING_MAXTAPS 9

typedef enum {
  srslte_channel_fading_model_none = 0,
  srslte_channel_fading_model_epa,
  srslte_channel_fading_model_eva,
  srslte_channel_fading_model_etu,
} srslte_channel_fading_model_t;

typedef struct {
  // Configuration parameters
  float                         srate;   // Sampling rate: 1.92e6, 3.84e6, ..., 23.04e6, 30.72e6
  srslte_channel_fading_model_t model;   // None, EPA, EVA, ETU
  float                         doppler; // Maximum doppler: 5, 70, 300

  // Internal tap parametrization
  uint32_t N;                                      // FFT size
  uint32_t path_delay;                             // Path delay
  double   coeff_w[SRSLTE_CHANNEL_FADING_MAXTAPS]; // Angular Speed, random
  double   coeff_a[SRSLTE_CHANNEL_FADING_MAXTAPS]; // Modulation Coefficient
  double   coeff_p[SRSLTE_CHANNEL_FADING_MAXTAPS]; // Initial phase, random

  // Utils
  srslte_dft_plan_t fft;    // DFT to frequency domain
  srslte_dft_plan_t ifft;   // DFT to time domain
  cf_t*             temp;   // Temporal buffer, length fft_size
  cf_t*             h_freq; // Channel frequency response, length fft_size
  cf_t*             y_freq; // Intermediate frequency domain buffer

  // State variables
  cf_t* state; // Length fft_size/2
} srslte_channel_fading_t;

#ifdef __cplusplus
extern "C" {
#endif

SRSLTE_API int srslte_channel_fading_init(srslte_channel_fading_t* q, double srate, const char* model, uint32_t seed);

SRSLTE_API void srslte_channel_fading_free(srslte_channel_fading_t* q);

SRSLTE_API double srslte_channel_fading_execute(
    srslte_channel_fading_t* q, const cf_t* in, cf_t* out, uint32_t nof_samples, double init_time);

#ifdef __cplusplus
}
#endif

#endif // SRSLTE_FADING_H
