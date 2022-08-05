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

#include <stdlib.h>
#include <strings.h>
#include <complex.h>

#include "srslte/phy/modem/demod_soft.h"
#include "srslte/phy/utils/bit.h"
#include "srslte/phy/utils/debug.h"
#include "srslte/phy/utils/vector.h"

#ifdef LV_HAVE_SSE
#include <smmintrin.h>
void demod_16qam_lte_s_sse(const cf_t *symbols, short *llr, int nsymbols);
#endif

#define SCALE_SHORT_CONV_QPSK  100
#define SCALE_SHORT_CONV_QAM16 400
#define SCALE_SHORT_CONV_QAM64 700
#define SCALE_SHORT_CONV_QAM256 1000

#define SCALE_BYTE_CONV_QPSK  20
#define SCALE_BYTE_CONV_QAM16 30
#define SCALE_BYTE_CONV_QAM64 40
#define SCALE_BYTE_CONV_QAM256 50

void demod_bpsk_lte_b(const cf_t *symbols, int8_t *llr, int nsymbols) {
  for (int i=0;i<nsymbols;i++) {
    llr[i] = (int8_t) -SCALE_BYTE_CONV_QPSK*(crealf(symbols[i]) + cimagf(symbols[i]))/sqrt(2);
  }
}

void demod_bpsk_lte_s(const cf_t *symbols, short *llr, int nsymbols) {
  for (int i=0;i<nsymbols;i++) {
    llr[i] = (short) -SCALE_SHORT_CONV_QPSK*(crealf(symbols[i]) + cimagf(symbols[i]))/sqrt(2);
  }
}

void demod_bpsk_lte(const cf_t *symbols, float *llr, int nsymbols) {
  for (int i=0;i<nsymbols;i++) {
    llr[i] = -(crealf(symbols[i]) + cimagf(symbols[i]))/sqrt(2);
  }
}

void demod_qpsk_lte_b(const cf_t *symbols, int8_t *llr, int nsymbols) {
  srslte_vec_convert_fb((const float*) symbols, -SCALE_BYTE_CONV_QPSK*sqrt(2), llr, nsymbols*2);
}

void demod_qpsk_lte_s(const cf_t *symbols, short *llr, int nsymbols) {
  srslte_vec_convert_fi((const float*) symbols, -SCALE_SHORT_CONV_QPSK*sqrt(2), llr, nsymbols*2);
}

void demod_qpsk_lte(const cf_t *symbols, float *llr, int nsymbols) {
  srslte_vec_sc_prod_fff((const float*) symbols, -sqrt(2), llr, nsymbols*2);
}

void demod_16qam_lte(const cf_t *symbols, float *llr, int nsymbols) {
  for (int i=0;i<nsymbols;i++) {
    float yre = crealf(symbols[i]);
    float yim = cimagf(symbols[i]);
    
    llr[4*i+0] = -yre;
    llr[4*i+1] = -yim;
    llr[4*i+2] = fabsf(yre)-2/sqrt(10);
    llr[4*i+3] = fabsf(yim)-2/sqrt(10);
  }
}

#ifdef LV_HAVE_SSE

void demod_16qam_lte_s_sse(const cf_t *symbols, short *llr, int nsymbols) {
    float *symbolsPtr = (float*) symbols;
  __m128i *resultPtr = (__m128i*) llr;
  __m128 symbol1, symbol2; 
  __m128i symbol_i1, symbol_i2, symbol_i, symbol_abs;
  __m128i offset = _mm_set1_epi16(2*SCALE_SHORT_CONV_QAM16/sqrt(10));
  __m128i result11, result12, result22, result21; 
  __m128 scale_v = _mm_set1_ps(-SCALE_SHORT_CONV_QAM16);
  __m128i shuffle_negated_1 = _mm_set_epi8(0xff,0xff,0xff,0xff,7,6,5,4,0xff,0xff,0xff,0xff,3,2,1,0);
  __m128i shuffle_abs_1 = _mm_set_epi8(7,6,5,4,0xff,0xff,0xff,0xff,3,2,1,0,0xff,0xff,0xff,0xff);

  __m128i shuffle_negated_2 = _mm_set_epi8(0xff,0xff,0xff,0xff,15,14,13,12,0xff,0xff,0xff,0xff,11,10,9,8);
  __m128i shuffle_abs_2 = _mm_set_epi8(15,14,13,12,0xff,0xff,0xff,0xff,11,10,9,8,0xff,0xff,0xff,0xff);

  for (int i=0;i<nsymbols/4;i++) {
    symbol1   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol2   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol_i1 = _mm_cvtps_epi32(_mm_mul_ps(symbol1, scale_v));
    symbol_i2 = _mm_cvtps_epi32(_mm_mul_ps(symbol2, scale_v));
    symbol_i  = _mm_packs_epi32(symbol_i1, symbol_i2);
    
    symbol_abs  = _mm_abs_epi16(symbol_i);
    symbol_abs  = _mm_sub_epi16(symbol_abs, offset);
    
    result11 = _mm_shuffle_epi8(symbol_i, shuffle_negated_1);  
    result12 = _mm_shuffle_epi8(symbol_abs, shuffle_abs_1);  

    result21 = _mm_shuffle_epi8(symbol_i, shuffle_negated_2);  
    result22 = _mm_shuffle_epi8(symbol_abs, shuffle_abs_2);  

    _mm_store_si128(resultPtr, _mm_or_si128(result11, result12)); resultPtr++;
    _mm_store_si128(resultPtr, _mm_or_si128(result21, result22)); resultPtr++;
  }
  // Demodulate last symbols 
  for (int i=4*(nsymbols/4);i<nsymbols;i++) {
    short yre = (short) (SCALE_SHORT_CONV_QAM16*crealf(symbols[i]));
    short yim = (short) (SCALE_SHORT_CONV_QAM16*cimagf(symbols[i]));
        
    llr[4*i+0] = -yre;
    llr[4*i+1] = -yim;
    llr[4*i+2] = abs(yre)-2*SCALE_SHORT_CONV_QAM16/sqrt(10);
    llr[4*i+3] = abs(yim)-2*SCALE_SHORT_CONV_QAM16/sqrt(10);    
  }
}

void demod_16qam_lte_b_sse(const cf_t *symbols, int8_t *llr, int nsymbols) {
  float *symbolsPtr = (float*) symbols;
  __m128i *resultPtr = (__m128i*) llr;
  __m128 symbol1, symbol2, symbol3, symbol4;
  __m128i symbol_i1, symbol_i2, symbol_i3, symbol_i4, symbol_i, symbol_abs, symbol_12, symbol_34;
  __m128i offset = _mm_set1_epi8(2*SCALE_BYTE_CONV_QAM16/sqrt(10));
  __m128i result1n, result1a, result2n, result2a;
  __m128 scale_v = _mm_set1_ps(-SCALE_BYTE_CONV_QAM16);

  __m128i shuffle_negated_1 = _mm_set_epi8(0xff,0xff,7,6,0xff,0xff,5,4,0xff,0xff,3,2,0xff,0xff,1,0);
  __m128i shuffle_abs_1     = _mm_set_epi8(7,6,0xff,0xff,5,4,0xff,0xff,3,2,0xff,0xff,1,0,0xff,0xff);

  __m128i shuffle_negated_2 = _mm_set_epi8(0xff,0xff,15,14,0xff,0xff,13,12,0xff,0xff,11,10,0xff,0xff,9,8);
  __m128i shuffle_abs_2     = _mm_set_epi8(15,14,0xff,0xff,13,12,0xff,0xff,11,10,0xff,0xff,9,8,0xff,0xff);

  for (int i=0;i<nsymbols/8;i++) {
    symbol1   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol2   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol3   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol4   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol_i1 = _mm_cvtps_epi32(_mm_mul_ps(symbol1, scale_v));
    symbol_i2 = _mm_cvtps_epi32(_mm_mul_ps(symbol2, scale_v));
    symbol_i3 = _mm_cvtps_epi32(_mm_mul_ps(symbol3, scale_v));
    symbol_i4 = _mm_cvtps_epi32(_mm_mul_ps(symbol4, scale_v));
    symbol_12  = _mm_packs_epi32(symbol_i1, symbol_i2);
    symbol_34  = _mm_packs_epi32(symbol_i3, symbol_i4);
    symbol_i   = _mm_packs_epi16(symbol_12, symbol_34);

    symbol_abs  = _mm_abs_epi8(symbol_i);
    symbol_abs  = _mm_sub_epi8(symbol_abs, offset);

    result1n = _mm_shuffle_epi8(symbol_i, shuffle_negated_1);
    result1a = _mm_shuffle_epi8(symbol_abs, shuffle_abs_1);

    result2n = _mm_shuffle_epi8(symbol_i, shuffle_negated_2);
    result2a = _mm_shuffle_epi8(symbol_abs, shuffle_abs_2);

    _mm_store_si128(resultPtr, _mm_or_si128(result1n, result1a)); resultPtr++;
    _mm_store_si128(resultPtr, _mm_or_si128(result2n, result2a)); resultPtr++;

  }
  // Demodulate last symbols
  for (int i=8*(nsymbols/8);i<nsymbols;i++) {
    short yre = (int8_t) (SCALE_BYTE_CONV_QAM16*crealf(symbols[i]));
    short yim = (int8_t) (SCALE_BYTE_CONV_QAM16*cimagf(symbols[i]));

    llr[4*i+0] = -yre;
    llr[4*i+1] = -yim;
    llr[4*i+2] = abs(yre)-2*SCALE_BYTE_CONV_QAM16/sqrt(10);
    llr[4*i+3] = abs(yim)-2*SCALE_BYTE_CONV_QAM16/sqrt(10);
  }
}

#endif

void demod_16qam_lte_s(const cf_t *symbols, short *llr, int nsymbols) {
#ifdef LV_HAVE_SSE
  demod_16qam_lte_s_sse(symbols, llr, nsymbols);
#else
  for (int i=0;i<nsymbols;i++) {
    short yre = (short) (SCALE_SHORT_CONV_QAM16*crealf(symbols[i]));
    short yim = (short) (SCALE_SHORT_CONV_QAM16*cimagf(symbols[i]));
        
    llr[4*i+0] = -yre;
    llr[4*i+1] = -yim;
    llr[4*i+2] = abs(yre)-2*SCALE_SHORT_CONV_QAM16/sqrt(10);
    llr[4*i+3] = abs(yim)-2*SCALE_SHORT_CONV_QAM16/sqrt(10);    
  }
#endif
}

void demod_16qam_lte_b(const cf_t *symbols, int8_t *llr, int nsymbols) {
#ifdef LV_HAVE_SSE
  demod_16qam_lte_b_sse(symbols, llr, nsymbols);
#else
  for (int i=0;i<nsymbols;i++) {
    int8_t yre = (int8_t) (SCALE_BYTE_CONV_QAM16*crealf(symbols[i]));
    int8_t yim = (int8_t) (SCALE_BYTE_CONV_QAM16*cimagf(symbols[i]));

    llr[4*i+0] = -yre;
    llr[4*i+1] = -yim;
    llr[4*i+2] = abs(yre)-2*SCALE_BYTE_CONV_QAM16/sqrt(10);
    llr[4*i+3] = abs(yim)-2*SCALE_BYTE_CONV_QAM16/sqrt(10);
  }
#endif
}

void demod_64qam_lte(const cf_t *symbols, float *llr, int nsymbols) 
{
  for (int i=0;i<nsymbols;i++) {
    float yre = crealf(symbols[i]);
    float yim = cimagf(symbols[i]);

    llr[6*i+0] = -yre;
    llr[6*i+1] = -yim;
    llr[6*i+2] = fabsf(yre)-4/sqrt(42);
    llr[6*i+3] = fabsf(yim)-4/sqrt(42);
    llr[6*i+4] = fabsf(llr[6*i+2])-2/sqrt(42);
    llr[6*i+5] = fabsf(llr[6*i+3])-2/sqrt(42);        
  }
  
}

#ifdef LV_HAVE_SSE

void demod_64qam_lte_s_sse(const cf_t *symbols, short *llr, int nsymbols) 
{
  float *symbolsPtr = (float*) symbols;
  __m128i *resultPtr = (__m128i*) llr;
  __m128 symbol1, symbol2; 
  __m128i symbol_i1, symbol_i2, symbol_i, symbol_abs, symbol_abs2;
  __m128i offset1 = _mm_set1_epi16(4*SCALE_SHORT_CONV_QAM64/sqrt(42));
  __m128i offset2 = _mm_set1_epi16(2*SCALE_SHORT_CONV_QAM64/sqrt(42));
  __m128 scale_v = _mm_set1_ps(-SCALE_SHORT_CONV_QAM64);
  __m128i result11, result12, result13, result22, result21,result23, result31, result32, result33; 

  __m128i shuffle_negated_1 = _mm_set_epi8(7,6,5,4,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,3,2,1,0);
  __m128i shuffle_negated_2 = _mm_set_epi8(0xff,0xff,0xff,0xff,11,10,9,8,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff);
  __m128i shuffle_negated_3 = _mm_set_epi8(0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,15,14,13,12,0xff,0xff,0xff,0xff);

  __m128i shuffle_abs_1 = _mm_set_epi8(0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,3,2,1,0,0xff,0xff,0xff,0xff);
  __m128i shuffle_abs_2 = _mm_set_epi8(11,10,9,8,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,7,6,5,4);
  __m128i shuffle_abs_3 = _mm_set_epi8(0xff,0xff,0xff,0xff,15,14,13,12,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff);

  __m128i shuffle_abs2_1 = _mm_set_epi8(0xff,0xff,0xff,0xff,3,2,1,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff);
  __m128i shuffle_abs2_2 = _mm_set_epi8(0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,7,6,5,4,0xff,0xff,0xff,0xff);
  __m128i shuffle_abs2_3 = _mm_set_epi8(15,14,13,12,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,11,10,9,8);

  for (int i=0;i<nsymbols/4;i++) {
    symbol1   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol2   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol_i1 = _mm_cvtps_epi32(_mm_mul_ps(symbol1, scale_v));
    symbol_i2 = _mm_cvtps_epi32(_mm_mul_ps(symbol2, scale_v));
    symbol_i  = _mm_packs_epi32(symbol_i1, symbol_i2);
    
    symbol_abs  = _mm_abs_epi16(symbol_i);
    symbol_abs  = _mm_sub_epi16(symbol_abs, offset1);
    symbol_abs2 = _mm_sub_epi16(_mm_abs_epi16(symbol_abs), offset2);
    
    result11 = _mm_shuffle_epi8(symbol_i, shuffle_negated_1);  
    result12 = _mm_shuffle_epi8(symbol_abs, shuffle_abs_1);  
    result13 = _mm_shuffle_epi8(symbol_abs2, shuffle_abs2_1);  

    result21 = _mm_shuffle_epi8(symbol_i, shuffle_negated_2);  
    result22 = _mm_shuffle_epi8(symbol_abs, shuffle_abs_2);  
    result23 = _mm_shuffle_epi8(symbol_abs2, shuffle_abs2_2);  

    result31 = _mm_shuffle_epi8(symbol_i, shuffle_negated_3);  
    result32 = _mm_shuffle_epi8(symbol_abs, shuffle_abs_3);  
    result33 = _mm_shuffle_epi8(symbol_abs2, shuffle_abs2_3);  

    _mm_store_si128(resultPtr, _mm_or_si128(_mm_or_si128(result11, result12),result13)); resultPtr++;
    _mm_store_si128(resultPtr, _mm_or_si128(_mm_or_si128(result21, result22),result23)); resultPtr++;
    _mm_store_si128(resultPtr, _mm_or_si128(_mm_or_si128(result31, result32),result33)); resultPtr++;
  }
  for (int i=4*(nsymbols/4);i<nsymbols;i++) {
    float yre = (short) (SCALE_SHORT_CONV_QAM64*crealf(symbols[i]));
    float yim = (short) (SCALE_SHORT_CONV_QAM64*cimagf(symbols[i]));

    llr[6*i+0] = -yre;
    llr[6*i+1] = -yim;
    llr[6*i+2] = abs(yre)-4*SCALE_SHORT_CONV_QAM64/sqrt(42);
    llr[6*i+3] = abs(yim)-4*SCALE_SHORT_CONV_QAM64/sqrt(42);
    llr[6*i+4] = abs(llr[6*i+2])-2*SCALE_SHORT_CONV_QAM64/sqrt(42);
    llr[6*i+5] = abs(llr[6*i+3])-2*SCALE_SHORT_CONV_QAM64/sqrt(42);        
  }
}

void demod_64qam_lte_b_sse(const cf_t *symbols, int8_t *llr, int nsymbols)
{
  float *symbolsPtr = (float*) symbols;
  __m128i *resultPtr = (__m128i*) llr;
  __m128 symbol1, symbol2, symbol3, symbol4;
  __m128i symbol_i1, symbol_i2, symbol_i3, symbol_i4, symbol_i, symbol_abs, symbol_abs2,symbol_12, symbol_34;
  __m128i offset1 = _mm_set1_epi8(4*SCALE_BYTE_CONV_QAM64/sqrt(42));
  __m128i offset2 = _mm_set1_epi8(2*SCALE_BYTE_CONV_QAM64/sqrt(42));
  __m128 scale_v = _mm_set1_ps(-SCALE_BYTE_CONV_QAM64);
  __m128i result11, result12, result13, result22, result21,result23, result31, result32, result33;

  __m128i shuffle_negated_1 = _mm_set_epi8(0xff,0xff,5,4,0xff,0xff,0xff,0xff,3,2,0xff,0xff,0xff,0xff,1,0);
  __m128i shuffle_negated_2 = _mm_set_epi8(11,10,0xff,0xff,0xff,0xff,9,8,0xff,0xff,0xff,0xff,7,6,0xff,0xff);
  __m128i shuffle_negated_3 = _mm_set_epi8(0xff,0xff,0xff,0xff,15,14,0xff,0xff,0xff,0xff,13,12,0xff,0xff,0xff,0xff);

  __m128i shuffle_abs_1 = _mm_set_epi8(5,4,0xff,0xff,0xff,0xff,3,2,0xff,0xff,0xff,0xff,1,0,0xff,0xff);
  __m128i shuffle_abs_2 = _mm_set_epi8(0xff,0xff,0xff,0xff,9,8,0xff,0xff,0xff,0xff,7,6,0xff,0xff,0xff,0xff);
  __m128i shuffle_abs_3 = _mm_set_epi8(0xff,0xff,15,14,0xff,0xff,0xff,0xff,13,12,0xff,0xff,0xff,0xff,11,10);

  __m128i shuffle_abs2_1 = _mm_set_epi8(0xff,0xff,0xff,0xff,3,2,0xff,0xff,0xff,0xff,1,0,0xff,0xff,0xff,0xff);
  __m128i shuffle_abs2_2 = _mm_set_epi8(0xff,0xff,9,8,0xff,0xff,0xff,0xff,7,6,0xff,0xff,0xff,0xff,5,4);
  __m128i shuffle_abs2_3 = _mm_set_epi8(15,14,0xff,0xff,0xff,0xff,13,12,0xff,0xff,0xff,0xff,11,10,0xff,0xff);

  for (int i=0;i<nsymbols/8;i++) {
    symbol1   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol2   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol3   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol4   = _mm_load_ps(symbolsPtr); symbolsPtr+=4;
    symbol_i1 = _mm_cvtps_epi32(_mm_mul_ps(symbol1, scale_v));
    symbol_i2 = _mm_cvtps_epi32(_mm_mul_ps(symbol2, scale_v));
    symbol_i3 = _mm_cvtps_epi32(_mm_mul_ps(symbol3, scale_v));
    symbol_i4 = _mm_cvtps_epi32(_mm_mul_ps(symbol4, scale_v));
    symbol_12  = _mm_packs_epi32(symbol_i1, symbol_i2);
    symbol_34  = _mm_packs_epi32(symbol_i3, symbol_i4);
    symbol_i   = _mm_packs_epi16(symbol_12, symbol_34);

    symbol_abs  = _mm_abs_epi8(symbol_i);
    symbol_abs  = _mm_sub_epi8(symbol_abs, offset1);
    symbol_abs2 = _mm_sub_epi8(_mm_abs_epi8(symbol_abs), offset2);

    result11 = _mm_shuffle_epi8(symbol_i, shuffle_negated_1);
    result12 = _mm_shuffle_epi8(symbol_abs, shuffle_abs_1);
    result13 = _mm_shuffle_epi8(symbol_abs2, shuffle_abs2_1);

    result21 = _mm_shuffle_epi8(symbol_i, shuffle_negated_2);
    result22 = _mm_shuffle_epi8(symbol_abs, shuffle_abs_2);
    result23 = _mm_shuffle_epi8(symbol_abs2, shuffle_abs2_2);

    result31 = _mm_shuffle_epi8(symbol_i, shuffle_negated_3);
    result32 = _mm_shuffle_epi8(symbol_abs, shuffle_abs_3);
    result33 = _mm_shuffle_epi8(symbol_abs2, shuffle_abs2_3);

    _mm_store_si128(resultPtr, _mm_or_si128(_mm_or_si128(result11, result12),result13)); resultPtr++;
    _mm_store_si128(resultPtr, _mm_or_si128(_mm_or_si128(result21, result22),result23)); resultPtr++;
    _mm_store_si128(resultPtr, _mm_or_si128(_mm_or_si128(result31, result32),result33)); resultPtr++;

  }
  for (int i=8*(nsymbols/8);i<nsymbols;i++) {
    float yre = (int8_t) (SCALE_BYTE_CONV_QAM64*crealf(symbols[i]));
    float yim = (int8_t) (SCALE_BYTE_CONV_QAM64*cimagf(symbols[i]));

    llr[6*i+0] = -yre;
    llr[6*i+1] = -yim;
    llr[6*i+2] = abs(yre)-4*SCALE_BYTE_CONV_QAM64/sqrt(42);
    llr[6*i+3] = abs(yim)-4*SCALE_BYTE_CONV_QAM64/sqrt(42);
    llr[6*i+4] = abs(llr[6*i+2])-2*SCALE_BYTE_CONV_QAM64/sqrt(42);
    llr[6*i+5] = abs(llr[6*i+3])-2*SCALE_BYTE_CONV_QAM64/sqrt(42);
  }
}
  
#endif

void demod_64qam_lte_s(const cf_t *symbols, short *llr, int nsymbols) 
{
#ifdef LV_HAVE_SSE
  demod_64qam_lte_s_sse(symbols, llr, nsymbols);
#else
  for (int i=0;i<nsymbols;i++) {
    float yre = (short) (SCALE_SHORT_CONV_QAM64*crealf(symbols[i]));
    float yim = (short) (SCALE_SHORT_CONV_QAM64*cimagf(symbols[i]));

    llr[6*i+0] = -yre;
    llr[6*i+1] = -yim;
    llr[6*i+2] = abs(yre)-4*SCALE_SHORT_CONV_QAM64/sqrt(42);
    llr[6*i+3] = abs(yim)-4*SCALE_SHORT_CONV_QAM64/sqrt(42);
    llr[6*i+4] = abs(llr[6*i+2])-2*SCALE_SHORT_CONV_QAM64/sqrt(42);
    llr[6*i+5] = abs(llr[6*i+3])-2*SCALE_SHORT_CONV_QAM64/sqrt(42);        
  }
#endif
}

void demod_64qam_lte_b(const cf_t *symbols, int8_t *llr, int nsymbols)
{
#ifdef LV_HAVE_SSE
  demod_64qam_lte_b_sse(symbols, llr, nsymbols);
#else
  for (int i=0;i<nsymbols;i++) {
    float yre = (int8_t) (SCALE_BYTE_CONV_QAM64*crealf(symbols[i]));
    float yim = (int8_t) (SCALE_BYTE_CONV_QAM64*cimagf(symbols[i]));

    llr[6*i+0] = -yre;
    llr[6*i+1] = -yim;
    llr[6*i+2] = abs(yre)-4*SCALE_BYTE_CONV_QAM64/sqrt(42);
    llr[6*i+3] = abs(yim)-4*SCALE_BYTE_CONV_QAM64/sqrt(42);
    llr[6*i+4] = abs(llr[6*i+2])-2*SCALE_BYTE_CONV_QAM64/sqrt(42);
    llr[6*i+5] = abs(llr[6*i+3])-2*SCALE_BYTE_CONV_QAM64/sqrt(42);
  }
#endif
}

void demod_256qam_lte(const cf_t* symbols, float* llr, int nsymbols)
{
  for (int i = 0; i < nsymbols; i++) {
    float real = -__real__ symbols[i];
    float imag = -__imag__ symbols[i];
    *(llr++)   = real;
    *(llr++)   = imag;
    real       = fabsf(real) - 8.0f / sqrtf(170.0f);
    imag       = fabsf(imag) - 8.0f / sqrtf(170.0f);
    *(llr++)   = real;
    *(llr++)   = imag;
    real       = fabsf(real) - 4.0f / sqrtf(170.0f);
    imag       = fabsf(imag) - 4.0f / sqrtf(170.0f);
    *(llr++)   = real;
    *(llr++)   = imag;
    real       = fabsf(real) - 2.0f / sqrtf(170.0f);
    imag       = fabsf(imag) - 2.0f / sqrtf(170.0f);
    *(llr++)   = real;
    *(llr++)   = imag;
  }
}

void demod_256qam_lte_b(const cf_t* symbols, int8_t* llr, int nsymbols)
{
  for (int i = 0; i < nsymbols; i++) {
    float real = -__real__ symbols[i];
    float imag = -__imag__ symbols[i];
    *(llr++)   = SCALE_BYTE_CONV_QAM256 * real;
    *(llr++)   = SCALE_BYTE_CONV_QAM256 * imag;
    real       = fabsf(real) - 8.0f / sqrtf(170.0f);
    imag       = fabsf(imag) - 8.0f / sqrtf(170.0f);
    *(llr++)   = SCALE_BYTE_CONV_QAM256 * real;
    *(llr++)   = SCALE_BYTE_CONV_QAM256 * imag;
    real       = fabsf(real) - 4.0f / sqrtf(170.0f);
    imag       = fabsf(imag) - 4.0f / sqrtf(170.0f);
    *(llr++)   = SCALE_BYTE_CONV_QAM256 * real;
    *(llr++)   = SCALE_BYTE_CONV_QAM256 * imag;
    real       = fabsf(real) - 2.0f / sqrtf(170.0f);
    imag       = fabsf(imag) - 2.0f / sqrtf(170.0f);
    *(llr++)   = SCALE_BYTE_CONV_QAM256 * real;
    *(llr++)   = SCALE_BYTE_CONV_QAM256 * imag;
  }
}

void demod_256qam_lte_s(const cf_t* symbols, short* llr, int nsymbols)
{
  for (int i = 0; i < nsymbols; i++) {
    float real = -__real__ symbols[i];
    float imag = -__imag__ symbols[i];
    *(llr++)   = SCALE_SHORT_CONV_QAM256 * real;
    *(llr++)   = SCALE_SHORT_CONV_QAM256 * imag;
    real       = fabsf(real) - 8.0f / sqrtf(170.0f);
    imag       = fabsf(imag) - 8.0f / sqrtf(170.0f);
    *(llr++)   = SCALE_SHORT_CONV_QAM256 * real;
    *(llr++)   = SCALE_SHORT_CONV_QAM256 * imag;
    real       = fabsf(real) - 4.0f / sqrtf(170.0f);
    imag       = fabsf(imag) - 4.0f / sqrtf(170.0f);
    *(llr++)   = SCALE_SHORT_CONV_QAM256 * real;
    *(llr++)   = SCALE_SHORT_CONV_QAM256 * imag;
    real       = fabsf(real) - 2.0f / sqrtf(170.0f);
    imag       = fabsf(imag) - 2.0f / sqrtf(170.0f);
    *(llr++)   = SCALE_SHORT_CONV_QAM256 * real;
    *(llr++)   = SCALE_SHORT_CONV_QAM256 * imag;
  }
}

int srslte_demod_soft_demodulate(srslte_mod_t modulation, const cf_t* symbols, float* llr, int nsymbols) {
  switch(modulation) {
    case SRSLTE_MOD_BPSK:
      demod_bpsk_lte(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_QPSK:
      demod_qpsk_lte(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_16QAM:
      demod_16qam_lte(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_64QAM:
      demod_64qam_lte(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_256QAM:
      demod_256qam_lte(symbols, llr, nsymbols);
      break;
    default:
      ERROR("Invalid modulation %d\n", modulation);
      return -1;
  } 
  return 0; 
}

int srslte_demod_soft_demodulate_s(srslte_mod_t modulation, const cf_t* symbols, short* llr, int nsymbols) {
  switch(modulation) {
    case SRSLTE_MOD_BPSK:
      demod_bpsk_lte_s(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_QPSK:
      demod_qpsk_lte_s(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_16QAM:
      demod_16qam_lte_s(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_64QAM:
      demod_64qam_lte_s(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_256QAM:
      demod_256qam_lte_s(symbols, llr, nsymbols);
      break;
    default:
      ERROR("Invalid modulation %d\n", modulation);
      return -1;
  } 
  return 0; 
}

int srslte_demod_soft_demodulate_b(srslte_mod_t modulation, const cf_t* symbols, int8_t* llr, int nsymbols) {
  switch(modulation) {
    case SRSLTE_MOD_BPSK:
      demod_bpsk_lte_b(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_QPSK:
      demod_qpsk_lte_b(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_16QAM:
      demod_16qam_lte_b(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_64QAM:
      demod_64qam_lte_b(symbols, llr, nsymbols);
      break;
    case SRSLTE_MOD_256QAM:
      demod_256qam_lte_b(symbols, llr, nsymbols);
      break;
    default:
      ERROR("Invalid modulation %d\n", modulation);
      return -1;
  }
  return 0;
}
