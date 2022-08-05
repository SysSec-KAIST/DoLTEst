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

#include "srslte/common/log_filter.h"
#include "srslte/common/trace.h"
#include "srslte/phy/rf/rf.h"
#include "srslte/srslte.h"

#ifndef SRSLTE_RADIO_H
#define SRSLTE_RADIO_H

namespace srslte {

/* Interface to the RF frontend. 
  */
class radio {
 public:
   radio() : tr_local_time(1024 * 10), tr_usrp_time(1024 * 10), tr_tx_time(1024 * 10), tr_is_eob(1024 * 10), zeros(NULL)
   {
     bzero(&rf_device, sizeof(srslte_rf_t));
     bzero(&end_of_burst_time, sizeof(srslte_timestamp_t));
     zeros = (cf_t*)srslte_vec_malloc(burst_preamble_max_samples * sizeof(cf_t));
     bzero(zeros, burst_preamble_max_samples * sizeof(cf_t));

     log_h = NULL;

     burst_preamble_sec          = 0;
     is_start_of_burst           = false;
     burst_preamble_samples      = 0;
     burst_preamble_time_rounded = 0;

     master_clock_rate  = 0;
     cur_tx_srate       = 0;
     tx_adv_sec         = 0;
     tx_adv_nsamples    = 0;
     tx_adv_auto        = false;
     tx_adv_negative    = false;
     tx_freq            = 0;
     rx_freq            = 0;
     freq_offset        = 0;
     trace_enabled      = false;
     tti                = 0;
     agc_enabled        = false;
     radio_is_streaming = false;
     is_initialized     = false;
     continuous_tx      = false;
  };

  ~radio()
  {
    if (zeros) {
      free(zeros);
      zeros = NULL;
    }
  }

  bool init(log_filter* _log_h, char* args = NULL, char* devname = NULL, uint32_t nof_channels = 1);
  void stop();
  void reset();
  bool start_agc(bool tx_gain_same_rx = false);

  void set_burst_preamble(double preamble_us);
  void set_tx_adv(int nsamples);
  void set_tx_adv_neg(bool tx_adv_is_neg);

  bool is_continuous_tx();
  void set_continuous_tx(bool enable);

  void get_time(srslte_timestamp_t *now);
  int  synch_wait();
  void synch_issue();
  bool tx_single(cf_t* buffer, uint32_t nof_samples, srslte_timestamp_t tx_time);
  bool tx(cf_t* buffer[SRSLTE_MAX_PORTS], uint32_t nof_samples, srslte_timestamp_t tx_time);
  void tx_end();
  bool rx_now(cf_t* buffer[SRSLTE_MAX_PORTS], uint32_t nof_samples, srslte_timestamp_t* rxd_time);
  bool rx_at(cf_t* buffer, uint32_t nof_samples, srslte_timestamp_t rx_time);

  void set_tx_gain(float gain);
  void set_rx_gain(float gain);
  void set_tx_rx_gain_offset(float offset);
  double set_rx_gain_th(float gain);
  void   set_master_clock_rate(double rate);

  void set_freq_offset(double freq);
  void set_tx_freq(uint32_t chan, double freq);
  void set_rx_freq(uint32_t chan, double freq);

  double get_freq_offset();
  double get_tx_freq();
  double get_rx_freq();

  void set_tx_srate(double srate);
  void set_rx_srate(double srate);

  float get_tx_gain();
  float get_rx_gain();
  srslte_rf_info_t *get_info();

  float get_max_tx_power();
  float set_tx_power(float power);
  float get_rssi();
  bool has_rssi();

  bool is_first_of_burst();

  bool is_init();

  void register_error_handler(srslte_rf_error_handler_t h);

 protected:
   srslte_rf_t rf_device;
   log_filter* log_h;

   const static uint32_t burst_preamble_max_samples = 13824;
   double                burst_preamble_sec; // Start of burst preamble time (off->on RF transition time)
   srslte_timestamp_t    end_of_burst_time;
   bool                  is_start_of_burst;
   uint32_t              burst_preamble_samples;
   double                burst_preamble_time_rounded; // preamble time rounded to sample time
   cf_t*                 zeros;
   double                master_clock_rate;
   double                cur_tx_srate;

   double tx_adv_sec;      // Transmission time advance to compensate for antenna->timestamp delay
   int    tx_adv_nsamples; // Transmision time advance in number of samples

   // Define default values for known radios
   bool                    tx_adv_auto;
   bool                    tx_adv_negative;
   constexpr static double uhd_default_burst_preamble_sec = 600 * 1e-6;
   constexpr static double uhd_default_tx_adv_samples     = 98;
   constexpr static double uhd_default_tx_adv_offset_sec  = 4 * 1e-6;

   constexpr static double blade_default_burst_preamble_sec = 0.0;
   constexpr static double blade_default_tx_adv_samples     = 27;
   constexpr static double blade_default_tx_adv_offset_sec  = 1e-6;

   double tx_freq, rx_freq, freq_offset;

   trace<uint32_t> tr_local_time;
   trace<uint32_t> tr_usrp_time;
   trace<uint32_t> tr_tx_time;
   trace<uint32_t> tr_is_eob;
   bool            trace_enabled;
   uint32_t        tti;
   bool            agc_enabled;

   bool continuous_tx;
   bool is_initialized;
   bool radio_is_streaming;

   uint32_t saved_nof_channels;
   char     saved_args[128];
   char     saved_devname[128];
};

} // namespace srslte

#endif // SRSLTE_RADIO_H
