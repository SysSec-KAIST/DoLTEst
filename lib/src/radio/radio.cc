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

#include "srslte/srslte.h"
extern "C" {
#include "srslte/phy/rf/rf.h"
}
#include "srslte/common/log_filter.h"
#include "srslte/radio/radio.h"
#include <string.h>
#include <unistd.h>

namespace srslte {

bool radio::init(log_filter* _log_h, char* args, char* devname, uint32_t nof_channels)
{
  if (srslte_rf_open_devname(&rf_device, devname, args, nof_channels)) {
    ERROR("Error opening RF device\n");
    return false;
  }

  log_h                       = _log_h;
  tx_adv_negative = false; 
  agc_enabled = false; 
  burst_preamble_samples = 0; 
  burst_preamble_time_rounded = 0; 
  cur_tx_srate = 0; 
  is_start_of_burst = true; 
  
  // Suppress radio stdout
  srslte_rf_suppress_stdout(&rf_device);

  continuous_tx = true;
  tx_adv_auto = true;
  // Set default preamble length each known device
  // We distinguish by device family, maybe we should calibrate per device
  if (strstr(srslte_rf_name(&rf_device), "uhd")) {
  } else if (strstr(srslte_rf_name(&rf_device), "bladerf")) {
    burst_preamble_sec = blade_default_burst_preamble_sec;
  } else {
    burst_preamble_sec = 0;
    log_h->console("\nWarning burst preamble is not calibrated for device %s. Set a value manually\n\n",
                   srslte_rf_name(&rf_device));
  }

  if (args) {
    strncpy(saved_args, args, 127);
  }
  if (devname) {
    strncpy(saved_devname, devname, 127);
  }
  saved_nof_channels = nof_channels;

  is_initialized = true;
  return true;
}

bool radio::is_init() {
  return is_initialized;
}

void radio::stop() 
{
  if (zeros) {
    free(zeros);
    zeros = NULL;
  }
  if (is_initialized) {
    srslte_rf_close(&rf_device);
  }
}

void radio::reset()
{
  srslte_rf_stop_rx_stream(&rf_device);
  radio_is_streaming = false;
  usleep(100000);
}

void radio::set_tx_rx_gain_offset(float offset) {
  srslte_rf_set_tx_rx_gain_offset(&rf_device, offset);  
}

void radio::set_burst_preamble(double preamble_us)
{
  burst_preamble_sec = (double) preamble_us/1e6; 
}

void radio::set_continuous_tx(bool enable) {
  continuous_tx = enable;
}

bool radio::is_continuous_tx() {
  return continuous_tx;
}

void radio::set_tx_adv(int nsamples)
{
  tx_adv_auto = false;
  tx_adv_nsamples = nsamples;
  if (!nsamples) {
    tx_adv_sec = 0; 
  }
  
}

void radio::set_tx_adv_neg(bool tx_adv_is_neg) {
  tx_adv_negative = tx_adv_is_neg; 
}

bool radio::start_agc(bool tx_gain_same_rx)
{
  if (srslte_rf_start_gain_thread(&rf_device, tx_gain_same_rx)) {
    ERROR("Error starting AGC Thread RF device\n");
    return false;
  }

  agc_enabled = true; 
 
  return true;    
}
bool radio::rx_at(cf_t* buffer, uint32_t nof_samples, srslte_timestamp_t rx_time)
{
  ERROR("Not implemented\n");
  return false; 
}

bool radio::rx_now(cf_t* buffer[SRSLTE_MAX_PORTS], uint32_t nof_samples, srslte_timestamp_t* rxd_time)
{
  bool ret = true;

  if (!radio_is_streaming) {
    srslte_rf_start_rx_stream(&rf_device, false);
    radio_is_streaming = true;
  }

  time_t* full_secs = rxd_time ? &rxd_time->full_secs : NULL;
  double* frac_secs = rxd_time ? &rxd_time->frac_secs : NULL;

  if (srslte_rf_recv_with_time_multi(&rf_device, (void**)buffer, nof_samples, true, full_secs, frac_secs) > 0) {
    ret = true;
  } else {
    ret = false;
  }

  return ret;
}

void radio::get_time(srslte_timestamp_t* now)
{
  srslte_rf_get_time(&rf_device, &now->full_secs, &now->frac_secs);
}

float radio::get_max_tx_power()
{
  return 40;
}

float radio::get_rssi()
{
  return srslte_rf_get_rssi(&rf_device);  
}

bool radio::has_rssi()
{
  return srslte_rf_has_rssi(&rf_device);
}

bool radio::is_first_of_burst() {
  return is_start_of_burst;
}

#define BLOCKING_TX true

bool radio::tx_single(cf_t* buffer, uint32_t nof_samples, srslte_timestamp_t tx_time)
{
  cf_t* _buffer[SRSLTE_MAX_PORTS];

  _buffer[0] = (buffer) ? buffer : zeros;
  for (int p = 1; p < SRSLTE_MAX_PORTS; p++) {
    _buffer[p] = zeros;
  }

  return this->tx(_buffer, nof_samples, tx_time);
}

bool radio::tx(cf_t* buffer[SRSLTE_MAX_PORTS], uint32_t nof_samples, srslte_timestamp_t tx_time)
{
  if (!tx_adv_negative) {
    srslte_timestamp_sub(&tx_time, 0, tx_adv_sec);
  } else {
    srslte_timestamp_add(&tx_time, 0, tx_adv_sec);
  }
  
  if (is_start_of_burst) {
    if (burst_preamble_samples != 0) {
      srslte_timestamp_t tx_time_pad;
      srslte_timestamp_copy(&tx_time_pad, &tx_time);
      srslte_timestamp_sub(&tx_time_pad, 0, burst_preamble_time_rounded);
      srslte_rf_send_timed_multi(&rf_device,
                                 (void**)buffer,
                                 burst_preamble_samples,
                                 tx_time_pad.full_secs,
                                 tx_time_pad.frac_secs,
                                 true,
                                 true,
                                 false);
      is_start_of_burst = false;
    }
  }
  
  // Save possible end of burst time 
  srslte_timestamp_copy(&end_of_burst_time, &tx_time);
  srslte_timestamp_add(&end_of_burst_time, 0, (double)nof_samples / cur_tx_srate);

  int ret           = srslte_rf_send_timed_multi(&rf_device,
                                       (void**)buffer,
                                       nof_samples,
                                       tx_time.full_secs,
                                       tx_time.frac_secs,
                                       BLOCKING_TX,
                                       is_start_of_burst,
                                       false);
  is_start_of_burst = false;
  if (ret > 0) {
    return true; 
  } else {
    return false; 
  }
}

void radio::tx_end()
{
  if (!is_start_of_burst) {
    srslte_rf_send_timed2(&rf_device, zeros, 0, end_of_burst_time.full_secs, end_of_burst_time.frac_secs, false, true);
    is_start_of_burst = true;
  }
}

void radio::set_freq_offset(double freq) {
  freq_offset = freq;
}

void radio::set_rx_freq(uint32_t ch, double freq)
{
  rx_freq = srslte_rf_set_rx_freq(&rf_device, ch, freq + freq_offset);
}

void radio::set_rx_gain(float gain)
{
  srslte_rf_set_rx_gain(&rf_device, gain);
}

double radio::set_rx_gain_th(float gain)
{
  return srslte_rf_set_rx_gain_th(&rf_device, gain);
}

void radio::set_master_clock_rate(double rate)
{
  if (rate != master_clock_rate) {
    srslte_rf_stop_rx_stream(&rf_device);
    srslte_rf_set_master_clock_rate(&rf_device, rate);
    srslte_rf_start_rx_stream(&rf_device, false);
    master_clock_rate = rate;
  }
}

void radio::set_rx_srate(double srate)
{
  set_master_clock_rate(srate);
  srslte_rf_set_rx_srate(&rf_device, srate);
}

void radio::set_tx_freq(uint32_t ch, double freq)
{
  tx_freq = srslte_rf_set_tx_freq(&rf_device, ch, freq + freq_offset);
}

void radio::set_tx_gain(float gain)
{
  srslte_rf_set_tx_gain(&rf_device, gain);
}

double radio::get_rx_freq()
{
  return rx_freq;
}

double radio::get_freq_offset()
{
  return freq_offset;
}

double radio::get_tx_freq()
{
  return tx_freq; 
}

float radio::get_tx_gain()
{
  return srslte_rf_get_tx_gain(&rf_device);
}

float radio::get_rx_gain()
{
  return srslte_rf_get_rx_gain(&rf_device);
}

void radio::set_tx_srate(double srate)
{
  set_master_clock_rate(srate);
  cur_tx_srate = srslte_rf_set_tx_srate(&rf_device, srate);
  burst_preamble_samples = (uint32_t) (cur_tx_srate * burst_preamble_sec);
  if (burst_preamble_samples > burst_preamble_max_samples) {
    fprintf(stderr, "Error setting TX srate %.1f MHz. Maximum burst preamble samples: %d, requested: %d\n", srate*1e-6, burst_preamble_max_samples, burst_preamble_samples  );
  }
  burst_preamble_time_rounded = (double) burst_preamble_samples/cur_tx_srate;  
  
  int nsamples=0;
  /* Set time advance for each known device if in auto mode */
  if (tx_adv_auto) {
   
    /* This values have been calibrated using the prach_test_usrp tool in srsLTE */

    if (!strcmp(srslte_rf_name(&rf_device), "uhd_b200")) {

      double srate_khz = round(cur_tx_srate/1e3);
      if (srate_khz == 1.92e3) {
        // 6 PRB
        nsamples = 57;
      } else if (srate_khz == 3.84e3) {
        // 15 PRB
        nsamples = 60;
      } else if (srate_khz == 5.76e3) {
        // 25 PRB
        nsamples = 92;
      } else if (srate_khz == 11.52e3) {
        // 50 PRB
        nsamples = 120;
      } else if (srate_khz == 15.36e3) {
        // 75 PRB
        nsamples = 160;
      } else if (srate_khz == 23.04e3) {
        // 100 PRB
        nsamples = 160;
      } else {
        /* Interpolate from known values */
        log_h->console(
            "\nWarning TX/RX time offset for sampling rate %.0f KHz not calibrated. Using interpolated value\n\n",
            cur_tx_srate);
        nsamples = cur_tx_srate*(uhd_default_tx_adv_samples * (1/cur_tx_srate) + uhd_default_tx_adv_offset_sec);        
      }
      
    }else if(!strcmp(srslte_rf_name(&rf_device), "uhd_usrp2")) {
            double srate_khz = round(cur_tx_srate/1e3);
            if (srate_khz == 1.92e3) {
              nsamples = 14; // estimated
            } else if (srate_khz == 3.84e3) {
              nsamples = 32;
      } else if (srate_khz == 5.76e3) {
        nsamples = 43;
      } else if (srate_khz == 11.52e3) {
        nsamples = 54;
      } else if (srate_khz == 15.36e3) {
        nsamples = 65;// to calc
      } else if (srate_khz == 23.04e3) {
        nsamples = 80; // to calc
      } else {
        /* Interpolate from known values */
        log_h->console(
            "\nWarning TX/RX time offset for sampling rate %.0f KHz not calibrated. Using interpolated value\n\n",
            cur_tx_srate);
        nsamples = cur_tx_srate*(uhd_default_tx_adv_samples * (1/cur_tx_srate) + uhd_default_tx_adv_offset_sec);        
      }
      
    } else if(!strcmp(srslte_rf_name(&rf_device), "lime")) {
      double srate_khz = round(cur_tx_srate/1e3);
      if (srate_khz == 1.92e3) {
        nsamples = 28;
      } else if (srate_khz == 3.84e3) {
        nsamples = 51;
      } else if (srate_khz == 5.76e3) {
        nsamples = 74;
      } else if (srate_khz == 11.52e3) {
        nsamples = 78;
      } else if (srate_khz == 15.36e3) {
        nsamples = 86;
      } else if (srate_khz == 23.04e3) {
        nsamples = 102;
      } else {
        /* Interpolate from known values */
        log_h->console(
            "\nWarning TX/RX time offset for sampling rate %.0f KHz not calibrated. Using interpolated value\n\n",
            cur_tx_srate);
        nsamples = cur_tx_srate*(uhd_default_tx_adv_samples * (1/cur_tx_srate) + uhd_default_tx_adv_offset_sec);        
      }
      
    } else if (!strcmp(srslte_rf_name(&rf_device), "uhd_x300")) {

      // In X300 TX/RX offset is independent of sampling rate
      nsamples = 45;
    } else if (!strcmp(srslte_rf_name(&rf_device), "bladerf")) {
      
      double srate_khz = round(cur_tx_srate/1e3);
      if (srate_khz == 1.92e3) {
        nsamples = 16;
      } else if (srate_khz == 3.84e3) {
        nsamples = 18; 
      } else if (srate_khz == 5.76e3) {
        nsamples = 16;
      } else if (srate_khz == 11.52e3) {
        nsamples = 21;
      } else if (srate_khz == 15.36e3) {
        nsamples = 14;
      } else if (srate_khz == 23.04e3) {
        nsamples = 21;
      } else {
        /* Interpolate from known values */
        log_h->console(
            "\nWarning TX/RX time offset for sampling rate %.0f KHz not calibrated. Using interpolated value\n\n",
            cur_tx_srate);
        tx_adv_sec = blade_default_tx_adv_samples * (1/cur_tx_srate) + blade_default_tx_adv_offset_sec;        
      }
    } else {
      log_h->console("\nWarning TX/RX time offset has not been calibrated for device %s. Set a value manually\n\n",
                     srslte_rf_name(&rf_device));
    }
  } else {
    nsamples = tx_adv_nsamples;
    log_h->console("Setting manual TX/RX offset to %d samples\n", nsamples);
  }
  
  // Calculate TX advance in seconds from samples and sampling rate 
  tx_adv_sec = nsamples/cur_tx_srate;
  if (tx_adv_sec<0) {
    tx_adv_sec *= -1;
    tx_adv_negative = true; 
  }
}

void radio::register_error_handler(srslte_rf_error_handler_t h)
{
  srslte_rf_register_error_handler(&rf_device, h);
}

srslte_rf_info_t* radio::get_info()
{
  return srslte_rf_get_info(&rf_device);
}
  
}

