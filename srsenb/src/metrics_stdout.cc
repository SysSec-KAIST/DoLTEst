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

#include "srsenb/hdr/metrics_stdout.h"

#include <unistd.h>
#include <sstream>
#include <stdlib.h>
#include <math.h>
#include <float.h>
#include <iomanip>
#include <iostream>

#include <stdio.h>
#include <string.h>

using namespace std;

namespace srsenb{

char const * const prefixes[2][9] =
{
  {   "",   "m",   "u",   "n",    "p",    "f",    "a",    "z",    "y", },
  {   "",   "k",   "M",   "G",    "T",    "P",    "E",    "Z",    "Y", },
};


metrics_stdout::metrics_stdout()
    :do_print(false)
    ,n_reports(10)
    ,enb(NULL)
{
}

void metrics_stdout::set_handle(enb_metrics_interface *enb_)
{
  enb = enb_;
}

void metrics_stdout::toggle_print(bool b)
{
  do_print = b;
}

void metrics_stdout::set_metrics(enb_metrics_t &metrics, const uint32_t period_usec)
{
  if (!do_print || enb == NULL || metrics.stack.rrc.n_ues == 0) {
    return;
  }

  std::ios::fmtflags f(cout.flags()); // For avoiding Coverity defect: Not restoring ostream format

  if (++n_reports > 10) {
    n_reports = 0;
    cout << endl;
    cout << "------DL------------------------------UL----------------------------------" << endl;
    cout << "rnti  cqi    ri   mcs  brate   bler   snr   phr   mcs  brate   bler    bsr" << endl;
  }

  for (int i = 0; i < metrics.stack.rrc.n_ues; i++) {
    if (metrics.stack.mac[i].tx_errors > metrics.stack.mac[i].tx_pkts) {
      printf("tx caution errors %d > %d\n", metrics.stack.mac[i].tx_errors, metrics.stack.mac[i].tx_pkts);
    }
    if (metrics.stack.mac[i].rx_errors > metrics.stack.mac[i].rx_pkts) {
      printf("rx caution errors %d > %d\n", metrics.stack.mac[i].rx_errors, metrics.stack.mac[i].rx_pkts);
    }

    cout << std::hex << metrics.stack.mac[i].rnti << " ";
    cout << float_to_string(SRSLTE_MAX(0.1, metrics.stack.mac[i].dl_cqi), 2);
    cout << float_to_string(metrics.stack.mac[i].dl_ri, 1);
    if (not isnan(metrics.phy[i].dl.mcs)) {
      cout << float_to_string(SRSLTE_MAX(0.1, metrics.phy[i].dl.mcs), 2);
    } else {
      cout << float_to_string(0, 2);
    }
    if (metrics.stack.mac[i].tx_brate > 0) {
      cout << float_to_eng_string(SRSLTE_MAX(0.1, (float)metrics.stack.mac[i].tx_brate / period_usec * 1e6), 2);
    } else {
      cout << float_to_string(0, 2) << "";
    }
    if (metrics.stack.mac[i].tx_pkts > 0 && metrics.stack.mac[i].tx_errors) {
      cout << float_to_string(
                  SRSLTE_MAX(0.1, (float)100 * metrics.stack.mac[i].tx_errors / metrics.stack.mac[i].tx_pkts), 1)
           << "%";
    } else {
      cout << float_to_string(0, 1) << "%";
    }
    if (not isnan(metrics.phy[i].ul.sinr)) {
      cout << float_to_string(SRSLTE_MAX(0.1, metrics.phy[i].ul.sinr), 2);
    } else {
      cout << float_to_string(0, 2);
    }
    cout << float_to_string(metrics.stack.mac[i].phr, 2);
    if (not isnan(metrics.phy[i].ul.mcs)) {
      cout << float_to_string(SRSLTE_MAX(0.1, metrics.phy[i].ul.mcs), 2);
    } else {
      cout << float_to_string(0, 2);
    }
    if (metrics.stack.mac[i].rx_brate > 0) {
      cout << float_to_eng_string(SRSLTE_MAX(0.1, (float)metrics.stack.mac[i].rx_brate / period_usec * 1e6), 2);
    } else {
      cout << float_to_string(0, 2) << "";
    }
    if (metrics.stack.mac[i].rx_pkts > 0 && metrics.stack.mac[i].rx_errors > 0) {
      cout << float_to_string(
                  SRSLTE_MAX(0.1, (float)100 * metrics.stack.mac[i].rx_errors / metrics.stack.mac[i].rx_pkts), 1)
           << "%";
    } else {
      cout << float_to_string(0, 1) << "%";
    }
    cout << float_to_eng_string(metrics.stack.mac[i].ul_buffer, 2);
    cout << endl;
  }

  if (metrics.rf.rf_error) {
    printf("RF status: O=%d, U=%d, L=%d\n", metrics.rf.rf_o, metrics.rf.rf_u, metrics.rf.rf_l);
  }

  cout.flags(f); // For avoiding Coverity defect: Not restoring ostream format
}

std::string metrics_stdout::float_to_string(float f, int digits)
{
  std::ostringstream os;
  int precision;
  if (isnan(f) or fabs(f) < 0.0001) {
    f = 0.0;
    precision = digits-1;
  }
  else {
    precision = digits - (int)(log10(fabs(f))-2*DBL_EPSILON);
  }
  os << std::setw(6) << std::fixed << std::setprecision(precision) << f;
  return os.str();
}

std::string metrics_stdout::float_to_eng_string(float f, int digits)
{
  const int degree = (f == 0.0) ? 0 : lrint( floor( log10( fabs( f ) ) / 3) );

  std::string factor;

  if ( abs( degree ) < 9 )
  {
    if(degree < 0)
      factor = prefixes[0][ abs( degree ) ];
    else
      factor = prefixes[1][ abs( degree ) ];
  } else {
    return "failed";
  }

  const double scaled = f * pow( 1000.0, -degree );
  if (degree != 0) {
    return float_to_string(scaled, digits) + factor;
  } else {
    return " " + float_to_string(scaled, digits) + factor;
  }
}

} // namespace srsue
