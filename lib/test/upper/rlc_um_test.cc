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

#include <iostream>
#include "srslte/common/log_filter.h"
#include "srslte/upper/rlc_um.h"

#define TESTASSERT(cond)                                                                                               \
  {                                                                                                                    \
    if (!(cond)) {                                                                                                     \
      std::cout << "[" << __FUNCTION__ << "][Line " << __LINE__ << "]: FAIL at " << (#cond) << std::endl;              \
      return -1;                                                                                                       \
    }                                                                                                                  \
  }

#define MAX_NBUFS 100
#define NBUFS 5

using namespace srslte;
using namespace srsue;
using namespace asn1::rrc;

class mac_dummy_timers
    :public srslte::mac_interface_timers
{
public:
  srslte::timers::timer* timer_get(uint32_t timer_id)
  {
    return &t;
  }
  uint32_t timer_get_unique_id(){return 0;}
  void step()
  {
    t.step();
  }
  void timer_release_id(uint32_t timer_id) {}
private:
  srslte::timers::timer t;
};

class rlc_um_tester
    :public pdcp_interface_rlc
    ,public rrc_interface_rlc
{
public:
  rlc_um_tester(){
    bzero(sdus, sizeof(sdus));
    n_sdus = 0;
    expected_sdu_len = 0;
  }

  // PDCP interface
  void write_pdu(uint32_t lcid, unique_byte_buffer_t sdu)
  {
    if (lcid != 3 && sdu->N_bytes != expected_sdu_len) {
      printf("Received PDU with size %d, expected %d. Exiting.\n", sdu->N_bytes, expected_sdu_len);
      exit(-1);
    }
    sdus[n_sdus++] = std::move(sdu);
  }
  void write_pdu_bcch_bch(unique_byte_buffer_t sdu) {}
  void write_pdu_bcch_dlsch(unique_byte_buffer_t sdu) {}
  void write_pdu_pcch(unique_byte_buffer_t sdu) {}
  void write_pdu_mch(uint32_t lcid, srslte::unique_byte_buffer_t sdu)
  {
    sdus[n_sdus++] = std::move(sdu);
  }
  
  // RRC interface
  void max_retx_attempted(){}
  std::string get_rb_name(uint32_t lcid) { return std::string(""); }
  void set_expected_sdu_len(uint32_t len) { expected_sdu_len = len; }

  unique_byte_buffer_t sdus[MAX_NBUFS];
  int n_sdus;
  uint32_t expected_sdu_len;
};


int basic_test()
{
  srslte::log_filter log1("RLC_UM_1");
  srslte::log_filter log2("RLC_UM_2");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log2.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(-1);
  log2.set_hex_limit(-1);
  rlc_um_tester    tester;
  mac_dummy_timers timers;
  int              len = 0;

  rlc_um rlc1(&log1, 3, &tester, &tester, &timers);
  rlc_um rlc2(&log2, 3, &tester, &tester, &timers);

  rlc_config_t cnfg          = rlc_config_t::default_rlc_um_config(10);
  cnfg.rlc_mode              = rlc_mode_t::um;
  cnfg.um.t_reordering       = 5;
  cnfg.um.rx_sn_field_length = rlc_umd_sn_size_t::size10bits;
  cnfg.um.rx_window_size     = 512;
  cnfg.um.rx_mod             = 1024;
  cnfg.um.tx_sn_field_length = rlc_umd_sn_size_t::size10bits;
  cnfg.um.tx_mod             = 1024;

  TESTASSERT(rlc1.configure(cnfg) == true);
  TESTASSERT(rlc2.configure(cnfg) == true);

  tester.set_expected_sdu_len(1);

  // Push 5 SDUs into RLC1
  byte_buffer_pool*  pool = byte_buffer_pool::get_instance();
  unique_byte_buffer_t sdu_bufs[NBUFS];
  for(int i=0;i<NBUFS;i++)
  {
    sdu_bufs[i]          = srslte::allocate_unique_buffer(*pool, true);
    *sdu_bufs[i]->msg    = i; // Write the index into the buffer
    sdu_bufs[i]->N_bytes = 1; // Give each buffer a size of 1 byte
    rlc1.write_sdu(std::move(sdu_bufs[i]));
  }

  TESTASSERT(14 == rlc1.get_buffer_state());

  // Read 5 PDUs from RLC1 (1 byte each)
  byte_buffer_t pdu_bufs[NBUFS];
  for(int i=0;i<NBUFS;i++)
  {
    len = rlc1.read_pdu(pdu_bufs[i].msg, 4); // 3 bytes for header + payload
    pdu_bufs[i].N_bytes = len;
  }

  TESTASSERT(0 == rlc1.get_buffer_state());

  // Write 5 PDUs into RLC2
  for(int i=0;i<NBUFS;i++)
  {
    rlc2.write_pdu(pdu_bufs[i].msg, pdu_bufs[i].N_bytes);
  }

  TESTASSERT(0 == rlc2.get_buffer_state());

  TESTASSERT(NBUFS == tester.n_sdus);
  for(int i=0; i<tester.n_sdus; i++)
  {
    TESTASSERT(tester.sdus[i]->N_bytes == 1);
    TESTASSERT(*(tester.sdus[i]->msg) == i);
  }

  return 0;
}

int loss_test()
{
  srslte::log_filter log1("RLC_UM_1");
  srslte::log_filter log2("RLC_UM_2");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log2.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(-1);
  log2.set_hex_limit(-1);
  rlc_um_tester    tester;
  mac_dummy_timers timers;
  int              len = 0;

  rlc_um rlc1(&log1, 3, &tester, &tester, &timers);
  rlc_um rlc2(&log2, 3, &tester, &tester, &timers);

  rlc_config_t cnfg = rlc_config_t::default_rlc_um_config(10);

  rlc1.configure(cnfg);
  rlc2.configure(cnfg);

  tester.set_expected_sdu_len(1);

  // Push 5 SDUs into RLC1
  byte_buffer_pool*  pool = byte_buffer_pool::get_instance();
  unique_byte_buffer_t sdu_bufs[NBUFS];
  for(int i=0;i<NBUFS;i++)
  {
    sdu_bufs[i]          = srslte::allocate_unique_buffer(*pool, true);
    sdu_bufs[i]->msg[0]  = i; // Write the index into the buffer
    sdu_bufs[i]->N_bytes = 1; // Give each buffer a size of 1 byte
    rlc1.write_sdu(std::move(sdu_bufs[i]));
  }

  TESTASSERT(14 == rlc1.get_buffer_state());

  // Read 5 PDUs from RLC1 (1 byte each)
  byte_buffer_t pdu_bufs[NBUFS];
  for(int i=0;i<NBUFS;i++)
  {
    len = rlc1.read_pdu(pdu_bufs[i].msg, 4); // 3 bytes for header + payload
    pdu_bufs[i].N_bytes = len;
  }

  TESTASSERT(0 == rlc1.get_buffer_state());

  // Write 5 PDUs into RLC2 (skip SN 1)
  for(int i=0;i<NBUFS;i++)
  {
    if(i != 1)
      rlc2.write_pdu(pdu_bufs[i].msg, pdu_bufs[i].N_bytes);
  }

  // Step the reordering timer until expiry
  while(!timers.timer_get(1)->is_expired())
    timers.timer_get(1)->step();

  TESTASSERT(NBUFS - 1 == tester.n_sdus);

  return 0;
}

int basic_mbsfn_test()
{
  srslte::log_filter log1("RLC_UM_1");
  srslte::log_filter log2("RLC_UM_2");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log2.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(-1);
  log2.set_hex_limit(-1);
  rlc_um_tester    tester;
  mac_dummy_timers timers;
  int              len = 0;

  rlc_um rlc1(&log1, 3, &tester, &tester, &timers);
  rlc_um rlc2(&log2, 3, &tester, &tester, &timers);

  rlc1.configure(rlc_config_t::mch_config());
  rlc2.configure(rlc_config_t::mch_config());

  tester.set_expected_sdu_len(1);

  // Push 5 SDUs into RLC1
  byte_buffer_pool*  pool = byte_buffer_pool::get_instance();
  unique_byte_buffer_t sdu_bufs[NBUFS * 2];
  for(int i=0;i<NBUFS;i++)
  {
    sdu_bufs[i]          = srslte::allocate_unique_buffer(*pool, true);
    sdu_bufs[i]->msg[0]  = i; // Write the index into the buffer
    sdu_bufs[i]->N_bytes = 1; // Give each buffer a size of 1 byte
    rlc1.write_sdu(std::move(sdu_bufs[i]));
  }

  TESTASSERT(13 == rlc1.get_buffer_state());

  // Read 5 PDUs from RLC1 (1 byte each)
  byte_buffer_t pdu_bufs[NBUFS*2];
  for(int i=0;i<NBUFS;i++)
  {
    len = rlc1.read_pdu(pdu_bufs[i].msg, 3); // 2 bytes for header + payload
    pdu_bufs[i].N_bytes = len;
  }

  TESTASSERT(0 == rlc1.get_buffer_state());

  // Write 5 PDUs into RLC2
  for(int i=0;i<NBUFS;i++)
  {
    rlc2.write_pdu(pdu_bufs[i].msg, pdu_bufs[i].N_bytes);
  }

  TESTASSERT(0 == rlc2.get_buffer_state());

  TESTASSERT(NBUFS == tester.n_sdus);
  for(int i=0; i<tester.n_sdus; i++)
  {
    TESTASSERT(tester.sdus[i]->N_bytes == 1);
    TESTASSERT(*(tester.sdus[i]->msg) == i);
  }

  return 0;
}


 // This test checks the reassembly routines when a PDU
// is lost that contains the beginning of SDU segment.
// The PDU that contains the end of this SDU _also_ contains
// a segment of another SDU.
// On reassembly of the SDUs, the missing start segment
// should be detected and the complete SDU be discarded
// Therefore, one SDU less should be received than was tx'ed.
// This test sends PDU in two batches so it's not the reordering
// timeout that detects the missing PDU but the fact more
// PDUs than rx_mod are received.
int reassmble_test()
{
  srslte::log_filter log1("RLC_UM_1");
  srslte::log_filter log2("RLC_UM_2");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log2.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(-1);
  log2.set_hex_limit(-1);
  rlc_um_tester    tester;
  mac_dummy_timers timers;
  int              len = 0;

  rlc_um rlc1(&log1, 3, &tester, &tester, &timers);
  rlc_um rlc2(&log2, 3, &tester, &tester, &timers);

  rlc_config_t cnfg = rlc_config_t::default_rlc_um_config(5);

  rlc1.configure(cnfg);
  rlc2.configure(cnfg);

  // Push SDUs into RLC1
  const int n_sdus = 25;
  const int sdu_len = 100;

  tester.set_expected_sdu_len(sdu_len);


  const int n_sdu_first_batch = 17;

  byte_buffer_pool*  pool = byte_buffer_pool::get_instance();
  unique_byte_buffer_t sdu_bufs[n_sdus];
  for(int i=0;i<n_sdu_first_batch;i++) {
    sdu_bufs[i] = srslte::allocate_unique_buffer(*pool, true);
    for (int k = 0; k < sdu_len; ++k) {
      sdu_bufs[i]->msg[k] = i;
    }
    sdu_bufs[i]->N_bytes = sdu_len; // Give each buffer a size of 1 byte
    rlc1.write_sdu(std::move(sdu_bufs[i]));
  }

  // Read PDUs from RLC1 (use smaller grant for first PDU and large for the rest)
  const int max_n_pdus = 100;
  int n_pdus = 0;
  byte_buffer_t* pdu_bufs[max_n_pdus];
  for(int i=0;i<max_n_pdus;i++)
  {
    pdu_bufs[i]          = byte_buffer_pool::get_instance()->allocate();
    len                  = rlc1.read_pdu(pdu_bufs[i]->msg, (i == 0) ? sdu_len * 3 / 4 : sdu_len * 1.25);
    pdu_bufs[i]->N_bytes = len;
    if (len) {
      n_pdus++;
    } else {
      break;
    }
  }

  printf("Generated %d PDUs in first batch\n", n_pdus);
  TESTASSERT(0 == rlc1.get_buffer_state());

  // push second batch of SDUs
  for (int i = n_sdu_first_batch; i < n_sdus; ++i) {
    sdu_bufs[i] = srslte::allocate_unique_buffer(*pool, true);
    for (int k = 0; k < sdu_len; ++k) {
      sdu_bufs[i]->msg[k] = i;
    }
    sdu_bufs[i]->N_bytes = sdu_len; // Give each buffer a size of 1 byte
    rlc1.write_sdu(std::move(sdu_bufs[i]));
  }

  // Read second batch of PDUs (use large grants)
  for(int i=n_pdus;i<max_n_pdus;i++)
  {
    pdu_bufs[i]          = byte_buffer_pool::get_instance()->allocate();
    len                  = rlc1.read_pdu(pdu_bufs[i]->msg, sdu_len * 1.25);
    pdu_bufs[i]->N_bytes = len;
    if (len) {
      n_pdus++;
    } else {
      // stop reading PDUs after first zero length PDU
      break;
    }
  }

  printf("Generated %d PDUs in total\n", n_pdus);

  // Write all PDUs into RLC2 except first one
  for(int i=0;i<n_pdus;i++)
  {
    if (i!=0) {
      rlc2.write_pdu(pdu_bufs[i]->msg, pdu_bufs[i]->N_bytes);
    }
  }

  // We should have received one SDU less than we tx'ed
  TESTASSERT(tester.n_sdus == n_sdus - 1);
  for (int i = 0; i < tester.n_sdus; ++i) {
    TESTASSERT(tester.sdus[i]->N_bytes == sdu_len);
  }

  return 0;
}

// This reassmble test checks the reassembly routines when a PDU
// is lost that _only_ contains the beginning of SDU segment,
// while the next PDU contains the middle part of this SDU (and
// yet another PDU the end part).
// On reassembly of the SDUs, the missing start segment
// should be detected and the complete SDU be discarded
// Therefore, one SDU less should be received than was tx'ed.
int reassmble_test2()
{
  srslte::log_filter log1("RLC_UM_1");
  srslte::log_filter log2("RLC_UM_2");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log2.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(-1);
  log2.set_hex_limit(-1);
  rlc_um_tester    tester;
  mac_dummy_timers timers;
  int              len = 0;

  rlc_um rlc1(&log1, 3, &tester, &tester, &timers);
  rlc_um rlc2(&log2, 3, &tester, &tester, &timers);

  rlc_config_t cnfg = rlc_config_t::default_rlc_um_config(5);

  rlc1.configure(cnfg);
  rlc2.configure(cnfg);

  // Push SDUs into RLC1
  const int n_sdus = 25;
  const int sdu_len = 100;

  tester.set_expected_sdu_len(sdu_len);

  const int n_sdu_first_batch = 17;
  byte_buffer_pool*  pool              = byte_buffer_pool::get_instance();
  unique_byte_buffer_t sdu_bufs[n_sdus];
  for(int i=0;i<n_sdu_first_batch;i++) {
    sdu_bufs[i] = srslte::allocate_unique_buffer(*pool, true);
    for (int k = 0; k < sdu_len; ++k) {
      sdu_bufs[i]->msg[k] = i;
    }
    sdu_bufs[i]->N_bytes = sdu_len;
    rlc1.write_sdu(std::move(sdu_bufs[i]));
  }

  const int max_n_pdus = 100;
  int n_pdus = 0;
  byte_buffer_t* pdu_bufs[max_n_pdus];
  for(int i=0;i<max_n_pdus;i++)
  {
    pdu_bufs[i]          = byte_buffer_pool::get_instance()->allocate();
    len                  = rlc1.read_pdu(pdu_bufs[i]->msg, (i == 0) ? sdu_len * .75 : sdu_len * .25);
    pdu_bufs[i]->N_bytes = len;
    if (len) {
      n_pdus++;
    } else {
      break;
    }
  }

  printf("Generated %d PDUs in first batch\n", n_pdus);
  TESTASSERT(0 == rlc1.get_buffer_state());

  // push second batch of SDUs
  for (int i = n_sdu_first_batch; i < n_sdus; ++i) {
    sdu_bufs[i] = srslte::allocate_unique_buffer(*pool, true);
    for (int k = 0; k < sdu_len; ++k) {
      sdu_bufs[i]->msg[k] = i;
    }
    sdu_bufs[i]->N_bytes = sdu_len; // Give each buffer a size of 1 byte
    rlc1.write_sdu(std::move(sdu_bufs[i]));
  }

  // Read second batch of PDUs
  for(int i=n_pdus;i<max_n_pdus;i++)
  {
    pdu_bufs[i]          = byte_buffer_pool::get_instance()->allocate();
    len                  = rlc1.read_pdu(pdu_bufs[i]->msg, sdu_len * 1.25);
    pdu_bufs[i]->N_bytes = len;
    if (len) {
      n_pdus++;
    } else {
      break;
    }
  }

  printf("Generated %d PDUs in total\n", n_pdus);

  // Write all PDUs into RLC2 except first one
  for(int i=0;i<n_pdus;i++) {
    if (i!=0) {
      rlc2.write_pdu(pdu_bufs[i]->msg, pdu_bufs[i]->N_bytes);
    }
  }

  // We should have received one SDU less than we tx'ed
  TESTASSERT(tester.n_sdus == n_sdus - 1);
  for (int i = 0; i < tester.n_sdus; ++i) {
    TESTASSERT(tester.sdus[i]->N_bytes == sdu_len);
  }

  return 0;
}

int main(int argc, char** argv)
{
  if (basic_test()) {
    return -1;
  }
  byte_buffer_pool::get_instance()->cleanup();

  if (loss_test()) {
    return -1;
  }
  byte_buffer_pool::get_instance()->cleanup();

  if (basic_mbsfn_test()) {
    return -1;
  }
  byte_buffer_pool::get_instance()->cleanup();

  if (reassmble_test()) {
    return -1;
  }
  byte_buffer_pool::get_instance()->cleanup();

  if (reassmble_test2()) {
    return -1;
  }
  byte_buffer_pool::get_instance()->cleanup();
}

