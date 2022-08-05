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

#include "srslte/common/common.h"
#include "srslte/common/interfaces_common.h"
#include "srslte/common/log_filter.h"
#include "srslte/common/mac_pcap.h"
#include "srslte/common/pdu.h"
#include "srslte/interfaces/ue_interfaces.h"
#include <iostream>
#include <map>

#define TESTASSERT(cond)                                                                                               \
  {                                                                                                                    \
    if (!(cond)) {                                                                                                     \
      std::cout << "[" << __FUNCTION__ << "][Line " << __LINE__ << "]: FAIL at " << (#cond) << std::endl;              \
      return -1;                                                                                                       \
    }                                                                                                                  \
  }

#define HAVE_PCAP 0

static std::unique_ptr<srslte::mac_pcap> pcap_handle = nullptr;

using namespace srslte;

#define CRNTI (0x1001)

// TV1 contains a RAR PDU for a single RAPID and no backoff indication
#define RAPID_TV1 (42)
#define TA_CMD_TV1 (8)
uint8_t rar_pdu_tv1[] = {0x6a, 0x00, 0x80, 0x00, 0x0c, 0x10, 0x01};

// TV2 contains a RAR PDU for a single RAPID and also includes a backoff indication subheader
#define RAPID_TV2 (22)
#define BACKOFF_IND_TV2 (2)
#define TA_CMD_TV2 (0)
uint8_t rar_pdu_tv2[] = {0x82, 0x56, 0x00, 0x00, 0x00, 0x0c, 0x10, 0x01};

int mac_rar_pdu_unpack_test1()
{
  srslte::rar_pdu rar_pdu_msg;
  rar_pdu_msg.init_rx(sizeof(rar_pdu_tv1));
  rar_pdu_msg.parse_packet(rar_pdu_tv1);
  rar_pdu_msg.fprint(stdout);

  TESTASSERT(not rar_pdu_msg.has_backoff());
  while (rar_pdu_msg.next()) {
    TESTASSERT(rar_pdu_msg.get()->get_rapid() == RAPID_TV1);
    TESTASSERT(rar_pdu_msg.get()->get_ta_cmd() == TA_CMD_TV1);
    TESTASSERT(rar_pdu_msg.get()->get_temp_crnti() == CRNTI);
  }

  return SRSLTE_SUCCESS;
}

int mac_rar_pdu_unpack_test2()
{
  srslte::rar_pdu rar_pdu_msg;
  rar_pdu_msg.init_rx(sizeof(rar_pdu_tv2));
  rar_pdu_msg.parse_packet(rar_pdu_tv2);
  rar_pdu_msg.fprint(stdout);

  TESTASSERT(rar_pdu_msg.has_backoff());
  TESTASSERT(rar_pdu_msg.get_backoff() == BACKOFF_IND_TV2);
  while (rar_pdu_msg.next()) {
    if (rar_pdu_msg.get()->has_rapid()) {
      TESTASSERT(rar_pdu_msg.get()->get_rapid() == RAPID_TV2);
      TESTASSERT(rar_pdu_msg.get()->get_ta_cmd() == TA_CMD_TV2);
      TESTASSERT(rar_pdu_msg.get()->get_temp_crnti() == CRNTI);
    }
  }

  return SRSLTE_SUCCESS;
}

int mac_rar_pdu_pack_test1()
{
  // Prepare RAR grant
  uint8_t                grant_buffer[64] = {};
  srslte_dci_rar_grant_t rar_grant        = {};
  rar_grant.tpc_pusch                     = 3;
  srslte_dci_rar_pack(&rar_grant, grant_buffer);

  // Create MAC PDU and add RAR subheader
  srslte::rar_pdu rar_pdu;

  byte_buffer_t tx_buffer;
  rar_pdu.init_tx(&tx_buffer, 64);
  if (rar_pdu.new_subh()) {
    rar_pdu.get()->set_rapid(RAPID_TV1);
    rar_pdu.get()->set_ta_cmd(TA_CMD_TV1);
    rar_pdu.get()->set_temp_crnti(CRNTI);
    rar_pdu.get()->set_sched_grant(grant_buffer);
  }
  rar_pdu.write_packet(tx_buffer.msg);

  // compare with TV1
  TESTASSERT(memcmp(tx_buffer.msg, rar_pdu_tv1, sizeof(rar_pdu_tv1)) == 0);

  return SRSLTE_SUCCESS;
}

int mac_rar_pdu_pack_test2()
{
  // Prepare RAR grant
  uint8_t                grant_buffer[64] = {};
  srslte_dci_rar_grant_t rar_grant        = {};
  rar_grant.tpc_pusch                     = 3;
  srslte_dci_rar_pack(&rar_grant, grant_buffer);

  // Create MAC PDU and add RAR subheader
  srslte::rar_pdu rar_pdu;
  byte_buffer_t   tx_buffer;
  rar_pdu.init_tx(&tx_buffer, 64);
  rar_pdu.set_backoff(BACKOFF_IND_TV2);
  if (rar_pdu.new_subh()) {
    rar_pdu.get()->set_rapid(RAPID_TV2);
    rar_pdu.get()->set_ta_cmd(TA_CMD_TV2);
    rar_pdu.get()->set_temp_crnti(CRNTI);
    rar_pdu.get()->set_sched_grant(grant_buffer);
  }
  rar_pdu.write_packet(tx_buffer.msg);

  // compare with TV2
  TESTASSERT(memcmp(tx_buffer.msg, rar_pdu_tv2, sizeof(rar_pdu_tv2)) == 0);

  return SRSLTE_SUCCESS;
}

// Helper class to provide read_pdu_interface
class rlc_dummy : public srslte::read_pdu_interface
{
public:
  int read_pdu(uint32_t lcid, uint8_t* payload, uint32_t nof_bytes)
  {
    uint32_t len = SRSLTE_MIN(ul_queues[lcid], nof_bytes);

    // set payload bytes to LCID so we can check later if the scheduling was correct
    memset(payload, lcid, len);

    // remove from UL queue
    ul_queues[lcid] -= len;

    return len;
  };

  void write_sdu(uint32_t lcid, uint32_t nof_bytes) { ul_queues[lcid] += nof_bytes; }

private:
  // UL queues where key is LCID and value the queue length
  std::map<uint32_t, uint32_t> ul_queues;
};

// Basic test to pack a MAC PDU with a two SDUs of short length (i.e < 128B for short length header) and multi-byte
// padding
int mac_sch_pdu_pack_test1()
{
  static uint8_t tv[] = {0x21, 0x08, 0x22, 0x08, 0x1f, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                         0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00};

  srslte::log_filter rlc_log("RLC");
  rlc_log.set_level(srslte::LOG_LEVEL_DEBUG);
  rlc_log.set_hex_limit(100000);

  rlc_dummy rlc;

  srslte::log_filter mac_log("MAC");
  mac_log.set_level(srslte::LOG_LEVEL_DEBUG);
  mac_log.set_hex_limit(100000);

  // create RLC SDUs
  const uint32_t sdu_len = 8;
  rlc.write_sdu(1, sdu_len);
  rlc.write_sdu(2, sdu_len);

  const uint32_t  pdu_size = 25;
  srslte::sch_pdu pdu(10, &mac_log);

  byte_buffer_t buffer;
  pdu.init_tx(&buffer, pdu_size, true);

  TESTASSERT(pdu.rem_size() == pdu_size);
  TESTASSERT(pdu.get_pdu_len() == pdu_size);
  TESTASSERT(pdu.get_sdu_space() == pdu_size - 1);
  TESTASSERT(pdu.get_current_sdu_ptr() == buffer.msg);

  // Add first subheader and SDU
  TESTASSERT(pdu.new_subh());
  TESTASSERT(pdu.get()->set_sdu(1, sdu_len, &rlc) == sdu_len);

  // Have used 8 B SDU plus 1 B subheader
  TESTASSERT(pdu.rem_size() == pdu_size - 8 - 1);

  // Add second SCH
  TESTASSERT(pdu.new_subh());
  TESTASSERT(pdu.get()->set_sdu(2, sdu_len, &rlc) == sdu_len);
  TESTASSERT(pdu.rem_size() == pdu_size - 16 - 3);

  // write PDU
  TESTASSERT(pdu.write_packet(&mac_log) == buffer.msg);
  TESTASSERT(buffer.N_bytes == pdu_size);

  // log
  mac_log.info_hex(buffer.msg, buffer.N_bytes, "MAC PDU (%d B):\n", buffer.N_bytes);

#if HAVE_PCAP
  pcap_handle->write_ul_crnti(buffer.msg, buffer.N_bytes, 0x1001, true, 1);
#endif

  // compare with TV
  TESTASSERT(memcmp(buffer.msg, tv, sizeof(tv)) == 0);

  return SRSLTE_SUCCESS;
}

// Basic test to pack a MAC PDU with a two SDUs of short length (i.e < 128B for short length header) and 2x single-byte
// padding
int mac_sch_pdu_pack_test2()
{
  static uint8_t tv[] = {0x3f, 0x3f, 0x21, 0x08, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                         0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};

  srslte::log_filter rlc_log("RLC");
  rlc_log.set_level(srslte::LOG_LEVEL_DEBUG);
  rlc_log.set_hex_limit(100000);

  rlc_dummy rlc;

  srslte::log_filter mac_log("MAC");
  mac_log.set_level(srslte::LOG_LEVEL_DEBUG);
  mac_log.set_hex_limit(100000);

  // create RLC SDUs
  const uint32_t sdu_len = 8;
  rlc.write_sdu(1, sdu_len);
  rlc.write_sdu(2, sdu_len);

  const uint32_t pdu_size = 21;

  srslte::sch_pdu pdu(10, &mac_log);

  byte_buffer_t buffer;
  pdu.init_tx(&buffer, pdu_size, true);

  TESTASSERT(pdu.rem_size() == pdu_size);
  TESTASSERT(pdu.get_pdu_len() == pdu_size);
  TESTASSERT(pdu.get_sdu_space() == pdu_size - 1);
  TESTASSERT(pdu.get_current_sdu_ptr() == buffer.msg);

  // Add first subheader and SDU
  TESTASSERT(pdu.new_subh());
  TESTASSERT(pdu.get()->set_sdu(1, sdu_len, &rlc) == sdu_len);

  // Have used 8 B SDU plus 1 B subheader
  TESTASSERT(pdu.rem_size() == pdu_size - 8 - 1);

  // Add second SCH
  TESTASSERT(pdu.new_subh());
  TESTASSERT(pdu.get()->set_sdu(2, sdu_len, &rlc) == sdu_len);
  TESTASSERT(pdu.rem_size() == pdu_size - 16 - 3);

  // write PDU
  pdu.write_packet(&mac_log);

  // log
  mac_log.info_hex(buffer.msg, buffer.N_bytes, "MAC PDU (%d B):\n", buffer.N_bytes);

#if HAVE_PCAP
  pcap_handle->write_ul_crnti(buffer.msg, buffer.N_bytes, 0x1001, true, 1);
#endif

  // compare with TV
  TESTASSERT(memcmp(buffer.msg, tv, sizeof(tv)) == 0);

  return SRSLTE_SUCCESS;
}

// Basic test to pack a MAC PDU with one short and one long SDU (i.e >= 128 B for 16bit length header)
int mac_sch_pdu_pack_test3()
{
  static uint8_t tv[] = {
      0x21, 0x08, 0x22, 0x80, 0x82, 0x1f, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02,
      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  srslte::log_filter rlc_log("RLC");
  rlc_log.set_level(srslte::LOG_LEVEL_DEBUG);
  rlc_log.set_hex_limit(100000);

  rlc_dummy rlc;

  srslte::log_filter mac_log("MAC");
  mac_log.set_level(srslte::LOG_LEVEL_DEBUG);
  mac_log.set_hex_limit(100000);

  // create RLC SDUs
  // const uint32_t sdu_len = 130;
  rlc.write_sdu(1, 8);
  rlc.write_sdu(2, 130);

  const uint32_t  pdu_size = 150;
  srslte::sch_pdu pdu(10, &mac_log);

  byte_buffer_t buffer;
  pdu.init_tx(&buffer, pdu_size, true);

  TESTASSERT(pdu.rem_size() == pdu_size);
  TESTASSERT(pdu.get_pdu_len() == pdu_size);
  TESTASSERT(pdu.get_sdu_space() == pdu_size - 1);
  TESTASSERT(pdu.get_current_sdu_ptr() == buffer.msg);

  TESTASSERT(pdu.new_subh());
  TESTASSERT(pdu.get()->set_sdu(1, 8, &rlc));

  // Have used 8 B SDU plus 1 B subheader
  TESTASSERT(pdu.rem_size() == pdu_size - 8 - 1);

  TESTASSERT(pdu.new_subh());
  TESTASSERT(pdu.get()->set_sdu(2, 130, &rlc));

  // Have used 138 B SDU plus 3 B subheader
  TESTASSERT(pdu.rem_size() == pdu_size - 138 - 3);

  // write PDU
  pdu.write_packet(&mac_log);

  // log
  mac_log.info_hex(buffer.msg, buffer.N_bytes, "MAC PDU (%d B):\n", buffer.N_bytes);

#if HAVE_PCAP
  pcap_handle->write_ul_crnti(buffer.msg, buffer.N_bytes, 0x1001, true, 1);
#endif

  // compare with TV
  TESTASSERT(memcmp(buffer.msg, tv, sizeof(tv)) == 0);

  return SRSLTE_SUCCESS;
}

// Test for padding-only MAC PDU
int mac_sch_pdu_pack_test4()
{
  static uint8_t tv[] = {0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  srslte::log_filter rlc_log("RLC");
  rlc_log.set_level(srslte::LOG_LEVEL_DEBUG);
  rlc_log.set_hex_limit(100000);

  rlc_dummy rlc;

  srslte::log_filter mac_log("MAC");
  mac_log.set_level(srslte::LOG_LEVEL_DEBUG);
  mac_log.set_hex_limit(100000);

  const uint32_t  pdu_size = 10;
  srslte::sch_pdu pdu(10, &mac_log);

  byte_buffer_t buffer;
  pdu.init_tx(&buffer, pdu_size, true);

  TESTASSERT(pdu.rem_size() == pdu_size);
  TESTASSERT(pdu.get_pdu_len() == pdu_size);
  TESTASSERT(pdu.get_sdu_space() == pdu_size - 1);
  TESTASSERT(pdu.get_current_sdu_ptr() == buffer.msg);

  // Try to add SDU
  TESTASSERT(pdu.new_subh());
  TESTASSERT(pdu.get()->set_sdu(2, 5, &rlc) == 0);

  // Adding SDU failed, remove subheader again
  pdu.del_subh();

  // write PDU
  pdu.write_packet(&mac_log);

  // make sure full PDU has been written
  TESTASSERT(buffer.N_bytes == pdu_size);

  // log
  mac_log.info_hex(buffer.msg, buffer.N_bytes, "MAC PDU (%d B):\n", buffer.N_bytes);

#if HAVE_PCAP
  pcap_handle->write_ul_crnti(buffer.msg, buffer.N_bytes, 0x1001, true, 1);
#endif

  // compare with TV
  TESTASSERT(memcmp(buffer.msg, tv, sizeof(tv)) == 0);

  return SRSLTE_SUCCESS;
}

// Test for max. TBS MAC PDU
int mac_sch_pdu_pack_test5()
{
  rlc_dummy rlc;

  srslte::log_filter mac_log("MAC");
  mac_log.set_level(srslte::LOG_LEVEL_DEBUG);
  mac_log.set_hex_limit(32);

  // write big SDU
  rlc.write_sdu(2, 20000);

  const uint32_t  pdu_size = SRSLTE_MAX_TBSIZE_BITS / 8; // Max. DL allocation for a single TB using 256 QAM
  srslte::sch_pdu pdu(10, &mac_log);

  byte_buffer_t buffer;
  pdu.init_tx(&buffer, pdu_size, true);

  TESTASSERT(pdu.rem_size() == pdu_size);
  TESTASSERT(pdu.get_pdu_len() == pdu_size);
  TESTASSERT(pdu.get_sdu_space() == pdu_size - 1);
  TESTASSERT(pdu.get_current_sdu_ptr() == buffer.msg);

  // Try to add SDU
  TESTASSERT(pdu.new_subh());
  TESTASSERT(pdu.get()->set_sdu(2, pdu_size - 1, &rlc) != 0);

  // write PDU
  pdu.write_packet(&mac_log);

  // make sure full PDU has been written
  TESTASSERT(buffer.N_bytes == pdu_size);

  // log
  mac_log.info_hex(buffer.msg, buffer.N_bytes, "MAC PDU (%d B):\n", buffer.N_bytes);

#if HAVE_PCAP
  pcap_handle->write_ul_crnti(buffer.msg, buffer.N_bytes, 0x1001, true, 1);
#endif

  return SRSLTE_SUCCESS;
}

// Test for checking error cases
int mac_sch_pdu_pack_error_test()
{
  srslte::log_filter rlc_log("RLC");
  rlc_log.set_level(srslte::LOG_LEVEL_DEBUG);
  rlc_log.set_hex_limit(100000);

  rlc_dummy rlc;

  srslte::log_filter mac_log("MAC");
  mac_log.set_level(srslte::LOG_LEVEL_DEBUG);
  mac_log.set_hex_limit(100000);

  // create RLC SDUs
  rlc.write_sdu(1, 8);

  const uint32_t  pdu_size = 150;
  srslte::sch_pdu pdu(10, &mac_log);

  byte_buffer_t buffer;
  pdu.init_tx(&buffer, pdu_size, true);

  TESTASSERT(pdu.rem_size() == pdu_size);
  TESTASSERT(pdu.get_pdu_len() == pdu_size);
  TESTASSERT(pdu.get_sdu_space() == pdu_size - 1);
  TESTASSERT(pdu.get_current_sdu_ptr() == buffer.msg);

  // set msg pointer almost to end of byte buffer
  int buffer_space = buffer.get_tailroom();
  buffer.msg += buffer_space - 2;

  // subheader can be added
  TESTASSERT(pdu.new_subh());

  // adding SDU fails
  TESTASSERT(pdu.get()->set_sdu(1, 8, &rlc) == SRSLTE_ERROR);

  // writing PDU fails
  TESTASSERT(pdu.write_packet(&mac_log) == nullptr);

  // reset buffer
  buffer.clear();

  // write SDU again
  TESTASSERT(pdu.get() != nullptr);
  TESTASSERT(pdu.get()->set_sdu(1, 100, &rlc) == 8); // only 8 bytes in RLC buffer

  // writing PDU fails
  TESTASSERT(pdu.write_packet(&mac_log));

  // log
  mac_log.info_hex(buffer.msg, buffer.N_bytes, "MAC PDU (%d B):\n", buffer.N_bytes);

#if HAVE_PCAP
  pcap_handle->write_ul_crnti(buffer.msg, buffer.N_bytes, 0x1001, true, 1);
#endif

  return SRSLTE_SUCCESS;
}

int mac_mch_pdu_pack_test1() {
  static uint8_t tv[] = {0x3e, 0x02, 0x20, 0x05, 0x21, 0x0a, 0x1f, 0x0f,
                         0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x02, 0x04,
                         0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  srslte::log_filter mac_log("MAC");
  mac_log.set_level(srslte::LOG_LEVEL_DEBUG);
  mac_log.set_hex_limit(100000);

  const uint32_t pdu_size = 30;
  srslte::mch_pdu mch_pdu(10, &mac_log);
  byte_buffer_t buffer;
  mch_pdu.init_tx(&buffer, pdu_size, true);

  TESTASSERT(mch_pdu.rem_size() == pdu_size);
  TESTASSERT(mch_pdu.get_pdu_len() == pdu_size);
  TESTASSERT(mch_pdu.get_sdu_space() == pdu_size - 1);
  TESTASSERT(mch_pdu.get_current_sdu_ptr() == buffer.msg);
  // Add first subheader and SDU
  TESTASSERT(mch_pdu.new_subh());
  TESTASSERT(mch_pdu.get()->set_next_mch_sched_info(1, 0));

  // Add second SCH
  TESTASSERT(mch_pdu.new_subh());
  uint8_t sdu[5] = {1, 2, 3, 4, 5};
  TESTASSERT(mch_pdu.get()->set_sdu(0, 5, sdu) == 5);

  TESTASSERT(mch_pdu.new_subh());
  uint8_t sdu1[10] = {2, 4, 6, 8, 10, 12, 14, 16, 18, 20};
  mch_pdu.get()->set_sdu(1, 10, sdu1);

  // write PDU
  TESTASSERT(mch_pdu.write_packet(&mac_log) == buffer.msg);

  // log
  mac_log.info_hex(buffer.msg, buffer.N_bytes, "MAC PDU (%d B):\n",
                   buffer.N_bytes);

#if HAVE_PCAP
  pcap_handle->write_ul_crnti(buffer.msg, buffer.N_bytes, 0x1001, true, 1);
#endif

  // compare with TV
  TESTASSERT(memcmp(buffer.msg, tv, sizeof(buffer.N_bytes)) == 0);

#if HAVE_PCAP
  pcap_handle->write_ul_crnti(tv, sizeof(tv), 0x1001, true, 1);
#endif

  return SRSLTE_SUCCESS;
}

// Parsing a corrupted MAC PDU and making sure the PDU is reset and not further processed
int mac_sch_pdu_unpack_test1()
{
  static uint8_t tv[] = {0x3f, 0x3f, 0x21, 0x3f, 0x03, 0x00, 0x04, 0x00, 0x04};

  srslte::log_filter mac_log("MAC");
  mac_log.set_level(srslte::LOG_LEVEL_DEBUG);
  mac_log.set_hex_limit(100000);

  srslte::sch_pdu pdu(10, &mac_log);
  pdu.init_rx(sizeof(tv), false);
  pdu.parse_packet(tv);

  // make sure this PDU is reset and will not be further processed
  TESTASSERT(pdu.nof_subh() == 0);
  TESTASSERT(pdu.next() == false);

#if HAVE_PCAP
  pcap_handle->write_ul_crnti(tv, sizeof(tv), 0x1001, true, 1);
#endif

  return SRSLTE_SUCCESS;
}

int main(int argc, char** argv)
{
#if HAVE_PCAP
  pcap_handle = std::unique_ptr<srslte::mac_pcap>(new srslte::mac_pcap());
  pcap_handle->open("mac_pdu_test.pcap");
#endif

  if (mac_rar_pdu_unpack_test1()) {
    fprintf(stderr, "mac_rar_pdu_unpack_test1 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_rar_pdu_unpack_test2()) {
    fprintf(stderr, "mac_rar_pdu_unpack_test2 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_rar_pdu_pack_test1()) {
    fprintf(stderr, "mac_rar_pdu_pack_test1 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_rar_pdu_pack_test2()) {
    fprintf(stderr, "mac_rar_pdu_pack_test2 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_sch_pdu_pack_test1()) {
    fprintf(stderr, "mac_sch_pdu_pack_test1 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_sch_pdu_pack_test2()) {
    fprintf(stderr, "mac_sch_pdu_pack_test2 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_sch_pdu_pack_test3()) {
    fprintf(stderr, "mac_sch_pdu_pack_test3 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_sch_pdu_pack_test4()) {
    fprintf(stderr, "mac_sch_pdu_pack_test4 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_sch_pdu_pack_test5()) {
    fprintf(stderr, "mac_sch_pdu_pack_test5 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_sch_pdu_pack_error_test()) {
    fprintf(stderr, "mac_sch_pdu_pack_error_test failed.\n");
    return SRSLTE_ERROR;
  }
  
  if (mac_mch_pdu_pack_test1()) {
    fprintf(stderr, "mac_mch_pdu_pack_test1 failed.\n");
    return SRSLTE_ERROR;
  }

  if (mac_sch_pdu_unpack_test1()) {
    fprintf(stderr, "mac_sch_pdu_unpack_test1 failed.\n");
    return SRSLTE_ERROR;
  }

  return SRSLTE_SUCCESS;
}
