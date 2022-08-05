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

#ifndef SRSLTE_RLC_COMMON_H
#define SRSLTE_RLC_COMMON_H

#include "srslte/common/block_queue.h"
#include <stdlib.h>

namespace srslte {

/****************************************************************************
 * Structs and Defines
 * Ref: 3GPP TS 36.322 v10.0.0
 ***************************************************************************/

#define RLC_AM_WINDOW_SIZE  512
#define RLC_MAX_SDU_SIZE ((1<<11)-1) // Length of LI field is 11bits


typedef enum{
  RLC_FI_FIELD_START_AND_END_ALIGNED = 0,
  RLC_FI_FIELD_NOT_END_ALIGNED,
  RLC_FI_FIELD_NOT_START_ALIGNED,
  RLC_FI_FIELD_NOT_START_OR_END_ALIGNED,
  RLC_FI_FIELD_N_ITEMS,
}rlc_fi_field_t;
static const char rlc_fi_field_text[RLC_FI_FIELD_N_ITEMS][32] = {"Start and end aligned",
                                                                 "Not end aligned",
                                                                 "Not start aligned",
                                                                 "Not start or end aligned"};

typedef enum{
  RLC_DC_FIELD_CONTROL_PDU = 0,
  RLC_DC_FIELD_DATA_PDU,
  RLC_DC_FIELD_N_ITEMS,
}rlc_dc_field_t;
static const char rlc_dc_field_text[RLC_DC_FIELD_N_ITEMS][20] = {"Control PDU",
                                                                 "Data PDU"};

// UMD PDU Header
typedef struct{
  uint8_t           fi;                     // Framing info
  rlc_umd_sn_size_t sn_size;                // Sequence number size (5 or 10 bits)
  uint16_t          sn;                     // Sequence number
  uint32_t          N_li;                   // Number of length indicators
  uint16_t          li[RLC_AM_WINDOW_SIZE]; // Array of length indicators
}rlc_umd_pdu_header_t;

// AMD PDU Header
struct rlc_amd_pdu_header_t{
  rlc_dc_field_t dc;                      // Data or control
  uint8_t        rf;                      // Resegmentation flag
  uint8_t        p;                       // Polling bit
  uint8_t        fi;                      // Framing info
  uint16_t       sn;                      // Sequence number
  uint8_t        lsf;                     // Last segment flag
  uint16_t       so;                      // Segment offset
  uint32_t       N_li;                    // Number of length indicators
  uint16_t       li[RLC_AM_WINDOW_SIZE];  // Array of length indicators

  rlc_amd_pdu_header_t(){
    dc = RLC_DC_FIELD_CONTROL_PDU;
    rf = 0; 
    p  = 0; 
    fi = 0; 
    sn = 0; 
    lsf = 0; 
    so = 0; 
    N_li=0;
    for(int i=0;i<RLC_AM_WINDOW_SIZE;i++)
      li[i] = 0;
  }
  rlc_amd_pdu_header_t(const rlc_amd_pdu_header_t& h)
  {
    copy(h);
  }
  rlc_amd_pdu_header_t& operator= (const rlc_amd_pdu_header_t& h)
  {
    copy(h);
    return *this;
  }
  void copy(const rlc_amd_pdu_header_t& h)
  {
    dc   = h.dc;
    rf   = h.rf;
    p    = h.p;
    fi   = h.fi;
    sn   = h.sn;
    lsf  = h.lsf;
    so   = h.so;
    N_li = h.N_li;
    for(uint32_t i=0;i<h.N_li;i++)
      li[i] = h.li[i];
  }
};

// NACK helper
struct rlc_status_nack_t{
  uint16_t nack_sn;
  bool     has_so;
  uint16_t so_start;
  uint16_t so_end;

  rlc_status_nack_t(){has_so=false; nack_sn=0; so_start=0; so_end=0;}
};

// STATUS PDU
struct rlc_status_pdu_t{
  uint16_t          ack_sn;
  uint32_t          N_nack;
  rlc_status_nack_t nacks[RLC_AM_WINDOW_SIZE];

  rlc_status_pdu_t(){N_nack=0; ack_sn=0;}
};

/****************************************************************************
 * RLC Common interface
 * Common interface for all RLC entities
 ***************************************************************************/
class rlc_common
{
public:

  // Size of the Uplink buffer in number of PDUs
  const static int RLC_BUFFER_NOF_PDU = 128;

  virtual ~rlc_common() {}
  virtual bool configure(rlc_config_t cnfg) = 0;
  virtual void stop()                       = 0;
  virtual void reestablish()                = 0;
  virtual void empty_queue()                = 0;

  bool suspend()
  {
    if (is_suspended) {
      return false;
    }
    is_suspended = true;
    return true;
  }

  // Pops all PDUs from queue and calls write_pdu() method for the bearer type
  bool resume()
  {
    if (!is_suspended) {
      return false;
    }
    pdu_t p;
    // Do not block
    while (rx_pdu_resume_queue.try_pop(&p)) {
      write_pdu(p.payload, p.nof_bytes);
      free(p.payload);
    }
    is_suspended = false;
    return true;
  }

  void write_pdu_s(uint8_t* payload, uint32_t nof_bytes)
  {
    if (is_suspended) {
      queue_pdu(payload, nof_bytes);
    } else {
      write_pdu(payload, nof_bytes);
    }
  }

  virtual rlc_mode_t    get_mode() = 0;
  virtual uint32_t      get_bearer() = 0;

  virtual uint32_t get_num_tx_bytes() = 0;
  virtual uint32_t get_num_rx_bytes() = 0;
  virtual void reset_metrics() = 0;

  // PDCP interface
  virtual void write_sdu(unique_byte_buffer_t sdu, bool blocking) = 0;

  // MAC interface
  virtual bool     has_data() = 0;
  virtual uint32_t get_buffer_state() = 0;
  virtual int      read_pdu(uint8_t *payload, uint32_t nof_bytes) = 0;
  virtual void     write_pdu(uint8_t *payload, uint32_t nof_bytes) = 0;

private:
  bool is_suspended = false;

  // Enqueues the PDU in the resume queue
  void queue_pdu(uint8_t* payload, uint32_t nof_bytes)
  {
    pdu_t p     = {};
    p.nof_bytes = nof_bytes;
    p.payload   = (uint8_t*)malloc(nof_bytes);
    memcpy(p.payload, payload, nof_bytes);

    // Do not block ever
    if (!rx_pdu_resume_queue.try_push(p)) {
      fprintf(stderr, "Error dropping PDUs while bearer suspended. Queue should be unbounded\n");
      return;
    }
  }

  typedef struct {
    uint8_t* payload;
    uint32_t nof_bytes;
  } pdu_t;

  block_queue<pdu_t> rx_pdu_resume_queue;
};

} // namespace srslte

#endif // SRSLTE_RLC_COMMON_H
