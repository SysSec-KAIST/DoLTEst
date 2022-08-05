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

#include "srslte/asn1/liblte_mme.h"
#include "srslte/common/log_filter.h"
#include "srsue/hdr/stack/upper/tft_packet_filter.h"
#include <iostream>
#include <memory>
#include <srslte/common/buffer_pool.h>
#include <srslte/common/int_helpers.h>
#include <srslte/srslte.h>

#define TESTASSERT(cond)                                                                                               \
  {                                                                                                                    \
    if (!(cond)) {                                                                                                     \
      std::cout << "[" << __FUNCTION__ << "][Line " << __LINE__ << "]: FAIL at " << (#cond) << std::endl;              \
      return -1;                                                                                                       \
    }                                                                                                                  \
  }
using namespace srsue;
using namespace srslte;

// IP test message 1
// Source IP 127.0.0.1, Destination IP 127.0.0.2
// Protocol UDP
// Source port 2222, Destination port 2001
uint8_t ip_tst_message1[] = {
    0x45, 0x04, 0x00, 0x5c, 0xb5, 0x8e, 0x40, 0x00, 0x40, 0x11, 0x86, 0xfb, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00,
    0x02, 0x08, 0xae, 0x07, 0xd1, 0x00, 0x48, 0xfe, 0x5c, 0xaf, 0xed, 0x69, 0x5a, 0x77, 0x80, 0x6e, 0x2f, 0x5e, 0xf3,
    0x76, 0x17, 0x05, 0xe4, 0x2b, 0xca, 0xb2, 0xd2, 0xcb, 0xa5, 0x58, 0x06, 0xc5, 0x02, 0x8d, 0xf1, 0x7a, 0x3d, 0x4f,
    0x14, 0x34, 0x58, 0x92, 0x37, 0x7c, 0x95, 0x53, 0x18, 0xa3, 0xff, 0x08, 0x1b, 0x07, 0x99, 0x94, 0xe2, 0x10, 0x0d,
    0x3d, 0x25, 0x20, 0x13, 0x95, 0x84, 0x53, 0x4b, 0x6a, 0x92, 0x64, 0x5a, 0xce, 0xbb, 0x6c, 0x3a,
};
uint32_t ip_message_len1 = sizeof(ip_tst_message1);

// IP test message 2
// Source IP 172.16.3.40, Destination IP 172.16.3.41
// Protocol UDP
// Source port 8000, Destination Port 9000
uint8_t ip_tst_message2[] = {
    0x45, 0x00, 0x00, 0x5c, 0x7a, 0x02, 0x40, 0x00, 0x40, 0x11, 0x62, 0x1d, 0xac, 0x10, 0x03, 0x28, 0xac, 0x10, 0x03,
    0x29, 0x1f, 0x40, 0x23, 0x28, 0x00, 0x48, 0x5e, 0xcb, 0xcc, 0x29, 0x54, 0x9a, 0xf5, 0x18, 0xab, 0x86, 0x8b, 0x5e,
    0x5c, 0xc8, 0x80, 0x55, 0x85, 0xd4, 0xcd, 0x25, 0xa2, 0x94, 0x28, 0xcc, 0xbc, 0xa4, 0xe6, 0x69, 0xcc, 0x45, 0x0c,
    0x9e, 0xb4, 0xf3, 0x78, 0xaf, 0xa0, 0xba, 0xcf, 0xd1, 0xd2, 0xce, 0x7d, 0x7f, 0x94, 0x4a, 0x73, 0xd4, 0x2d, 0xd2,
    0x88, 0x29, 0x60, 0x02, 0xde, 0x41, 0x11, 0xc2, 0xaa, 0x5e, 0x9e, 0x27, 0x74, 0xa5, 0xd3, 0x19};
uint32_t ip_message_len2 = sizeof(ip_tst_message2);

#define EPS_BEARER_ID 6
#define LCID 1

int tft_filter_test_single_local_port()
{
  srslte::log_filter log1("TFT");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(128);

  srslte::byte_buffer_pool *pool = srslte::byte_buffer_pool::get_instance();
  srslte::unique_byte_buffer_t ip_msg1, ip_msg2;
  ip_msg1 = allocate_unique_buffer(*pool);
  ip_msg2 = allocate_unique_buffer(*pool);

  // Filter length: 3 bytes
  // Filter type:   Single local port
  // Local port:    2222
  uint8_t filter_message[3];
  filter_message[0] = SINGLE_LOCAL_PORT_TYPE;
  srslte::uint16_to_uint8(2222, &filter_message[1]);


  // Set IP test message
  ip_msg1->N_bytes = ip_message_len1;
  memcpy(ip_msg1->msg, ip_tst_message1, ip_message_len1);
  log1.info_hex(ip_msg1->msg, ip_msg1->N_bytes, "IP test message\n");


  // Set IP test message
  ip_msg2->N_bytes = ip_message_len2;
  memcpy(ip_msg2->msg, ip_tst_message2, ip_message_len1);
  log1.info_hex(ip_msg2->msg, ip_msg2->N_bytes, "IP test message\n");

  // Packet filter
  LIBLTE_MME_PACKET_FILTER_STRUCT packet_filter;

  packet_filter.dir = LIBLTE_MME_TFT_PACKET_FILTER_DIRECTION_BIDIRECTIONAL;
  packet_filter.id = 1;
  packet_filter.eval_precedence = 0;
  packet_filter.filter_size = 3;
  memcpy(packet_filter.filter, filter_message, 3);

  srsue::tft_packet_filter_t filter(EPS_BEARER_ID, LCID, packet_filter, &log1);

  // Check filter
  TESTASSERT(filter.match(ip_msg1));
  TESTASSERT(!filter.match(ip_msg2));

  printf("Test TFT filter single local port successfull\n");
  return 0;
}

int tft_filter_test_single_remote_port()
{
  srslte::log_filter log1("TFT");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(128);

  srslte::byte_buffer_pool *pool = srslte::byte_buffer_pool::get_instance();
  srslte::unique_byte_buffer_t ip_msg1, ip_msg2;
  ip_msg1 = allocate_unique_buffer(*pool);
  ip_msg2 = allocate_unique_buffer(*pool);

  // Filter length: 3 bytes
  // Filter type:   Single remote port
  // Remote port:   2001
  uint8_t filter_message[3];
  filter_message[0] = SINGLE_REMOTE_PORT_TYPE;
  srslte::uint16_to_uint8(2001, &filter_message[1]);

  // Set IP test message
  ip_msg1->N_bytes = ip_message_len1;
  memcpy(ip_msg1->msg, ip_tst_message1, ip_message_len1);
  log1.info_hex(ip_msg1->msg, ip_msg1->N_bytes, "IP test message\n");


  // Set IP test message
  ip_msg2->N_bytes = ip_message_len2;
  memcpy(ip_msg2->msg, ip_tst_message2, ip_message_len1);
  log1.info_hex(ip_msg2->msg, ip_msg2->N_bytes, "IP test message\n");

  // Packet filter
  LIBLTE_MME_PACKET_FILTER_STRUCT packet_filter;

  packet_filter.dir = LIBLTE_MME_TFT_PACKET_FILTER_DIRECTION_BIDIRECTIONAL;
  packet_filter.id = 1;
  packet_filter.eval_precedence = 0;
  packet_filter.filter_size = 3;
  memcpy(packet_filter.filter, filter_message, 3);

  srsue::tft_packet_filter_t filter(EPS_BEARER_ID, LCID, packet_filter, &log1);

  // Check filter
  TESTASSERT(filter.match(ip_msg1));
  TESTASSERT(!filter.match(ip_msg2));

  printf("Test TFT packet filter single remote port successfull\n");
  return 0;
}

int tft_filter_test_ipv4_local_addr()
{
  srslte::log_filter log1("TFT");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(128);

  srslte::byte_buffer_pool *pool = srslte::byte_buffer_pool::get_instance();
  srslte::unique_byte_buffer_t ip_msg1, ip_msg2;
  ip_msg1 = allocate_unique_buffer(*pool);
  ip_msg2 = allocate_unique_buffer(*pool);

  // Filter length: 5 bytes
  // Filter type:   IPv4 local address
  // Local address: 127.0.0.1
  uint8_t filter_message[5];
  uint8_t filter_size = 5;
  filter_message[0] = IPV4_LOCAL_ADDR_TYPE;
  inet_pton(AF_INET, "127.0.0.1", &filter_message[1]);

  // Set IP test message
  ip_msg1->N_bytes = ip_message_len1;
  memcpy(ip_msg1->msg, ip_tst_message1, ip_message_len1);
  log1.info_hex(ip_msg1->msg, ip_msg1->N_bytes, "IP test message\n");


  // Set IP test message
  ip_msg2->N_bytes = ip_message_len2;
  memcpy(ip_msg2->msg, ip_tst_message2, ip_message_len2);
  log1.info_hex(ip_msg2->msg, ip_msg2->N_bytes, "IP test message\n");

  // Packet filter
  LIBLTE_MME_PACKET_FILTER_STRUCT packet_filter;

  packet_filter.dir = LIBLTE_MME_TFT_PACKET_FILTER_DIRECTION_BIDIRECTIONAL;
  packet_filter.id = 1;
  packet_filter.eval_precedence = 0;
  packet_filter.filter_size = filter_size;
  memcpy(packet_filter.filter, filter_message, filter_size);

  srsue::tft_packet_filter_t filter(EPS_BEARER_ID, LCID, packet_filter, &log1);

  // Check filter
  TESTASSERT(filter.match(ip_msg1));
  TESTASSERT(!filter.match(ip_msg2));

  printf("Test TFT packet filter local IPv4 address successfull\n");
  return 0;
}

int tft_filter_test_ipv4_remote_addr()
{
  srslte::log_filter log1("TFT");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(128);

  srslte::byte_buffer_pool *pool = srslte::byte_buffer_pool::get_instance();
  srslte::unique_byte_buffer_t ip_msg1, ip_msg2;
  ip_msg1 = allocate_unique_buffer(*pool);
  ip_msg2 = allocate_unique_buffer(*pool);

  // Filter length: 5 bytes
  // Filter type:   IPv4 local address
  // Remote address: 127.0.0.2
  uint8_t filter_message[5];
  uint8_t filter_size = 5;
  filter_message[0] = IPV4_REMOTE_ADDR_TYPE;
  inet_pton(AF_INET, "127.0.0.2", &filter_message[1]);

  // Set IP test message
  ip_msg1->N_bytes = ip_message_len1;
  memcpy(ip_msg1->msg, ip_tst_message1, ip_message_len1);
  log1.info_hex(ip_msg1->msg, ip_msg1->N_bytes, "IP test message\n");


  // Set IP test message
  ip_msg2->N_bytes = ip_message_len2;
  memcpy(ip_msg2->msg, ip_tst_message2, ip_message_len2);
  log1.info_hex(ip_msg2->msg, ip_msg2->N_bytes, "IP test message\n");

  // Packet filter
  LIBLTE_MME_PACKET_FILTER_STRUCT packet_filter;

  packet_filter.dir = LIBLTE_MME_TFT_PACKET_FILTER_DIRECTION_BIDIRECTIONAL;
  packet_filter.id = 1;
  packet_filter.eval_precedence = 0;
  packet_filter.filter_size = filter_size;
  memcpy(packet_filter.filter, filter_message, filter_size);

  srsue::tft_packet_filter_t filter(EPS_BEARER_ID, LCID, packet_filter, &log1);

  // Check filter
  TESTASSERT(filter.match(ip_msg1));
  TESTASSERT(!filter.match(ip_msg2));

  printf("Test TFT packet filter remote IPv4 address successfull\n");
  return 0;
}

int tft_filter_test_ipv4_tos()
{
  srslte::log_filter log1("TFT");
  log1.set_level(srslte::LOG_LEVEL_DEBUG);
  log1.set_hex_limit(128);

  srslte::byte_buffer_pool *pool = srslte::byte_buffer_pool::get_instance();
  srslte::unique_byte_buffer_t ip_msg1, ip_msg2;
  ip_msg1 = allocate_unique_buffer(*pool);
  ip_msg2 = allocate_unique_buffer(*pool);

  // Filter length: 2 bytes
  // Filter type:   Type of service
  // ToS:           4
  uint8_t filter_message[2];
  uint8_t filter_size = 2;
  filter_message[0] = TYPE_OF_SERVICE_TYPE;
  filter_message[1] = 4;

  // Set IP test message
  ip_msg1->N_bytes = ip_message_len1;
  memcpy(ip_msg1->msg, ip_tst_message1, ip_message_len1);
  log1.info_hex(ip_msg1->msg, ip_msg1->N_bytes, "IP test message\n");

  // Set IP test message
  ip_msg2->N_bytes = ip_message_len2;
  memcpy(ip_msg2->msg, ip_tst_message2, ip_message_len2);
  log1.info_hex(ip_msg2->msg, ip_msg2->N_bytes, "IP test message\n");

  // Packet filter
  LIBLTE_MME_PACKET_FILTER_STRUCT packet_filter;

  packet_filter.dir = LIBLTE_MME_TFT_PACKET_FILTER_DIRECTION_BIDIRECTIONAL;
  packet_filter.id = 1;
  packet_filter.eval_precedence = 0;
  packet_filter.filter_size = filter_size;
  memcpy(packet_filter.filter, filter_message, filter_size);

  srsue::tft_packet_filter_t filter(EPS_BEARER_ID, LCID, packet_filter, &log1);

  // Check filter
  TESTASSERT(filter.match(ip_msg1));
  TESTASSERT(!filter.match(ip_msg2));

  printf("Test TFT packet filter type of service successfull\n");
  return 0;
}

int main(int argc, char **argv)
{
  srslte::byte_buffer_pool::get_instance();
  if (tft_filter_test_single_local_port()) {
    return -1;
  }
  if (tft_filter_test_single_remote_port()) {
    return -1;
  }
  if (tft_filter_test_ipv4_local_addr()) {
    return -1;
  }
  if (tft_filter_test_ipv4_remote_addr()) {
    return -1;
  }
  if (tft_filter_test_ipv4_tos()) {
    return -1;
  }
  srslte::byte_buffer_pool::cleanup();
}
