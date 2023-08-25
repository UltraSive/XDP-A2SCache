#include "../headers/bpf_helpers.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define MAX_A2S_SIZE 1024

struct a2s_info_val
{
  __u16 size;
  __u64 expires;
  unsigned char data[MAX_A2S_SIZE];
  unsigned char challenge[4];
  unsigned int challenge_set : 1;
};

struct server_key
{
  __be32 dst_ip;
  __be16 dst_port;
  __be16 padding;
};

BPF_MAP_DEF(query_cache_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct server_key),
    .value_size = sizeof(struct a2s_info_val),
    .max_entries = 16,
};
BPF_MAP_ADD(query_cache_map);

/**
 * Swaps ethernet header's source and destination MAC addresses.
 *
 * @param eth Pointer to Ethernet header.
 *
 * @return Void
 **/
static __always_inline void swap_eth(struct ethhdr *eth)
{
  __u8 tmp[ETH_ALEN];
  memcpy(tmp, &eth->h_source, ETH_ALEN);

  memcpy(&eth->h_source, &eth->h_dest, ETH_ALEN);
  memcpy(&eth->h_dest, tmp, ETH_ALEN);
}

/**
 * Swaps IPv4 header's source and destination IP addresses.
 *
 * @param iph Pointer to IPv4 header.
 *
 * @return Void
 **/
static __always_inline void swap_ip(struct iphdr *iph)
{
  __be32 tmp;
  memcpy(&tmp, &iph->saddr, sizeof(__be32));

  memcpy(&iph->saddr, &iph->daddr, sizeof(__be32));
  memcpy(&iph->daddr, &tmp, sizeof(__be32));
}

/**
 * Swaps UDP header's source and destination ports.
 *
 * @param udph Pointer to UDP header.
 *
 * @return Void
 **/
static __always_inline void swap_udp(struct udphdr *udph)
{
  __be16 tmp;
  memcpy(&tmp, &udph->source, sizeof(__be16));

  memcpy(&udph->source, &udph->dest, sizeof(__be16));
  memcpy(&udph->dest, &tmp, sizeof(__be16));
}

SEC("xdp")
int a2s_response(struct xdp_md *ctx)
{
  const char fmt_str[] = "Hello, world, from BPF!";
  bpf_printk(fmt_str);

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Only need IPv4 support
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end)
  {
    // Malformed Ethernet header
    return XDP_ABORTED;
  }

  if (ether->h_proto != 0x08U)
  { // htons(ETH_P_IP) -> 0x08U
    // Non IPv4 traffic
    // update_packet_stats(key_packets_passed);
    return XDP_PASS;
  }

  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end)
  {
    // Malformed IPv4 header
    return XDP_ABORTED;
  }

  data += sizeof(*ip);
  if (ip->protocol == IPPROTO_UDP)
  {
    if (data + sizeof(struct udphdr) > data_end)
    {
      // Malformed UDP header
      return XDP_ABORTED;
    }
    struct udphdr *udp = data;

    struct server_key key = {
        .dst_ip = ip->daddr,
        .dst_port = udp->dest,
    };

    struct a2s_info_val *a2s_info = bpf_map_lookup_elem(&query_cache_map, &key);
    if (a2s_info)
    {
      // Define A2S_INFO packet format
      __u8 a2s_info_packet[] = {
          0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F, 0x75,
          0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x69,
          0x6E, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79,
          0x00};

      // Check for A2S_INFO packet
      __u8 *udp_payload = (__u8 *)(udp + 1);
      size_t udp_payload_len = udp->len - sizeof(struct udphdr);

      //if (udp_payload_len >= sizeof(a2s_info_packet) &&
      //     bpf_memcmp(udp_payload, a2s_info_packet, sizeof(a2s_info_packet)) == 0
      //)
      //{
        __u16 len = (ctx->data_end - ctx->data);

        // Swap Mac, IP, and Port to be able to be transfered out the same NIC.
        swap_eth(ether);
        swap_ip(ip);
        swap_udp(udp);

        // Recalculate UDP length and checksum.

        udp->len = htons(sizeof(struct udphdr) + a2s_info->size + 5);
        udp->check = 0;
        udp->check = calc_udp_csum(ip, udp, data_end);

        // Recalculate IP header length and set TTL to 64.

        __u16 old_len = ip->tot_len;
        ip->tot_len = htons(len - sizeof(struct ethhdr));
        __u8 old_ttl = ip->ttl;
        ip->ttl = 64;
        ip->check = csum_diff4(old_len, ip->tot_len, ip->check);
        ip->check = csum_diff4(old_ttl, ip->ttl, ip->check);

        // Transmit the modified packet
        return XDP_TX;
      //}
    }
  }

  return XDP_PASS;
}
