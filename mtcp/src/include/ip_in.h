#ifndef IP_IN_H
#define IP_IN_H

#include "mtcp.h"
#include <linux/types.h>

int
ProcessIPv4Packet(mtcp_manager_t mtcp, uint32_t cur_ts, 
				  const int ifidx, unsigned char* pkt_data, int len);

#define __force
typedef unsigned int u32;

static inline __sum16 csum_fold(__wsum csum)
{
        u32 sum = (__force u32)csum;;

        sum += (sum << 16);
        csum = (sum < csum);
        sum >>= 16;
        sum += csum;

        return (__force __sum16)~sum;
}

static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
        const unsigned int *word = iph;
        const unsigned int *stop = word + ihl;
        unsigned int csum;
        int carry;

        csum = word[0];
        csum += word[1];
        carry = (csum < word[1]);
        csum += carry;

        csum += word[2];
        carry = (csum < word[2]);
        csum += carry;

        csum += word[3];
        carry = (csum < word[3]);
        csum += carry;

        word += 4;
        do {
                csum += *word;
                carry = (csum < *word);
                csum += carry;
                word++;
        } while (word != stop);

        return csum_fold(csum);
}
#endif /* IP_IN_H */
