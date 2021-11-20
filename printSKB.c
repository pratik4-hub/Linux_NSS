#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>

static struct nf_hook_ops nfho; // net filter hook option struct
struct sk_buff *sock_buff;      // socket buffer used in linux kernel
struct udphdr *tcp_header;      // tcp header struct
struct iphdr *ip_header;        // ip header struct
struct ethhdr *mac_header;      // mac header struct

MODULE_DESCRIPTION("Detect TCP Packet and print skbuffer");
MODULE_AUTHOR("Pratik Autade <>");
MODULE_LICENSE("GPL");

void print_skbuff_packet(struct sk_buff *skb)
{
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch;

    printk("Packet hex dump:\n");
    data = (uint8_t *)skb_mac_header(skb);

    if (skb_is_nonlinear(skb))
    {
        len = skb->data_len;
    }
    else
    {
        len = skb->len;
    }

    remaining = len;
    for (i = 0; i < len; i += rowsize)
    {
        printk("%06d\t", li);

        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++)
        {
            ch = data[l];
            printk(KERN_CONT "%02X ", (uint32_t)ch);
        }

        data += linelen;
        li += 10;

        printk(KERN_CONT "\n");
    }
}

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    sock_buff = skb;
    ip_header = (struct iphdr *)skb_network_header(sock_buff); //grab network header using accessor
    mac_header = (struct ethhdr *)skb_mac_header(sock_buff);

    if (!sock_buff)
    {
        return NF_DROP;
    }

    if (ip_header->protocol == IPPROTO_ICMP)
    {                                                                 //tcp=6
        printk(KERN_INFO "Got ICMP Reply packet and dropped it. \n"); //log we’ve got udp packet to /var/log/messages
        printk(KERN_INFO "src_ip: %pI4 \n", &ip_header->saddr);
        printk(KERN_INFO "dst_ip: %pI4\n", &ip_header->daddr);
        print_skbuff_packet(sock_buff);
    }
    return NF_ACCEPT;
}

int init_module(void)
{
    nfho.hook = hook_func;
    //nfho.hooknum = NF_IP_POST_ROUTING;                            //TCP reply packet capture.
    nfho.hooknum = NF_INET_POST_ROUTING; //TCP reply packet capture.
    nfho.pf = PF_INET;                   //IPV4 packets
    nfho.priority = NF_IP_PRI_FIRST;     //set to highest priority over all other hook functions
    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "---------------------------------------\n");
    printk(KERN_INFO "Loading printSKB...\n");
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Cleaning printSKB module.\n");
    nf_unregister_net_hook(&init_net, &nfho);
}
