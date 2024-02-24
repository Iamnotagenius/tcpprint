#include <linux/completion.h>
#include <linux/ip.h>
#include <linux/kern_levels.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/workqueue.h>

static unsigned int put_next_packet(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state);
static ssize_t read_next_packet(struct file *file, char *__user user_buffer,
                                size_t len, loff_t *offset);
static void format_packet(char *buffer, size_t size, struct sk_buff *skb);

static struct sk_buff current_packet;
static DECLARE_COMPLETION(next_packet_read);
static struct proc_ops fops = {
    .proc_read = read_next_packet,
};
static struct nf_hook_ops lab_hook = {
    .hook = put_next_packet,
    .hooknum = NF_INET_LOCAL_OUT,
    .pf = PF_INET,
    .priority = NF_IP_PRI_LAST,
};
static struct proc_dir_entry *tcpprint_proc_file;

#define procfs_name "next_packet"

static unsigned int put_next_packet(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
  current_packet = *skb;
  printk(KERN_DEBUG "%s: written packet with len %d\n", THIS_MODULE->name,
         current_packet.len);
  complete_all(&next_packet_read);
  return NF_ACCEPT;
}

static ssize_t read_next_packet(struct file *file, char *__user user_buffer,
                                size_t len, loff_t *offset) {
  char buffer[256];
  ssize_t remaining;
  int err;
  printk(KERN_DEBUG "%s: waiting for packet...\n", THIS_MODULE->name);
  if (wait_for_completion_interruptible(&next_packet_read)) {
    return -EINTR;
  };
  printk(KERN_DEBUG "%s: packet arrived\n", THIS_MODULE->name);
  if (current_packet.protocol != htons(ETH_P_IP)) {
    reinit_completion(&next_packet_read);
    return 0;
  }
  format_packet(buffer, sizeof(buffer), &current_packet);
  buffer[strlen(buffer)] = '\0';
  buffer[sizeof(buffer) - 1] = '\0';
  remaining = strlen(buffer) - *offset;
  printk(KERN_DEBUG "%s: %zd remaining bytes\n", THIS_MODULE->name, remaining);
  if (remaining <= 0) {
    reinit_completion(&next_packet_read);
    printk(KERN_DEBUG "%s: reinited completion\n", THIS_MODULE->name);
    return 0;
  } else if (remaining > len) {
    remaining = len;
  } else if (remaining < 0) {
    return -EINVAL;
  }
  printk(KERN_DEBUG "%s: copying to user: '%s' with len %zd\n",
         THIS_MODULE->name, buffer + *offset, remaining);
  err = copy_to_user(user_buffer, buffer + *offset, remaining);
  if (err == 0) {
    *offset += remaining;
    return remaining;
  } else {
    printk(KERN_ERR "%s: proc read failed\n", THIS_MODULE->name);
    reinit_completion(&next_packet_read);
    return -EFAULT;
  }
  return 0;
}

static void format_packet(char *buffer, size_t size, struct sk_buff *skb) {
  struct iphdr *iph = ip_hdr(skb);
  struct timespec64 tstamp = ktime_to_timespec64(skb->tstamp);
  unsigned int sport = 0;
  unsigned int dport = 0;
  const char *protocol = "UNKNOWN";

  if (iph->protocol == 17) {
    struct udphdr *udph = udp_hdr(skb);
    sport = (unsigned int)ntohs(udph->source);
    protocol = "UDP";
  } else if (iph->protocol == 6) {
    struct tcphdr *tcph = tcp_hdr(skb);
    sport = (unsigned int)ntohs(tcph->source);
    dport = (unsigned int)ntohs(tcph->dest);
    protocol = "TCP";
  }
  snprintf(buffer, size, "[%lld.%ld] SRC %pI4:%d DST %pI4:%d LEN %d %s\n",
           tstamp.tv_sec, tstamp.tv_nsec, &iph->saddr, sport, &iph->daddr,
           dport, current_packet.len, protocol);
}

static int __init tcpprint_init(void) {
  tcpprint_proc_file = proc_create(procfs_name, S_IRUGO, NULL, &fops);
  if (!tcpprint_proc_file) {
    printk(KERN_ERR "%s: failed to create /proc/%s\n", THIS_MODULE->name,
           procfs_name);
    return -EEXIST;
  }
  printk(KERN_DEBUG "%s: module initialized\n", THIS_MODULE->name);
  return nf_register_net_hook(&init_net, &lab_hook);
}

static void __exit tcpprint_exit(void) {
  printk(KERN_DEBUG "%s: removing module...\n", THIS_MODULE->name);

  proc_remove(tcpprint_proc_file);
  nf_unregister_net_hook(&init_net, &lab_hook);
}

module_init(tcpprint_init);
module_exit(tcpprint_exit);

MODULE_AUTHOR("Iamnotagenius");
MODULE_DESCRIPTION("Gives info about packets in /proc");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
