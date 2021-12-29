#include <linux/module.h>  
#include <linux/kernel.h>  
#include <linux/init.h>  
// #include <linux/netfilter.h>
// #include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>  
// #include <linux/skbuff.h>
// #include <linux/inet.h> 
#include <linux/ip.h>  
#include <linux/tcp.h>
#include <linux/udp.h> 
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/timer.h>

#define SNO "boot.serialno="
#define BUFSIZE  1024

struct timer_list ntimer;
struct proc_dir_entry * dev_debug_proc = NULL;
static unsigned int used = 0;
static unsigned int deny = 1;
static unsigned int enable = 0;

static unsigned int NET_HookLocalIn(
	void *priv, 
	struct sk_buff *skb, 
	const struct nf_hook_state *state)
{
	int retval = NF_ACCEPT;
	if(skb){	
		struct iphdr *iph;
		iph = ip_hdr(skb); 

		//if(iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP || iph->protocol == IPPROTO_ICMP)  
		if(iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_ICMP)  
		{
			if(1 == deny) 
				retval = NF_DROP;
		}
	}
	return retval;  
}

static struct nf_hook_ops net_hooks_ops = 
{
	.hook		= NET_HookLocalIn,
	.pf		= PF_INET,
	.hooknum	= NF_INET_LOCAL_IN,
	.priority	= NF_IP_PRI_FIRST,
};

void en_timer_tmp(unsigned long arg)
{
	if(1 != enable)
		deny = 1;
	del_timer(&ntimer);
}

// write '1' to enable network for 20 seconds
// sec: all 128 nums (char & int)
// time: 1601787, 截取后四位:t=1787, t[0]--sec[16] t[1]--sec[68], t[2]=sec[93], t[3]=sec[115] 
// sn: a2855628, 不满8位凑够8位
//               sn[1]--sec[18] or sec[21], 
// 		 sn[3]--sec[14] or sec[39], 
// 		 sn[5]--sec[45] or sec[49], 
// 		 sn[6]--sec[79], 
static ssize_t iiscsi_write(struct file *file,
                const char __user *buffer, size_t count, loff_t *pos)
{
    char sno[64];
    char *sno_ptr;
    struct timespec uptime;
    char data_string[BUFSIZE];
    char apktime_string[5];
    int cur_time = 0, apk_time = 0;
    if(*pos > 0 || count > BUFSIZE)
        return -EFAULT;
    if(copy_from_user(data_string, buffer, count))
        return -EINVAL;
    if(2 == count && data_string[0] == '1') {
	    if(0 == used) {
		used = 1;
	   	deny = 0;
		init_timer(&ntimer);
		ntimer.function = en_timer_tmp;
		ntimer.data = 1;
		ntimer.expires = jiffies + 15 * HZ;
		add_timer(&ntimer);
	    }
    } else if(129 == count) {
	get_monotonic_boottime(&uptime);
	// check uptime(s)
	cur_time = uptime.tv_sec % 10000;
	apktime_string[0] = data_string[16];
	apktime_string[1] = data_string[68];
	apktime_string[2] = data_string[93];
	apktime_string[3] = data_string[115];
	apktime_string[4] = '\0';
	kstrtoint(apktime_string, 10, &apk_time); 
	if(apk_time <= 0 || cur_time <= 0 || cur_time - apk_time > 15 || cur_time - apk_time < 0) 
		return count;

	// check serialno
	sno_ptr = strstr(saved_command_line, SNO);
	if(sno_ptr) {
		sscanf(sno_ptr, SNO"%8s", sno);
		// print serialno
	}

	if((sno[1] == data_string[18] || sno[1] == data_string[21])
	 	&& (sno[3] == data_string[14] || sno[3] == data_string[39]) 
	 	&& (sno[5] == data_string[45] || sno[5] == data_string[49]) 
	 	&& (sno[6] == data_string[79]) 
		) {
		enable = 1;
		deny = 0;
	}
    }
    return count;
}

//static ssize_t iiscsi_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
//{
//	char sbuf[64];
//	unsigned long now = jiffies;
//	int size = 0;
//	size = sprintf(sbuf, "num:%lu", jiffies_to_clock_t(now));
//	printk("size:%d", size);
//	copy_to_user(buf, sbuf, size);
//	return size;
//}
//        .read = iiscsi_read,

static int iiscsi_show(struct seq_file *m, void *v)
{
	// used:   1--temp enable network chance used
	// enable: 1--network is completely enabled
	seq_printf(m, "%d-%d\n", used, enable);

        return 0;
}

static int iiscsi_open(struct inode *inode, struct file *file)
{
        return single_open(file, iiscsi_show, NULL);
}

static const struct file_operations yaffs_fops = {
	.owner = THIS_MODULE,
	.open  = iiscsi_open,
	.read  = seq_read,
	.llseek = seq_lseek,
        .write = iiscsi_write,
	.release = single_release,
};

int __init create_dev_debug_proc(void)
{
    dev_debug_proc = proc_create("iscsi", S_IWUSR | S_IRUSR, NULL, &yaffs_fops);
    if(dev_debug_proc == NULL){
        return -EIO;
    }
    return 0;
}

static int __init net_hooks_init(void) 
{
	nf_register_net_hook(&init_net, &net_hooks_ops);
	create_dev_debug_proc();
	return 0; 
}

static void __exit net_hooks_exit(void)
{
	nf_unregister_net_hook(&init_net, &net_hooks_ops);
	proc_remove(dev_debug_proc);
} 

module_init(net_hooks_init); 
module_exit(net_hooks_exit); 

MODULE_LICENSE("Dual BSD/GPL");  
MODULE_AUTHOR("skyhood");  
MODULE_DESCRIPTION("Netfilter Demo");  
MODULE_VERSION("1.0");  
