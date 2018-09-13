/*
* my linux kernel version is 4.4.0 v127
* target android hammerdata kernel version 3.3.0
* android packet dump module
*/

/*
* this module dump all packet
* dump data export proc file (/drivers/pdump_prot)
* Latest update 2018, 7, 11
*/

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/string.h> /* Needed for strcat, memcpy */
#include <linux/vmalloc.h> /* Needed for vmalloc func */
#include <linux/skbuff.h> /* Needed for skbuff struct */
#include <linux/netfilter.h> /* Needed for hook　function */
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h> /* Needed for ip header */
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/byteorder/generic.h>
#include <linux/vfs.h>
#include <linux/namei.h>  /* Needed for path_lookup */
#include <linux/fs.h> /* Needed for  */
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/path.h> /* Needed for  */
#include <linux/mount.h> /* Needed for kern_path */
#include <asm-generic/rtc.h>/* Needed for using get_rtc_time function */
//#include <linux/time.h> /*Needed for func do_getimeofday function */
#include <linux/sched.h> /*Needed for schedule_timeout function */
//Needed for proc
#include <linux/types.h>
//#include <linux/fs.h>
#include <linux/proc_fs.h>/* Needed for copy_from_user */
#include <linux/stat.h>
//#include <linux/string.h>
//#include <asm/uaccess.h>
#include <linux/spinlock.h> /*Needed for spinlock*/

MODULE_AUTHOR("yfujieda");
MODULE_DESCRIPTION("packet dump");
MODULE_LICENSE("GPL");


#define PROC_NAME "driver/dump_file.txt"
#define MAX_FILE_LENGTH PAGE_SIZE
#define BUFFER_SIZE 16392
#define PACEKT_NUM 100
#define packet_next(i) i+1

/*
* include/linux/spinlock_types.h lines-97
* #define DEFINE_SPINLOCK spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
*/
DEFINE_SPINLOCK(log_lock);
unsigned long flags;

/* proc file entry */

// /fs/proc/internal.h lines-31

/*
*  is all packet amount
* log_end is array of packet end
* buffer_row packet_buf[buffer_row]
* main_flag initialization only ...
* packet_num all reserved
*/
struct proc_dir_entry *proc_entry;
unsigned int packet_n;
int buffer_row;
int i, j, n, m;
bool main_flag = false; //初期化用
unsigned int packet_num;

typedef struct packet_header{
  unsigned int packet_num;
  unsigned int packet_len;
} packet_t;


typedef struct packet_buf{
  char *buf;
  unsigned int log_end;
} packet_buf_t;

packet_buf_t *buffer;
const char proc_buf[BUFFER_SIZE];
//main module

struct skbbf *skb_bf;
static struct nf_hook_ops nfhook;
//register callback func to hook point

//Needed for timestamp

//char *time_tmp;
static char *months[12] ={"Jan", "Feb", "Mar", "Apr", "May", "Jun",
"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

///fs/proc/internal.h



static int proc_open(struct inode *node, struct file *fp){
  printk("open\n");
  return 0;
}

/*
* this function is proc filesystem read handler
*  we want to try copying packet to __user buffer
*/

//パケットをバッファに飛ばしたい
static ssize_t proc_read(struct file *fp, char __user *buf, size_t size, loff_t *off)
{

  char *p_temp=kmalloc(size, GFP_KERNEL);
  static int i,x;
  static int temp;
  int state = 0;

  x = buffer_row;
  printk("read call count=%d\n",(int)size);

  spin_lock_irqsave(&log_lock, flags);
  for(i=0; i < (buffer+x)->log_end; i++)
  {
    p_temp[i] = (buffer+x)->buf[i];
  }
  temp = (buffer+x)->log_end;
  spin_unlock_irqrestore(&log_lock, flags);


  spin_lock_irqsave(&log_lock, flags);
  if (copy_to_user(buf, p_temp, temp)){
    kfree(p_temp);
    goto out;
  }else{
    kfree(p_temp);
  }
  spin_unlock_irqrestore(&log_lock, flags);

  //stateが０の時つまりif state==0 と同値
  if(!state){
    //iは文字数を示す
    state = (buffer+x)->log_end;
  }
  out:
  return state;
}



static long proc_write(struct file *fp, const char *buf, size_t size, loff_t *off)
{
  printk("write\n");
  return size;
}


/*
* ここでハンドラを登録する
*/
static struct file_operations example_proc_fops = {
  .owner = THIS_MODULE,
  .open = proc_open,
  .read = proc_read,
  .write = proc_write,
};



int proc_create_entry(void) {

  int ret = 0;

  proc_entry = proc_create(PROC_NAME, S_IRUGO | S_IWUGO | S_IXUGO, NULL, &example_proc_fops);

  if (proc_entry == NULL) {

    ret = -ENOMEM;
    printk(KERN_INFO "[DEBUG]:mymodule_proc: Couldn't create proc entry\n");

  }
  return ret;

}

int proc_close(void){

  printk("proc_entry is succeed");
  remove_proc_entry(PROC_NAME, NULL);

  return 0;
}


//get timestamp
static void timestamp(void)
{
  struct rtc_time t;
  get_rtc_time(&t);

  //      strcat(time_tmp, months[t.tm_mon]);
  //      write_buf(time_tmp);
  printk("%s %d %d:%d:%d %d",
  months[t.tm_mon], t.tm_mday, (t.tm_hour + 9), t.tm_min,
  t.tm_sec, 2000 + (t.tm_year % 100));
}

//main modules

static unsigned int payload_dump(unsigned int hooknum,
  struct sk_buff *skb,
  const struct net_device *in,
  const struct net_device *out,
  int (*okfn)(struct sk_buff*))
  {

    packet_t packet_head;
    static char *buffer_p;

    //初期化系関数ここで初期化
    if (main_flag == false){
      //packet_bufの先頭アドレスヲぶち込む
      buffer_row = 0;
      buffer_p = buffer->buf;
      main_flag = true;
    }

    //ここではヘッダヲ作ってる
    packet_head.packet_num = packet_num;
    packet_head.packet_len = skb->tail;

    //ここでバッファno書き込み開始ポインタを更新
    if(BUFFER_SIZE - (buffer+buffer_row)->log_end < skb->tail)
    {
      if(!buffer_row){
        buffer_p = (buffer+buffer_row)->buf;
        (buffer+buffer_row)->log_end = 0;
        buffer_row = 0;
        printk("alternative1->0");
      }else if(buffer_row){
        buffer_p = (buffer+buffer_row)->buf;
        (buffer+buffer_row)->log_end = 0;
        buffer_row = 1;
        printk("alternative0->1");
      }else{
        printk(KERN_INFO"bufeer alternative is negative!!");
        return -2;
      }
    }

    //ここで実際にバッファに挿入
    memcpy(buffer_p, &packet_head, sizeof(packet_head));
    buffer_p = buffer_p + sizeof(packet_head);
    (buffer+buffer_row)->log_end = (buffer+buffer_row)->log_end + sizeof(packet_head);
    memcpy(buffer_p , skb->data, skb->tail);
    buffer_p = buffer_p + skb->tail;
    (buffer+buffer_row)->log_end = (buffer+buffer_row)->log_end + skb->tail;

    printk("skb->tail:%d\n", skb->tail);

    packet_num++;

    return NF_ACCEPT;
  }



  static int __init init_main(void)
  {
    /*
    * err is srr status if err is 1 , status negative
    */
    int err;
    packet_n = 2;
    /*
    * this part is　reserved packet_buf(in callback func)
    *
    */
    packet_buf_t p_buffer[2];
    /*buffer init*/
    buffer = p_buffer;
    for(i=0; i<packet_n; i++){
      (buffer+i)->buf = kmalloc(sizeof(char *)*BUFFER_SIZE, GFP_KERNEL);
      (buffer+i)->log_end = 0;
    }

    nfhook.hook     = payload_dump;
    nfhook.hooknum  = 0;
    nfhook.pf       = PF_INET;
    nfhook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfhook);
    timestamp();

    err = proc_create_entry();

    if(err == 0){
      printk("create proc entry is succeed\n");
    }
    return -err;
  }

  static void __exit cleanup_main(void)
  {
    nf_unregister_hook(&nfhook);
    printk("refused packetdump_mod");
    printk(KERN_INFO "%s\n", __FUNCTION__);
    proc_close();
    kfree((buffer)->buf);
    kfree((buffer+1)->buf);

  }

  module_init(init_main);
  module_exit(cleanup_main);
