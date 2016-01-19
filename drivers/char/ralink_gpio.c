/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright, Ralink Technology, Inc.
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  THIS  SOFTWARE  IS PROVIDED   ``AS  IS'' AND   ANY  EXPRESS OR IMPLIED
 *  WARRANTIES,   INCLUDING, BUT NOT  LIMITED  TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 *  NO  EVENT  SHALL   THE AUTHOR  BE    LIABLE FOR ANY   DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED   TO, PROCUREMENT OF  SUBSTITUTE GOODS  OR SERVICES; LOSS OF
 *  USE, DATA,  OR PROFITS; OR  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the  GNU General Public License along
 *  with this program; if not, write  to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 ***************************************************************************
 *
 */
#include <linux/init.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21)
#include <linux/autoconf.h>
#else
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include "ralink_gpio.h"

#include <asm/rt2880/surfboardint.h>

#ifdef  CONFIG_DEVFS_FS
#include <linux/devfs_fs_kernel.h>
#endif

#ifdef __BIG_ENDIAN
#undef cpu_to_le32
#undef le32_to_cpu
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#endif

#ifdef DEBUG
#define DBGPRINT(Level, Fmt...)	do {                 \
                                     if (Level <= 3) \
                                     {               \
                                        printk(Fmt); \
                                     }               \
                                } while(0)
#else
#define DBGPRINT(Level, Fmt...)
#endif

#define NAME			    "ralink_gpio"
#define RALINK_GPIO_DEVNAME	"gpio"
int ralink_gpio_major = 252;
int ralink_gpio_irqnum = 0;
u32 ralink_gpio_intp = 0;
u32 ralink_gpio_edge = 0;
int gpio_dbg_level = GPIO_TRACE_NONE;
ralink_gpio_reg_info ralink_gpio_info[RALINK_GPIO_NUMBER];
extern unsigned long volatile jiffies;

MODULE_DESCRIPTION("Ralink SoC GPIO Driver");
MODULE_AUTHOR("Winfred Lu <winfred_lu@ralinktech.com.tw>");
MODULE_LICENSE("GPL");
ralink_gpio_reg_info info;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
long ralink_gpio_ioctl(struct file *file, unsigned int req,
		unsigned long arg)
#else
int ralink_gpio_ioctl(struct inode *inode, struct file *file, unsigned int req,
		unsigned long arg)
#endif
{
	unsigned long tmp;
	ralink_gpio_reg_info info;

	req &= RALINK_GPIO_DATA_MASK;

	switch(req) {
	case RALINK_GPIO_SET_DIR:
		*(volatile u32 *)(RALINK_REG_PIODIR) = cpu_to_le32(arg);
		break;
	case RALINK_GPIO_SET_DIR_IN:
		if(arg > 15)
			return -EINVAL;
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
		DBGPRINT(GPIO_TRACE_IO, "read DIR: %lu, val: %x\n", tmp, ~(0x3<<(arg*2)));
		tmp &= ~(0x3<<(arg*2));
		DBGPRINT(GPIO_TRACE_IO, "write DIR: %lu\n", tmp);
		*(volatile u32 *)(RALINK_REG_PIODIR) = cpu_to_le32(tmp);
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOOE));
		DBGPRINT(GPIO_TRACE_IO, "read GPO: %lu, val: %x\n", tmp, ~(0x1<<arg));
		tmp &= ~(0x1<<arg);
		DBGPRINT(GPIO_TRACE_IO, "write GPO: %lu\n", tmp);
		*(volatile u32 *)(RALINK_REG_GPIOOE) = cpu_to_le32(tmp);
		break;
	case RALINK_GPIO_SET_DIR_OUT:
		if(arg > 15)
			return -EINVAL;
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODIR));
		DBGPRINT(GPIO_TRACE_IO, "read DIR: %lu, val: %x\n", tmp, 0x1<<(arg*2));
		tmp |= 0x1<<(arg*2);
		DBGPRINT(GPIO_TRACE_IO, "write DIR: %lu\n", tmp);
		*(volatile u32 *)(RALINK_REG_PIODIR) = cpu_to_le32(tmp);
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOOE));
		DBGPRINT(GPIO_TRACE_IO, "read GPO: %lu, val: %x\n", tmp, 0x1<<arg);
		tmp |= 0x1<<arg;
		DBGPRINT(GPIO_TRACE_IO, "write GPO: %lu\n", tmp);
		*(volatile u32 *)(RALINK_REG_GPIOOE) = cpu_to_le32(tmp);
		break;
	case RALINK_GPIO_READ: //RALINK_GPIO_READ_INT
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODATA));
		put_user(tmp, (int __user *)arg);
		break;
	case RALINK_GPIO_WRITE: //RALINK_GPIO_WRITE_INT
		*(volatile u32 *)(RALINK_REG_PIODATA) = cpu_to_le32(arg);
		break;
	case RALINK_GPIO_ENABLE_INTP:
		*(volatile u32 *)(RALINK_REG_INTENA) |= cpu_to_le32(RALINK_INTCTL_PIO);
		break;
	case RALINK_GPIO_DISABLE_INTP:
		*(volatile u32 *)(RALINK_REG_INTDIS) &= ~cpu_to_le32(RALINK_INTCTL_PIO);
		break;
	case RALINK_GPIO_REG_IRQ:
		copy_from_user(&info, (ralink_gpio_reg_info *)arg, sizeof(info));
		if (0 <= info.irq && info.irq < RALINK_GPIO_NUMBER/2) {
			tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIOEDGE));
			DBGPRINT(GPIO_TRACE_INT, "read PIOEDGE: %lu, val: %x, irq=: %x\n", tmp, 0x3<<(info.irq*2), info.irq);
			tmp |=  0x3<<(info.irq*2);
			DBGPRINT(GPIO_TRACE_INT, "write PIOEDGE: %lu\n", tmp);
			*(volatile u32 *)(RALINK_REG_PIOEDGE) = cpu_to_le32(tmp);
			ralink_gpio_info[info.irq].pid = info.pid;
		}
		else
			printk(KERN_ERR NAME ": irq number(%d) out of range\n",
					info.irq);
		break;
	case RALINK_GPIO3116_SET_DIR:
		*(volatile u32 *)(RALINK_REG_PIO3116DIR) = cpu_to_le32(arg);
		break;
	case RALINK_GPIO3116_SET_DIR_IN:
		if((arg < 16) || (arg > 31))
			return -EINVAL;
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3116DIR));
		DBGPRINT(GPIO_TRACE_IO, "read DIR3116: %lu, val: %x\n", tmp, ~(0x3<<((arg-16)*2)));
		tmp &= ~(0x3<<((arg-16)*2));
		DBGPRINT(GPIO_TRACE_IO, "write DIR3116: %lu\n", tmp);
		*(volatile u32 *)(RALINK_REG_PIO3116DIR) = cpu_to_le32(tmp);
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOOE));
		DBGPRINT(GPIO_TRACE_IO, "read GPO: %lu, val: %x\n", tmp, ~(0x1<<arg));
		tmp &= ~(0x1<<arg);
		DBGPRINT(GPIO_TRACE_IO, "write GPO: %lu\n", tmp);
		*(volatile u32 *)(RALINK_REG_GPIOOE) = cpu_to_le32(tmp);
		break;
	case RALINK_GPIO3116_SET_DIR_OUT:
		if((arg < 16) || (arg > 31))
			return -EINVAL;
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIO3116DIR));
		DBGPRINT(GPIO_TRACE_IO, "read DIR3116: %lu, val: %x\n", tmp, 0x1<<((arg-16)*2));
		tmp |= 0x1<<((arg-16)*2);
		DBGPRINT(GPIO_TRACE_IO, "write DIR3116: %lu\n", tmp);
		*(volatile u32 *)(RALINK_REG_PIO3116DIR) = cpu_to_le32(tmp);
		tmp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOOE));
		DBGPRINT(GPIO_TRACE_IO, "read GPO: %lu, val: %x\n", tmp, 0x1<<arg);
		tmp |= 0x1<<arg;
		DBGPRINT(GPIO_TRACE_IO, "write GPO: %lu\n", tmp);
		*(volatile u32 *)(RALINK_REG_GPIOOE) = cpu_to_le32(tmp);
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return 0;
}

int ralink_gpio_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_INC_USE_COUNT;
#else
	try_module_get(THIS_MODULE);
#endif
	return 0;
}

int ralink_gpio_release(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_DEC_USE_COUNT;
#else
	module_put(THIS_MODULE);
#endif
	return 0;
}

struct file_operations ralink_gpio_fops =
{
	owner:		THIS_MODULE,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	unlocked_ioctl:	ralink_gpio_ioctl,
#else
	ioctl:		ralink_gpio_ioctl,
#endif
	open:		ralink_gpio_open,
	release:	ralink_gpio_release,
};

/*
 * send a signal(SIGUSR1) to the registered user process whenever any gpio
 * interrupt comes
 * (called by interrupt handler)
 */
void ralink_gpio_notify_user(int usr)
{
	struct task_struct *p = NULL;

	if (ralink_gpio_irqnum < 0 || RALINK_GPIO_NUMBER <= ralink_gpio_irqnum) {
		printk(KERN_ERR NAME ": gpio irq number out of range\n");
		return;
	}

	//don't send any signal if pid is 0 or 1
	if ((int)ralink_gpio_info[ralink_gpio_irqnum].pid < 2)
		return;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	p = find_task_by_vpid(ralink_gpio_info[ralink_gpio_irqnum].pid);
#else
	p = find_task_by_pid(ralink_gpio_info[ralink_gpio_irqnum].pid);
#endif

	if (NULL == p) {
		printk(KERN_ERR NAME ": no registered process to notify\n");
		return;
	}

	if (usr == 1) {
		printk(KERN_NOTICE NAME ": sending a SIGUSR1 to process %d\n",
				ralink_gpio_info[ralink_gpio_irqnum].pid);
		send_sig(SIGUSR1, p, 0);
	}
	else if (usr == 2) {
		printk(KERN_NOTICE NAME ": sending a SIGUSR2 to process %d\n",
				ralink_gpio_info[ralink_gpio_irqnum].pid);
		send_sig(SIGUSR2, p, 0);
	}
}

/*
 * 1. save the PIOINT and PIOEDGE value
 * 2. clear PIOINT by writing 1
 * (called by interrupt handler)
 */
void ralink_gpio_save_clear_intp(void)
{
	ralink_gpio_intp = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIOINT));
	*(volatile u32 *)(RALINK_REG_PIOINT) = cpu_to_le32(0xffff);
	DBGPRINT(GPIO_TRACE_INT, "INTstate:%x\n", ralink_gpio_intp);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
void ralink_gpio_irq_handler(unsigned int irq, struct irqaction *irqaction)
#else
irqreturn_t ralink_gpio_irq_handler(int irq, void *irqaction)
#endif
{
	struct gpio_time_record {
		unsigned long timer;
		unsigned long trigger;
	};
	static struct gpio_time_record record[RALINK_GPIO_NUMBER/2];
	unsigned long now, data;
	int i;

	ralink_gpio_save_clear_intp();
	now = jiffies;

	data = le32_to_cpu(*(volatile u32 *)(RALINK_REG_PIODATA));

	for (i = 0; i < RALINK_GPIO_NUMBER/2; i++) {
		if (! (ralink_gpio_intp & (1 << i)))
			continue;
		ralink_gpio_irqnum = i;
		if (data & ralink_gpio_intp) {	// rising edge
			record[i].timer = now;
			record[i].trigger = 1;
			DBGPRINT(GPIO_TRACE_INT, "record jiffies: %lu\n", record[i].timer);
		} else {			// falling edge
			if (record[i].trigger == 0)
				continue;
			if (time_before_eq(now, record[i].timer + 20L)) {
				DBGPRINT(GPIO_TRACE_INT, "too short (%lu)\n", now);
			} else if (time_before(now, record[i].timer + 200L)) {
				DBGPRINT(GPIO_TRACE_INT, "i=%d, one click (%lu)\n", i, now);
				ralink_gpio_notify_user(1);
			} else {
				DBGPRINT(GPIO_TRACE_INT, "i=%d, push several seconds (%lu)\n", i, now);
				ralink_gpio_notify_user(2);
			}
			record[i].trigger = 0;
		}
		
		break;
	}

	return IRQ_HANDLED;
}

int __init ralink_gpio_init(void)
{
	unsigned int i;
	u32 gpiomode;
	int err, r = 0;

	r = register_chrdev(ralink_gpio_major, RALINK_GPIO_DEVNAME,
			&ralink_gpio_fops);
	if (r < 0) {
		printk(KERN_ERR NAME ": unable to register character device\n");
		return r;
	}
	if (ralink_gpio_major == 0) {
		ralink_gpio_major = r;
		printk(KERN_DEBUG NAME ": got dynamic major %d\n", r);
	}

#ifdef CONFIG_DEVFS_FS
	devfs_mk_cdev(MKDEV(ralink_gpio_major, 0), S_IFCHR|S_IRUGO|S_IWUGO, RALINK_GPIO_DEVNAME);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21)
	err = request_irq(SURFBOARDINT_GPIO, ralink_gpio_irq_handler, \
	    IRQF_DISABLED, NAME, NULL);
#else
	err = request_irq(SURFBOARDINT_GPIO, ralink_gpio_irq_handler, \
	    SA_INTERRUPT, NAME, NULL);
#endif
	if(err)
		return err;

	//config these pins to gpio mode (share pin)
	gpiomode = le32_to_cpu(*(volatile u32 *)(RALINK_REG_GPIOMODE));
	gpiomode &= ~RALINK_GPIOMODE_DFT;
	*(volatile u32 *)(RALINK_REG_GPIOMODE) = cpu_to_le32(gpiomode);

	//enable gpio interrupt
	*(volatile u32 *)(RALINK_REG_INTENA) |= cpu_to_le32(RALINK_INTCTL_PIO);
	for (i = 0; i < RALINK_GPIO_NUMBER/2; i++) {
		ralink_gpio_info[i].irq = i;
		ralink_gpio_info[i].pid = 0;
	}

	printk("Ralink gpio driver initialized\n");
	return 0;
}

void __exit ralink_gpio_exit(void)
{
#ifdef CONFIG_DEVFS_FS
	devfs_remove(RALINK_GPIO_DEVNAME);
#endif
	unregister_chrdev(ralink_gpio_major, RALINK_GPIO_DEVNAME);

	//config these pins to normal mode
	*(volatile u32 *)(RALINK_REG_GPIOMODE) &= ~RALINK_GPIOMODE_DFT;
	//disable gpio interrupt
	*(volatile u32 *)(RALINK_REG_INTDIS) &= ~cpu_to_le32(RALINK_INTCTL_PIO);
	printk("Ralink gpio driver exited\n");
}

module_init(ralink_gpio_init);
module_exit(ralink_gpio_exit);
