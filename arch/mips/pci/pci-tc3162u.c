#include <linux/types.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/interrupt.h> 
#include <asm/tc3162/tc3162.h>
#include <linux/proc_fs.h>

//#define PCIE_DEBUG	1
#define PCIE_CONFIG_ADDR		0xbfb81cf8
#define PCIE_CONFIG_DATA		0xbfb81cfc
#define AHB_BUS_TIMEOUT_ERR		(1<<25)
#define AHB_BUS_ADDR_ERR		(1<<24)

#define NIC3090_PCIe_DEVICE_ID  0x3090		// 1T/1R miniCard
#define NIC3091_PCIe_DEVICE_ID  0x3091		// 1T/2R miniCard
#define NIC3092_PCIe_DEVICE_ID  0x3092		// 2T/2R miniCard
#define NIC3390_PCIe_DEVICE_ID  0x3390		// 1T/1R miniCard
#define NIC5390_PCIe_DEVICE_ID	0x5390
#define NIC539F_PCIe_DEVICE_ID  0x539F
#define NIC5392_PCIe_DEVICE_ID  0x5392

#define NIC_PCI_VENDOR_ID	0x1814
#define PCI_DEVICE_MEM1		0xbf700000
#define PCIE_TYPE_RC		0x0
#define PCIE_TYPE_DEV		0x1
#define PCIE_BUS_RC			0x0
#define PCIE_BUS_DEV		0x1
#define PCIE_DEVNUM_0		0x0
#define PCIE_DEVNUM_1		0x1
#define PHYSADDR(a)	((unsigned int)(a)&0x1fffffff)

static int ahb_status=0;
static int pcie_soft_patch=1;

static struct resource tc3162_pcie_io_resource = {
	.name   = "pcie IO space",
#ifdef CONFIG_MIPS_TC3162U
	.start  = 0x1FBD0000,
	.end    = 0x1FBEFFFF,
#endif
#ifdef CONFIG_MIPS_TC3182
	.start  = 0x1F600000,
	.end    = 0x1F61FFFF,
#endif
	.flags  = IORESOURCE_IO
};

static struct resource tc3162_pcie_mem_resource = {
	.name   = "pcie memory space",
	.start  = 0x1F700000,
	.end    = 0x1F8FFFFF,
	.flags  = IORESOURCE_MEM
};

extern struct pci_ops tc3162_pcie_ops;

struct pci_controller tc3162_pcie_controller = {
	.pci_ops   		= &tc3162_pcie_ops,
	.io_resource	= &tc3162_pcie_io_resource,
	.mem_resource	= &tc3162_pcie_mem_resource,
};

void pcieReset(void){
	VPint(CR_AHB_PCIC) &= ~(1<<29);
	mdelay(5);
	VPint(CR_AHB_PCIC) &= ~(1<<30);
	mdelay(5);
	VPint(CR_AHB_PCIC) |= (1<<29);
	mdelay(5);
	VPint(CR_AHB_PCIC) |= (1<<30);
	mdelay(5);
	/*force link up, workaround the pcie hardware problems.*/
	if(isTC3162U){
		VPint(PCIE_CONFIG_ADDR) = 0x40;
		VPint(PCIE_CONFIG_DATA) = 0x20;
	}
}

EXPORT_SYMBOL(pcieReset);

int pcie_write_config_word(unsigned char type, unsigned char bus, unsigned char devnum, unsigned char regnum, unsigned long int value)
{
	VPint(PCIE_CONFIG_ADDR)=(type<<31|bus<<20 |devnum<<15|regnum);
	VPint(PCIE_CONFIG_DATA)=value;
	return 0;
}
int pcie_write_config_byte(unsigned char type, unsigned char bus, unsigned char devnum, unsigned char regnum, unsigned char value)
{
	VPint(PCIE_CONFIG_ADDR)=(type<<31|bus<<20 |devnum<<15|regnum);
	VPint(PCIE_CONFIG_DATA)=value;
	return 0;
}
unsigned long int pcie_read_config_word(unsigned char type, unsigned char bus, unsigned char devnum, unsigned char regnum)
{
	VPint(PCIE_CONFIG_ADDR)=(type<<31|bus<<20|devnum<<15|regnum);
	return VPint(PCIE_CONFIG_DATA);
}

int pcieRegInitConfig(void)
{
	unsigned int reg1_val, reg2_val;
	unsigned int reg_val = 0;
	int i = 0;
	int slot;
	int pci_device_exist;


	/* PCIe init module */
	/* reset PCIe module */
	/*
	 * From: TC/Li Fengbo 
	 * To: 'krammer' ; 'Marshall Yen \
	 * Cc: 'Liu, Shuenn-Ren' ; 'Graham Fan\
	 * Sent: Friday, May 22, 2009 2:49 PM
	 * Subject: new pof for software reboot
	 *
	 * Dear both,
	 * I have generated a new pof for software reboot, the pof file name is 
	 * software_reboot_20090522.pof
	 * It has been transported to Hsingchu, please help to check it
	 * Software Reset User Guide:
	 * After power on, there are two steps to active PCIe System
	 * 1 Wait for minimum 50us, Write ¡§1¡¨ to bit 29 of Register bfb0_0088, then
	 * 2 Wait for minimum 3.5us, write ¡§1¡¨ to bit 30 of Register bfb0_0088
	 * 
	 * Before do software reboot, 
	 * 1 Write ¡§0¡¨ to bit 29 and bit 30 of Register bfb0_0088
	 * Then reset for PCIE system is completed, you can reboot system
	 * Don¡¦t forget to release PCIe reset
	 * 2 Wait for minimum 50us , Write ¡§1¡¨ to bit 29 of bfb0_0088, then
	 * 3 Wait for minimum 3.5us, write ¡§1¡¨ to bit 30 of bfb0_0088
	 *
	 * Best regards
	 * Fengbo Li
	 *
	 */
	/* pcie fixup start */
	/* setup COMMAND register */
	pcie_write_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0x04, 0x00100007);

	/* setup CACHE_LINE_SIZE register */
	pcie_write_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0x0c/*PCI_CACHE_LINE_SIZE*/, 0x00000008);//duoduo_20090701
	/* setup LATENCY_TIMER register */
	/* pcie fixup end */
	/*setup secondary bus number*/
	/*setup subordinate bus number*/
	pcie_write_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0x18, 0x00010100);
	/*setup I/O Base register*/
	pcie_write_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0x30, 0x0000FFFF);
	pcie_write_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0x1C, 0x000000F0);
	/*setup memory base register*/
	pcie_write_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0x20, 0x1F701F70);
	/*setup prefetchable memory base register */
	pcie_write_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0x24, 0x0000FFF0);
	/*setup I/O Base upper 16 bits register*/
	/*setup interrupt line register*/
	/*setup bridge control*/
	pcie_write_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0x3C, 0x0004010B);
	/* pci register 0x10 config needed or not? Linos for L2H will configure it */
	do
	{
		mdelay(30);
		reg_val = pcie_read_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0xe0);
		i++;
	}
	while((reg_val & 0x03f00000) != 0x00100000 && i <= 10);//check the if the dev has been link up
	for(i = 0; i < 10; i++){
		reg1_val = pcie_read_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x0);
		mdelay(1);
		reg2_val = pcie_read_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_1, 0x0);
		mdelay(1);
	}
	if( (reg1_val != 0xffffffff) &&
			( (reg1_val == ((NIC3090_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID)) //duoduo_20090702
			  || (reg1_val == ((NIC3091_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))
			  || (reg1_val == ((NIC3092_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID)) 
			  || (reg1_val == ((NIC3390_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))
			  || (reg1_val == ((NIC5390_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))//xyyou_20101111
			  || (reg1_val == ((NIC539F_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))
			  || (reg1_val == ((NIC5392_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))) ){//xyyou wait to do
		pcie_write_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x04, 0x00100006);
		pcie_write_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x10, PHYSADDR(PCI_DEVICE_MEM1)); 
		pcie_write_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x14, 0); 
		pcie_write_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x18, 0); 
		pcie_write_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x1C, 0); 
		pcie_write_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x20, 0); 
		pcie_write_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x24, 0); 
		pcie_write_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x30, 0); 
		pcie_write_config_word(PCIE_TYPE_DEV, PCIE_BUS_DEV, PCIE_DEVNUM_0, 0x3C, 0x0000010B); 

		slot = PCIE_DEVNUM_0;		
		pci_device_exist++;
	}
	else if( (reg2_val != 0xffffffff) &&
			( (reg2_val == ((NIC3090_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID)) 
			  || (reg2_val == ((NIC3091_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))
			  || (reg2_val == ((NIC3092_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))
			  || (reg1_val == ((NIC3390_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))
			  || (reg1_val == ((NIC5390_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))
			  || (reg1_val == ((NIC539F_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))
			  || (reg1_val == ((NIC5392_PCIe_DEVICE_ID <<16) |NIC_PCI_VENDOR_ID))) ){
		slot=PCIE_DEVNUM_1;
		pci_device_exist++;
	}
	else{
		printk("no_pci_found error case\n");
		return -1;
	}
	return slot;
}
EXPORT_SYMBOL(pcieRegInitConfig);

void
ahbErrChk(void){
	register uint32 status=0;
	unsigned long flags;
	status=VPint(CR_AHB_AACS);
	if((status & AHB_BUS_TIMEOUT_ERR)||(status & AHB_BUS_ADDR_ERR)){	
		printk("CR_AHB_AACS:0x%08lx\n", status);
		printk("CR_AHB_ABEM:0x%08lx\n", VPint(CR_AHB_ABEM));
		printk("CR_AHB_ABEA:0x%08lx\n", VPint(CR_AHB_ABEA));
		local_irq_save(flags);
		ahb_status=1;
		pcieReset();
		pcieRegInitConfig();
		local_irq_restore(flags);
	}
}
EXPORT_SYMBOL(ahbErrChk);

#ifdef CONFIG_MIPS_TC3162U
static irqreturn_t ahbErrIsr(int irq, void *dev){
	ahbErrChk();	
	return IRQ_HANDLED;
}
#endif

void chkAhbErr(int force){
	uint32 val=0;
	unsigned long flags;
	if(isTC3162U && pcie_soft_patch){
		local_irq_save(flags);
		/*check the pcie bus crc error counter*/
		val= pcie_read_config_word(PCIE_TYPE_RC, PCIE_BUS_RC, PCIE_DEVNUM_0, 0x54);
		if((val!=0x0) || (force==0x1) ){
			/*Reset pcie and refill pcie-registers*/
			pcieReset();
			pcieRegInitConfig();
			ahb_status = 1;
		}
		local_irq_restore(flags);
	}
}
EXPORT_SYMBOL(chkAhbErr);
static int ahb_status_read_proc(char *page, char **start, off_t off,
	int count, int *eof, void *data)
{
	int len;
	len = sprintf(page, "%d %d", pcie_soft_patch,ahb_status);
	len -= off;
	*start = page + off;

	if (len > count)
		len = count;
	else
		*eof = 1;

	if (len < 0)
		len = 0;
	
	chkAhbErr(0);
	return len;
}

static int ahb_status_write_proc(struct file *file, const char *buffer,
	unsigned long count, void *data)
{
	char val_string[8];
	int val=0;
	unsigned long flags;

	if (count > sizeof(val_string) - 1)
		return -EINVAL;

	if (copy_from_user(val_string, buffer, count))
		return -EFAULT;

	val_string[count] = '\0';
	if(sscanf(val_string,"%d %d", &pcie_soft_patch, &val)!=2){
		printk("usage: <onoff> <type>\n");
		return count;
	}
	if(val==0x2){
		/*Reset pcie and refill pcie-registers*/
		local_irq_save(flags);
		pcieReset();
		pcieRegInitConfig();
		local_irq_restore(flags);
	}
	if (val == 0) /*Disable wifi interface down to up*/
		ahb_status = 0;
	else
		ahb_status = 1;
	return count;
}

static __init int tc3162_pcie_init(void)
{
	struct proc_dir_entry *ahb_status_proc;
	printk("tc3162_pcie_init\n");
	/* no use now
	pci_bios = VPint(CR_AHB_HWCONF) & (1<<8);

	printk(KERN_INFO "tc3162: system has %sPCI BIOS\n",
		pci_bios ? "" : "no ");
	if (pci_bios == 0)
		return -1; */
#ifdef CONFIG_MIPS_TC3182
	VPint(0xbfb000b8) = 0x00000001;
#endif 

#if defined(CONFIG_MIPS_TC3162U) || defined(CONFIG_MIPS_TC3182)
	/*pcie relate clock setting*/
	uint32 tmp = VPint(CR_AHB_SSR);
	//tmp &= ~(1<<0 | 1<<2 | 1<<3 | 1<<4);
	//tmp |= (1<<0 | 1<<2 | 1<<3 | 1<<4);
	/*use internal clock,*/
	tmp &= ~(1<<0 | 1<<2 | 1<<3);
	tmp |= (1<<0 | 1<<2 | 1<<3);
	VPint(CR_AHB_SSR) = tmp;
	mdelay(1);
#endif
	//VPint(CR_AHB_PCIC) &= ~(1<<29);
	//mdelay(5);
	//VPint(CR_AHB_PCIC) &= ~(1<<30);
	//mdelay(5);
	VPint(CR_AHB_PCIC) |= (1<<29);
	mdelay(5);
	VPint(CR_AHB_PCIC) |= (1<<30);
	mdelay(5);

#ifdef CONFIG_MIPS_TC3162U
	/*work arround for pcie link up*/
	VPint(PCIE_CONFIG_ADDR) = 0x40;
	VPint(PCIE_CONFIG_DATA) = 0x20;
#endif	
	/* PCI memory byte swap enable */
	/*
	VPint(CR_AHB_PCIC) |= (1<<24) | (1<<25);
	*/

	/* Set I/O resource limits.  */
	ioport_resource.end = 0x1fffffff;
	iomem_resource.end = 0xffffffff;

	register_pci_controller(&tc3162_pcie_controller);
	
#ifdef CONFIG_MIPS_TC3162U
	/*Add AHB error monitor check*/
	if(request_irq(ARBITER_ERR_INT, ahbErrIsr, 0, "AHB ERR", ahbErrIsr) != 0) {
		printk("request ARBITER err isr error.\n");
	}
#endif
	/*create a proc to check wifi dead or not*/
	ahb_status_proc = create_proc_entry("tc3162/ahb_status", 0, NULL);
	ahb_status_proc->read_proc = ahb_status_read_proc;
	ahb_status_proc->write_proc = ahb_status_write_proc;
	return 0;
}

arch_initcall(tc3162_pcie_init);
