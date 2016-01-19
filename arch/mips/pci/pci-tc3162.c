#include <linux/types.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <asm/tc3162/tc3162.h>


#ifdef CONFIG_MIPS_TC3262
#define PCI_COMMAND_WINDOW 0xBFB80CF8
#endif
static struct resource tc3162_pci_io_resource = {
	.name   = "pci IO space",
	.start  = 0x1FB90000,
	.end    = 0x1FB9FFFF,
	.flags  = IORESOURCE_IO
};

static struct resource tc3162_pci_mem_resource = {
	.name   = "pci memory space",
	.start  = 0x1FBA0000,
	.end    = 0x1FBCFFFF,
	.flags  = IORESOURCE_MEM
};

extern struct pci_ops tc3162_pci_ops;

struct pci_controller tc3162_controller = {
	.pci_ops   		= &tc3162_pci_ops,
	.io_resource	= &tc3162_pci_io_resource,
	.mem_resource	= &tc3162_pci_mem_resource,
};

static __init int tc3162_pci_init(void)
{
	int pci_bios;

#ifndef CONFIG_MIPS_TC3262
	pci_bios = VPint(CR_AHB_HWCONF) & (1<<8);

	printk(KERN_INFO "tc3162: system has %sPCI BIOS\n",
		pci_bios ? "" : "no ");
	if (pci_bios == 0)
		return -1;
#endif
	VPint(CR_AHB_PCIC) &= ~(1<<31);
	mdelay(100);
	VPint(CR_AHB_PCIC) |= (1<<31);
	mdelay(300);

	/* PCI memory byte swap enable */
	/*
	VPint(CR_AHB_PCIC) |= (1<<24) | (1<<25);
	*/

#ifdef CONFIG_MIPS_TC3262

	/*read pci enable bit from PCI bridge command window to check pci support.
           shnwind*/
	VPint(PCI_COMMAND_WINDOW) = (1<<31);
	 pci_bios = VPint(PCI_COMMAND_WINDOW);
	 
	  printk(KERN_INFO "system has %sPCI BIOS\n",pci_bios ? "" : "no ");
	  if (pci_bios == 0){
		  return -1;
	  }
#endif	
	/* Set I/O resource limits.  */
	ioport_resource.end = 0x1fffffff;
	iomem_resource.end = 0xffffffff;

	register_pci_controller(&tc3162_controller);
	return 0;
}

arch_initcall(tc3162_pci_init);
