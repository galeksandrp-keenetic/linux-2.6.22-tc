#include <linux/init.h>
#include <linux/types.h>
#include <linux/root_dev.h>
#include <linux/kernel.h>
#include <linux/mtd/map.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <asm/io.h>
#include <asm/tc3162/tc3162.h>

#define WINDOW_ADDR 0x1fc00000
#define WINDOW_SIZE 0x400000
#define BUSWIDTH 	2

static struct mtd_info *tc3162_mtd_info;

static struct map_info tc3162_map = {
       .name = "tc3162",
       .size = WINDOW_SIZE,
       .bankwidth = BUSWIDTH,
       .phys = WINDOW_ADDR,
};

static struct mtd_partition tc3162_parts[] = {
        {
                name:           "U-Boot",  /* mtdblock0 */
                size:           0x30000,  /* 192K */
                offset:         0,
                mask_flags:     0  /* force read-only */
        }, {
                name:           "U-Config", /* mtdblock1 */
                size:           0x10000,  /* 64K */
                offset:         0x30000,
                mask_flags:     0  /* force read-only */
        }, {
                name:           "RF-EEPROM", /* mtdblock2 */
                size:           0x10000,  /* 64K */
                offset:         0x40000,
                mask_flags:     0  /* force read-only */
        }, {
#ifdef CONFIG_ROOTFS_IN_FLASH
#if defined (CONFIG_FLASH_4M)
                name:           "Kernel", /* mtdblock3 */
                size:           0x130000,
                offset:         0x50000,
        }, {
                name:           "RootFS", /* mtdblock4 */
                size:           0x240000,
                offset:         0x180000,
        }, {
                name:           "Config", /* mtdblock5 */
                size:           0x10000,
                offset:         0x3c0000,
#elif defined (CONFIG_FLASH_8M)
                name:           "Kernel", /* mtdblock3 */
                size:           0x150000,
                offset:         0x50000,
        }, {
                name:           "RootFS", /* mtdblock4 */
                size:           0x550000,
                offset:         0x1a0000,
        }, {
                name:           "Config", /* mtdblock5 */
                size:           0x10000,
                offset:         0x6f0000,
        }, {
                name:           "Storage", /* mtdblock6 */
                size:           0x100000,
                offset:         0x700000,
#elif defined (CONFIG_FLASH_16M)
                name:           "Kernel", /* mtdblock3 */
                size:           0x150000,
                offset:         0x50000,
        }, {
                name:           "RootFS", /* mtdblock4 */
                size:           0xc50000,
                offset:         0x1a0000,
        }, {
                name:           "Config", /* mtdblock5 */
                size:           0x10000,
                offset:         0xdf0000,
        }, {
                name:           "Storage", /* mtdblock6 */
                size:           0x200000,
                offset:         0xe00000,
#else
                name:           "Kernel", /* mtdblock3 */
                size:           0xF0000,
                offset:         0x50000,
        }, {
                name:           "RootFS", /* mtdblock4 */
                size:           0x2B0000,
                offset:         0x140000,
        }, {
                name:           "Config", /* mtdblock5 */
                size:           0x10000,
                offset:         0x3f0000,
#endif
#else
#if defined (CONFIG_FLASH_4M)
                name:           "Kernel", /* mtdblock3 */
                size:           0x370000,
                offset:         0x50000,
        }, {
                name:           "Config", /* mtdblock5 */
                size:           0x10000,
                offset:         0x3c0000,
#elif defined (CONFIG_FLASH_8M)
                name:           "Kernel", /* mtdblock3 */
                size:           0x7a0000,
                offset:         0x50000,
        }, {
                name:           "Config", /* mtdblock5 */
                size:           0x10000,
                offset:         0x7f0000,
#elif defined (CONFIG_FLASH_16M)
                name:           "Kernel", /* mtdblock3 */
                size:           0xfa0000,
                offset:         0x50000,
        }, {
                name:           "Config", /* mtdblock5 */
                size:           0x10000,
                offset:         0xff0000,
#else
                name:           "Kernel", /* mtdblock3 */
                size:           0x3a0000,
                offset:         0x50000,
        }, {
                name:           "Config", /* mtdblock5 */
                size:           0x10000,
                offset:         0x3f0000,

#endif	  
#endif
        }
};

static int tc3162_parts_size = sizeof(tc3162_parts) / sizeof(tc3162_parts[0]);

static int __init tc3162_mtd_init(void)
{
	/*add 8M 16M flash support. shnwind*/
#if !defined CONFIG_FLASH_4M
	if (isTC3162U || isTC3182 || isRT65168 || isRT63165 || isRT63365 || isRT63260){
		/*enable addr bigger than 4M support.*/
		VPint(0xbfb00038) |= 0x80000000;
		printk("tc3162: flash device 0x%08x at 0x%08x\n", 0x1000000, 0x10000000);
		tc3162_map.virt = ioremap_nocache(0x10000000, 0x1000000);
		tc3162_map.phys = 0x10000000;
		tc3162_map.size = 0x1000000;
		ioremap_nocache(WINDOW_ADDR, WINDOW_SIZE);
	} else
#endif
	{
		printk("tc3162: flash device 0x%08x at 0x%08x\n", WINDOW_SIZE, WINDOW_ADDR);
		tc3162_map.virt = ioremap_nocache(WINDOW_ADDR, WINDOW_SIZE);
	}
	if (!tc3162_map.virt) {
   		printk("tc3162: Failed to ioremap\n");
		return -EIO;
	}

	simple_map_init(&tc3162_map);

	/* check if boot from SPI flash */
	if (IS_SPIFLASH) {
		tc3162_mtd_info = do_map_probe("spiflash_probe", &tc3162_map);
	} else {
		tc3162_mtd_info = do_map_probe("cfi_probe", &tc3162_map);
	}

	if (!tc3162_mtd_info) {
		iounmap(tc3162_map.virt);
		return -ENXIO;
	}

  	tc3162_mtd_info->owner = THIS_MODULE;

	add_mtd_partitions(tc3162_mtd_info, tc3162_parts, tc3162_parts_size);
	return 0;
}

static void __exit tc3162_mtd_cleanup(void)
{
	if (tc3162_mtd_info) {
    	del_mtd_partitions(tc3162_mtd_info);
       	map_destroy(tc3162_mtd_info);
	}

   	if (tc3162_map.virt) {
   		iounmap(tc3162_map.virt);
       	tc3162_map.virt = 0;
	}
}

module_init(tc3162_mtd_init);
module_exit(tc3162_mtd_cleanup);

/*
 * Flash API: ra_mtd_read, ra_mtd_write
 * Arguments:
 *   - num: specific the mtd number
 *   - to/from: the offset to read from or written to
 *   - len: length
 *   - buf: data to be read/written
 * Returns:
 *   - return -errno if failed
 *   - return the number of bytes read/written if successed
 */
#ifdef RA_MTD_RW_BY_NUM
int ra_mtd_write(int num, loff_t to, size_t len, const u_char *buf)
{
	int ret = -1;
	size_t rdlen, wrlen;
	struct mtd_info *mtd;
	struct erase_info ei;
	u_char *bak = NULL;

	mtd = get_mtd_device(NULL, num);
	if (IS_ERR(mtd))
		return (int)mtd;
	if (len > mtd->erasesize) {
		put_mtd_device(mtd);
		return -E2BIG;
	}

	bak = kmalloc(mtd->erasesize, GFP_KERNEL);
	if (bak == NULL) {
		put_mtd_device(mtd);
		return -ENOMEM;
	}

	ret = mtd->read(mtd, 0, mtd->erasesize, &rdlen, bak);
	if (ret != 0) {
		put_mtd_device(mtd);
		kfree(bak);
		return ret;
	}
	if (rdlen != mtd->erasesize)
		printk("warning: ra_mtd_write: rdlen is not equal to erasesize\n");

	memcpy(bak + to, buf, len);

	ei.mtd = mtd;
	ei.callback = NULL;
	ei.addr = 0;
	ei.len = mtd->erasesize;
	ei.priv = 0;
	ret = mtd->erase(mtd, &ei);
	if (ret != 0) {
		put_mtd_device(mtd);
		kfree(bak);
		return ret;
	}

	ret = mtd->write(mtd, 0, mtd->erasesize, &wrlen, bak);

	put_mtd_device(mtd);
	kfree(bak);
	return ret;
}
#endif

int ra_mtd_write_nm(char *name, loff_t to, size_t len, const u_char *buf)
{
	int ret = -1;
	size_t rdlen, wrlen;
	struct mtd_info *mtd;
	struct erase_info ei;
	u_char *bak = NULL;

	mtd = get_mtd_device_nm(name);
	if (IS_ERR(mtd))
		return (int)mtd;
	if (len > mtd->erasesize) {
		put_mtd_device(mtd);
		return -E2BIG;
	}

	bak = kmalloc(mtd->erasesize, GFP_KERNEL);
	if (bak == NULL) {
		put_mtd_device(mtd);
		return -ENOMEM;
	}

	ret = mtd->read(mtd, 0, mtd->erasesize, &rdlen, bak);
	if (ret != 0) {
		put_mtd_device(mtd);
		kfree(bak);
		return ret;
	}
	if (rdlen != mtd->erasesize)
		printk("warning: ra_mtd_write: rdlen is not equal to erasesize\n");

	memcpy(bak + to, buf, len);

	ei.mtd = mtd;
	ei.callback = NULL;
	ei.addr = 0;
	ei.len = mtd->erasesize;
	ei.priv = 0;
	ret = mtd->erase(mtd, &ei);
	if (ret != 0) {
		put_mtd_device(mtd);
		kfree(bak);
		return ret;
	}

	ret = mtd->write(mtd, 0, mtd->erasesize, &wrlen, bak);

	put_mtd_device(mtd);
	kfree(bak);
	return ret;
}

#ifdef RA_MTD_RW_BY_NUM
int ra_mtd_read(int num, loff_t from, size_t len, u_char *buf)
{
	int ret;
	size_t rdlen;
	struct mtd_info *mtd;

	mtd = get_mtd_device(NULL, num);
	if (IS_ERR(mtd))
		return (int)mtd;

	ret = mtd->read(mtd, from, len, &rdlen, buf);
	if (rdlen != len)
		printk("warning: ra_mtd_read: rdlen is not equal to len\n");

	put_mtd_device(mtd);
	return ret;
}
#endif

int ra_mtd_read_nm(char *name, loff_t from, size_t len, u_char *buf)
{
	int ret;
	size_t rdlen;
	struct mtd_info *mtd;

	mtd = get_mtd_device_nm(name);
	if (IS_ERR(mtd))
		return (int)mtd;

	ret = mtd->read(mtd, from, len, &rdlen, buf);
	if (rdlen != len)
		printk("warning: ra_mtd_read_nm: rdlen is not equal to len\n");

	put_mtd_device(mtd);
	return ret;
}

#ifdef RA_MTD_RW_BY_NUM
EXPORT_SYMBOL(ra_mtd_write);
EXPORT_SYMBOL(ra_mtd_read);
#endif
EXPORT_SYMBOL(ra_mtd_write_nm);
EXPORT_SYMBOL(ra_mtd_read_nm);
