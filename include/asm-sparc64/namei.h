/* $Id: namei.h,v 1.1.1.1 2010/04/09 09:39:23 feiyan Exp $
 * linux/include/asm-sparc64/namei.h
 *
 * Routines to handle famous /usr/gnemul/s*.
 * Included from linux/fs/namei.c
 */

#ifndef __SPARC64_NAMEI_H
#define __SPARC64_NAMEI_H

#define SPARC_BSD_EMUL "/usr/gnemul/sunos/"
#define SPARC_SOL_EMUL "/usr/gnemul/solaris/"

static inline char * __emul_prefix(void)
{
	switch (current->personality) {
	case PER_SUNOS:
		return SPARC_BSD_EMUL;
	case PER_SVR4:
		return SPARC_SOL_EMUL;
	default:
		return NULL;
	}
}

#endif /* __SPARC64_NAMEI_H */
