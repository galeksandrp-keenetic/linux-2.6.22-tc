#ifndef __sser_defs_h
#define __sser_defs_h

/*
 * This file is autogenerated from
 *   file:           ../../inst/syncser/rtl/sser_regs.r
 *     id:           sser_regs.r,v 1.24 2005/02/11 14:27:36 gunnard Exp
 *     last modfied: Mon Apr 11 16:09:48 2005
 *
 *   by /n/asic/design/tools/rdesc/src/rdes2c --outfile sser_defs.h ../../inst/syncser/rtl/sser_regs.r
 *      id: $Id: sser_defs.h,v 1.1.1.1 2010/04/09 09:39:25 feiyan Exp $
 * Any changes here will be lost.
 *
 * -*- buffer-read-only: t -*-
 */
/* Main access macros */
#ifndef REG_RD
#define REG_RD( scope, inst, reg ) \
  REG_READ( reg_##scope##_##reg, \
            (inst) + REG_RD_ADDR_##scope##_##reg )
#endif

#ifndef REG_WR
#define REG_WR( scope, inst, reg, val ) \
  REG_WRITE( reg_##scope##_##reg, \
             (inst) + REG_WR_ADDR_##scope##_##reg, (val) )
#endif

#ifndef REG_RD_VECT
#define REG_RD_VECT( scope, inst, reg, index ) \
  REG_READ( reg_##scope##_##reg, \
            (inst) + REG_RD_ADDR_##scope##_##reg + \
	    (index) * STRIDE_##scope##_##reg )
#endif

#ifndef REG_WR_VECT
#define REG_WR_VECT( scope, inst, reg, index, val ) \
  REG_WRITE( reg_##scope##_##reg, \
             (inst) + REG_WR_ADDR_##scope##_##reg + \
	     (index) * STRIDE_##scope##_##reg, (val) )
#endif

#ifndef REG_RD_INT
#define REG_RD_INT( scope, inst, reg ) \
  REG_READ( int, (inst) + REG_RD_ADDR_##scope##_##reg )
#endif

#ifndef REG_WR_INT
#define REG_WR_INT( scope, inst, reg, val ) \
  REG_WRITE( int, (inst) + REG_WR_ADDR_##scope##_##reg, (val) )
#endif

#ifndef REG_RD_INT_VECT
#define REG_RD_INT_VECT( scope, inst, reg, index ) \
  REG_READ( int, (inst) + REG_RD_ADDR_##scope##_##reg + \
	    (index) * STRIDE_##scope##_##reg )
#endif

#ifndef REG_WR_INT_VECT
#define REG_WR_INT_VECT( scope, inst, reg, index, val ) \
  REG_WRITE( int, (inst) + REG_WR_ADDR_##scope##_##reg + \
	     (index) * STRIDE_##scope##_##reg, (val) )
#endif

#ifndef REG_TYPE_CONV
#define REG_TYPE_CONV( type, orgtype, val ) \
  ( { union { orgtype o; type n; } r; r.o = val; r.n; } )
#endif

#ifndef reg_page_size
#define reg_page_size 8192
#endif

#ifndef REG_ADDR
#define REG_ADDR( scope, inst, reg ) \
  ( (inst) + REG_RD_ADDR_##scope##_##reg )
#endif

#ifndef REG_ADDR_VECT
#define REG_ADDR_VECT( scope, inst, reg, index ) \
  ( (inst) + REG_RD_ADDR_##scope##_##reg + \
    (index) * STRIDE_##scope##_##reg )
#endif

/* C-code for register scope sser */

/* Register rw_cfg, scope sser, type rw */
typedef struct {
  unsigned int clk_div      : 16;
  unsigned int base_freq    : 3;
  unsigned int gate_clk     : 1;
  unsigned int clkgate_ctrl : 1;
  unsigned int clkgate_in   : 1;
  unsigned int clk_dir      : 1;
  unsigned int clk_od_mode  : 1;
  unsigned int out_clk_pol  : 1;
  unsigned int out_clk_src  : 2;
  unsigned int clk_in_sel   : 1;
  unsigned int hold_pol     : 1;
  unsigned int prepare      : 1;
  unsigned int en           : 1;
  unsigned int dummy1       : 1;
} reg_sser_rw_cfg;
#define REG_RD_ADDR_sser_rw_cfg 0
#define REG_WR_ADDR_sser_rw_cfg 0

/* Register rw_frm_cfg, scope sser, type rw */
typedef struct {
  unsigned int wordrate       : 10;
  unsigned int rec_delay      : 3;
  unsigned int tr_delay       : 3;
  unsigned int early_wend     : 1;
  unsigned int level          : 2;
  unsigned int type           : 1;
  unsigned int clk_pol        : 1;
  unsigned int fr_in_rxclk    : 1;
  unsigned int clk_src        : 1;
  unsigned int out_off        : 1;
  unsigned int out_on         : 1;
  unsigned int frame_pin_dir  : 1;
  unsigned int frame_pin_use  : 2;
  unsigned int status_pin_dir : 1;
  unsigned int status_pin_use : 2;
  unsigned int dummy1         : 1;
} reg_sser_rw_frm_cfg;
#define REG_RD_ADDR_sser_rw_frm_cfg 4
#define REG_WR_ADDR_sser_rw_frm_cfg 4

/* Register rw_tr_cfg, scope sser, type rw */
typedef struct {
  unsigned int tr_en          : 1;
  unsigned int stop           : 1;
  unsigned int urun_stop      : 1;
  unsigned int eop_stop       : 1;
  unsigned int sample_size    : 6;
  unsigned int sh_dir         : 1;
  unsigned int clk_pol        : 1;
  unsigned int clk_src        : 1;
  unsigned int use_dma        : 1;
  unsigned int mode           : 2;
  unsigned int frm_src        : 1;
  unsigned int use60958       : 1;
  unsigned int iec60958_ckdiv : 2;
  unsigned int rate_ctrl      : 1;
  unsigned int use_md         : 1;
  unsigned int dual_i2s       : 1;
  unsigned int data_pin_use   : 2;
  unsigned int od_mode        : 1;
  unsigned int bulk_wspace    : 2;
  unsigned int dummy1         : 4;
} reg_sser_rw_tr_cfg;
#define REG_RD_ADDR_sser_rw_tr_cfg 8
#define REG_WR_ADDR_sser_rw_tr_cfg 8

/* Register rw_rec_cfg, scope sser, type rw */
typedef struct {
  unsigned int rec_en          : 1;
  unsigned int force_eop       : 1;
  unsigned int stop            : 1;
  unsigned int orun_stop       : 1;
  unsigned int eop_stop        : 1;
  unsigned int sample_size     : 6;
  unsigned int sh_dir          : 1;
  unsigned int clk_pol         : 1;
  unsigned int clk_src         : 1;
  unsigned int use_dma         : 1;
  unsigned int mode            : 2;
  unsigned int frm_src         : 2;
  unsigned int use60958        : 1;
  unsigned int iec60958_ui_len : 5;
  unsigned int slave2_en       : 1;
  unsigned int slave3_en       : 1;
  unsigned int fifo_thr        : 2;
  unsigned int dummy1          : 3;
} reg_sser_rw_rec_cfg;
#define REG_RD_ADDR_sser_rw_rec_cfg 12
#define REG_WR_ADDR_sser_rw_rec_cfg 12

/* Register rw_tr_data, scope sser, type rw */
typedef struct {
  unsigned int data : 16;
  unsigned int md   : 1;
  unsigned int dummy1 : 15;
} reg_sser_rw_tr_data;
#define REG_RD_ADDR_sser_rw_tr_data 16
#define REG_WR_ADDR_sser_rw_tr_data 16

/* Register r_rec_data, scope sser, type r */
typedef struct {
  unsigned int data      : 16;
  unsigned int md        : 1;
  unsigned int ext_clk   : 1;
  unsigned int status_in : 1;
  unsigned int frame_in  : 1;
  unsigned int din       : 1;
  unsigned int data_in   : 1;
  unsigned int clk_in    : 1;
  unsigned int dummy1    : 9;
} reg_sser_r_rec_data;
#define REG_RD_ADDR_sser_r_rec_data 20

/* Register rw_extra, scope sser, type rw */
typedef struct {
  unsigned int clkoff_cycles : 20;
  unsigned int clkoff_en     : 1;
  unsigned int clkon_en      : 1;
  unsigned int dout_delay    : 5;
  unsigned int dummy1        : 5;
} reg_sser_rw_extra;
#define REG_RD_ADDR_sser_rw_extra 24
#define REG_WR_ADDR_sser_rw_extra 24

/* Register rw_intr_mask, scope sser, type rw */
typedef struct {
  unsigned int trdy    : 1;
  unsigned int rdav    : 1;
  unsigned int tidle   : 1;
  unsigned int rstop   : 1;
  unsigned int urun    : 1;
  unsigned int orun    : 1;
  unsigned int md_rec  : 1;
  unsigned int md_sent : 1;
  unsigned int r958err : 1;
  unsigned int dummy1  : 23;
} reg_sser_rw_intr_mask;
#define REG_RD_ADDR_sser_rw_intr_mask 28
#define REG_WR_ADDR_sser_rw_intr_mask 28

/* Register rw_ack_intr, scope sser, type rw */
typedef struct {
  unsigned int trdy    : 1;
  unsigned int rdav    : 1;
  unsigned int tidle   : 1;
  unsigned int rstop   : 1;
  unsigned int urun    : 1;
  unsigned int orun    : 1;
  unsigned int md_rec  : 1;
  unsigned int md_sent : 1;
  unsigned int r958err : 1;
  unsigned int dummy1  : 23;
} reg_sser_rw_ack_intr;
#define REG_RD_ADDR_sser_rw_ack_intr 32
#define REG_WR_ADDR_sser_rw_ack_intr 32

/* Register r_intr, scope sser, type r */
typedef struct {
  unsigned int trdy    : 1;
  unsigned int rdav    : 1;
  unsigned int tidle   : 1;
  unsigned int rstop   : 1;
  unsigned int urun    : 1;
  unsigned int orun    : 1;
  unsigned int md_rec  : 1;
  unsigned int md_sent : 1;
  unsigned int r958err : 1;
  unsigned int dummy1  : 23;
} reg_sser_r_intr;
#define REG_RD_ADDR_sser_r_intr 36

/* Register r_masked_intr, scope sser, type r */
typedef struct {
  unsigned int trdy    : 1;
  unsigned int rdav    : 1;
  unsigned int tidle   : 1;
  unsigned int rstop   : 1;
  unsigned int urun    : 1;
  unsigned int orun    : 1;
  unsigned int md_rec  : 1;
  unsigned int md_sent : 1;
  unsigned int r958err : 1;
  unsigned int dummy1  : 23;
} reg_sser_r_masked_intr;
#define REG_RD_ADDR_sser_r_masked_intr 40


/* Constants */
enum {
  regk_sser_both                           = 0x00000002,
  regk_sser_bulk                           = 0x00000001,
  regk_sser_clk100                         = 0x00000000,
  regk_sser_clk_in                         = 0x00000000,
  regk_sser_const0                         = 0x00000003,
  regk_sser_dout                           = 0x00000002,
  regk_sser_edge                           = 0x00000000,
  regk_sser_ext                            = 0x00000001,
  regk_sser_ext_clk                        = 0x00000001,
  regk_sser_f100                           = 0x00000000,
  regk_sser_f29_493                        = 0x00000004,
  regk_sser_f32                            = 0x00000005,
  regk_sser_f32_768                        = 0x00000006,
  regk_sser_frm                            = 0x00000003,
  regk_sser_gio0                           = 0x00000000,
  regk_sser_gio1                           = 0x00000001,
  regk_sser_hispeed                        = 0x00000001,
  regk_sser_hold                           = 0x00000002,
  regk_sser_in                             = 0x00000000,
  regk_sser_inf                            = 0x00000003,
  regk_sser_intern                         = 0x00000000,
  regk_sser_intern_clk                     = 0x00000001,
  regk_sser_intern_tb                      = 0x00000000,
  regk_sser_iso                            = 0x00000000,
  regk_sser_level                          = 0x00000001,
  regk_sser_lospeed                        = 0x00000000,
  regk_sser_lsbfirst                       = 0x00000000,
  regk_sser_msbfirst                       = 0x00000001,
  regk_sser_neg                            = 0x00000001,
  regk_sser_neg_lo                         = 0x00000000,
  regk_sser_no                             = 0x00000000,
  regk_sser_no_clk                         = 0x00000007,
  regk_sser_nojitter                       = 0x00000002,
  regk_sser_out                            = 0x00000001,
  regk_sser_pos                            = 0x00000000,
  regk_sser_pos_hi                         = 0x00000001,
  regk_sser_rec                            = 0x00000000,
  regk_sser_rw_cfg_default                 = 0x00000000,
  regk_sser_rw_extra_default               = 0x00000000,
  regk_sser_rw_frm_cfg_default             = 0x00000000,
  regk_sser_rw_intr_mask_default           = 0x00000000,
  regk_sser_rw_rec_cfg_default             = 0x00000000,
  regk_sser_rw_tr_cfg_default              = 0x01800000,
  regk_sser_rw_tr_data_default             = 0x00000000,
  regk_sser_thr16                          = 0x00000001,
  regk_sser_thr32                          = 0x00000002,
  regk_sser_thr8                           = 0x00000000,
  regk_sser_tr                             = 0x00000001,
  regk_sser_ts_out                         = 0x00000003,
  regk_sser_tx_bulk                        = 0x00000002,
  regk_sser_wiresave                       = 0x00000002,
  regk_sser_yes                            = 0x00000001
};
#endif /* __sser_defs_h */
