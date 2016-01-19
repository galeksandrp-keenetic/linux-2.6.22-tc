#ifndef __dma_defs_asm_h
#define __dma_defs_asm_h

/*
 * This file is autogenerated from
 *   file:           ../../inst/dma/inst/dma_common/rtl/dma_regdes.r
 *     id:           dma_regdes.r,v 1.39 2005/02/10 14:07:23 janb Exp
 *     last modfied: Mon Apr 11 16:06:51 2005
 *
 *   by /n/asic/design/tools/rdesc/src/rdes2c -asm --outfile asm/dma_defs_asm.h ../../inst/dma/inst/dma_common/rtl/dma_regdes.r
 *      id: $Id: dma_defs_asm.h,v 1.1.1.1 2010/04/09 09:39:25 feiyan Exp $
 * Any changes here will be lost.
 *
 * -*- buffer-read-only: t -*-
 */

#ifndef REG_FIELD
#define REG_FIELD( scope, reg, field, value ) \
  REG_FIELD_X_( value, reg_##scope##_##reg##___##field##___lsb )
#define REG_FIELD_X_( value, shift ) ((value) << shift)
#endif

#ifndef REG_STATE
#define REG_STATE( scope, reg, field, symbolic_value ) \
  REG_STATE_X_( regk_##scope##_##symbolic_value, reg_##scope##_##reg##___##field##___lsb )
#define REG_STATE_X_( k, shift ) (k << shift)
#endif

#ifndef REG_MASK
#define REG_MASK( scope, reg, field ) \
  REG_MASK_X_( reg_##scope##_##reg##___##field##___width, reg_##scope##_##reg##___##field##___lsb )
#define REG_MASK_X_( width, lsb ) (((1 << width)-1) << lsb)
#endif

#ifndef REG_LSB
#define REG_LSB( scope, reg, field ) reg_##scope##_##reg##___##field##___lsb
#endif

#ifndef REG_BIT
#define REG_BIT( scope, reg, field ) reg_##scope##_##reg##___##field##___bit
#endif

#ifndef REG_ADDR
#define REG_ADDR( scope, inst, reg ) REG_ADDR_X_(inst, reg_##scope##_##reg##_offset)
#define REG_ADDR_X_( inst, offs ) ((inst) + offs)
#endif

#ifndef REG_ADDR_VECT
#define REG_ADDR_VECT( scope, inst, reg, index ) \
         REG_ADDR_VECT_X_(inst, reg_##scope##_##reg##_offset, index, \
			 STRIDE_##scope##_##reg )
#define REG_ADDR_VECT_X_( inst, offs, index, stride ) \
                          ((inst) + offs + (index) * stride)
#endif

/* Register rw_data, scope dma, type rw */
#define reg_dma_rw_data_offset 0

/* Register rw_data_next, scope dma, type rw */
#define reg_dma_rw_data_next_offset 4

/* Register rw_data_buf, scope dma, type rw */
#define reg_dma_rw_data_buf_offset 8

/* Register rw_data_ctrl, scope dma, type rw */
#define reg_dma_rw_data_ctrl___eol___lsb 0
#define reg_dma_rw_data_ctrl___eol___width 1
#define reg_dma_rw_data_ctrl___eol___bit 0
#define reg_dma_rw_data_ctrl___out_eop___lsb 3
#define reg_dma_rw_data_ctrl___out_eop___width 1
#define reg_dma_rw_data_ctrl___out_eop___bit 3
#define reg_dma_rw_data_ctrl___intr___lsb 4
#define reg_dma_rw_data_ctrl___intr___width 1
#define reg_dma_rw_data_ctrl___intr___bit 4
#define reg_dma_rw_data_ctrl___wait___lsb 5
#define reg_dma_rw_data_ctrl___wait___width 1
#define reg_dma_rw_data_ctrl___wait___bit 5
#define reg_dma_rw_data_ctrl_offset 12

/* Register rw_data_stat, scope dma, type rw */
#define reg_dma_rw_data_stat___in_eop___lsb 3
#define reg_dma_rw_data_stat___in_eop___width 1
#define reg_dma_rw_data_stat___in_eop___bit 3
#define reg_dma_rw_data_stat_offset 16

/* Register rw_data_md, scope dma, type rw */
#define reg_dma_rw_data_md___md___lsb 0
#define reg_dma_rw_data_md___md___width 16
#define reg_dma_rw_data_md_offset 20

/* Register rw_data_md_s, scope dma, type rw */
#define reg_dma_rw_data_md_s___md_s___lsb 0
#define reg_dma_rw_data_md_s___md_s___width 16
#define reg_dma_rw_data_md_s_offset 24

/* Register rw_data_after, scope dma, type rw */
#define reg_dma_rw_data_after_offset 28

/* Register rw_ctxt, scope dma, type rw */
#define reg_dma_rw_ctxt_offset 32

/* Register rw_ctxt_next, scope dma, type rw */
#define reg_dma_rw_ctxt_next_offset 36

/* Register rw_ctxt_ctrl, scope dma, type rw */
#define reg_dma_rw_ctxt_ctrl___eol___lsb 0
#define reg_dma_rw_ctxt_ctrl___eol___width 1
#define reg_dma_rw_ctxt_ctrl___eol___bit 0
#define reg_dma_rw_ctxt_ctrl___intr___lsb 4
#define reg_dma_rw_ctxt_ctrl___intr___width 1
#define reg_dma_rw_ctxt_ctrl___intr___bit 4
#define reg_dma_rw_ctxt_ctrl___store_mode___lsb 6
#define reg_dma_rw_ctxt_ctrl___store_mode___width 1
#define reg_dma_rw_ctxt_ctrl___store_mode___bit 6
#define reg_dma_rw_ctxt_ctrl___en___lsb 7
#define reg_dma_rw_ctxt_ctrl___en___width 1
#define reg_dma_rw_ctxt_ctrl___en___bit 7
#define reg_dma_rw_ctxt_ctrl_offset 40

/* Register rw_ctxt_stat, scope dma, type rw */
#define reg_dma_rw_ctxt_stat___dis___lsb 7
#define reg_dma_rw_ctxt_stat___dis___width 1
#define reg_dma_rw_ctxt_stat___dis___bit 7
#define reg_dma_rw_ctxt_stat_offset 44

/* Register rw_ctxt_md0, scope dma, type rw */
#define reg_dma_rw_ctxt_md0___md0___lsb 0
#define reg_dma_rw_ctxt_md0___md0___width 16
#define reg_dma_rw_ctxt_md0_offset 48

/* Register rw_ctxt_md0_s, scope dma, type rw */
#define reg_dma_rw_ctxt_md0_s___md0_s___lsb 0
#define reg_dma_rw_ctxt_md0_s___md0_s___width 16
#define reg_dma_rw_ctxt_md0_s_offset 52

/* Register rw_ctxt_md1, scope dma, type rw */
#define reg_dma_rw_ctxt_md1_offset 56

/* Register rw_ctxt_md1_s, scope dma, type rw */
#define reg_dma_rw_ctxt_md1_s_offset 60

/* Register rw_ctxt_md2, scope dma, type rw */
#define reg_dma_rw_ctxt_md2_offset 64

/* Register rw_ctxt_md2_s, scope dma, type rw */
#define reg_dma_rw_ctxt_md2_s_offset 68

/* Register rw_ctxt_md3, scope dma, type rw */
#define reg_dma_rw_ctxt_md3_offset 72

/* Register rw_ctxt_md3_s, scope dma, type rw */
#define reg_dma_rw_ctxt_md3_s_offset 76

/* Register rw_ctxt_md4, scope dma, type rw */
#define reg_dma_rw_ctxt_md4_offset 80

/* Register rw_ctxt_md4_s, scope dma, type rw */
#define reg_dma_rw_ctxt_md4_s_offset 84

/* Register rw_saved_data, scope dma, type rw */
#define reg_dma_rw_saved_data_offset 88

/* Register rw_saved_data_buf, scope dma, type rw */
#define reg_dma_rw_saved_data_buf_offset 92

/* Register rw_group, scope dma, type rw */
#define reg_dma_rw_group_offset 96

/* Register rw_group_next, scope dma, type rw */
#define reg_dma_rw_group_next_offset 100

/* Register rw_group_ctrl, scope dma, type rw */
#define reg_dma_rw_group_ctrl___eol___lsb 0
#define reg_dma_rw_group_ctrl___eol___width 1
#define reg_dma_rw_group_ctrl___eol___bit 0
#define reg_dma_rw_group_ctrl___tol___lsb 1
#define reg_dma_rw_group_ctrl___tol___width 1
#define reg_dma_rw_group_ctrl___tol___bit 1
#define reg_dma_rw_group_ctrl___bol___lsb 2
#define reg_dma_rw_group_ctrl___bol___width 1
#define reg_dma_rw_group_ctrl___bol___bit 2
#define reg_dma_rw_group_ctrl___intr___lsb 4
#define reg_dma_rw_group_ctrl___intr___width 1
#define reg_dma_rw_group_ctrl___intr___bit 4
#define reg_dma_rw_group_ctrl___en___lsb 7
#define reg_dma_rw_group_ctrl___en___width 1
#define reg_dma_rw_group_ctrl___en___bit 7
#define reg_dma_rw_group_ctrl_offset 104

/* Register rw_group_stat, scope dma, type rw */
#define reg_dma_rw_group_stat___dis___lsb 7
#define reg_dma_rw_group_stat___dis___width 1
#define reg_dma_rw_group_stat___dis___bit 7
#define reg_dma_rw_group_stat_offset 108

/* Register rw_group_md, scope dma, type rw */
#define reg_dma_rw_group_md___md___lsb 0
#define reg_dma_rw_group_md___md___width 16
#define reg_dma_rw_group_md_offset 112

/* Register rw_group_md_s, scope dma, type rw */
#define reg_dma_rw_group_md_s___md_s___lsb 0
#define reg_dma_rw_group_md_s___md_s___width 16
#define reg_dma_rw_group_md_s_offset 116

/* Register rw_group_up, scope dma, type rw */
#define reg_dma_rw_group_up_offset 120

/* Register rw_group_down, scope dma, type rw */
#define reg_dma_rw_group_down_offset 124

/* Register rw_cmd, scope dma, type rw */
#define reg_dma_rw_cmd___cont_data___lsb 0
#define reg_dma_rw_cmd___cont_data___width 1
#define reg_dma_rw_cmd___cont_data___bit 0
#define reg_dma_rw_cmd_offset 128

/* Register rw_cfg, scope dma, type rw */
#define reg_dma_rw_cfg___en___lsb 0
#define reg_dma_rw_cfg___en___width 1
#define reg_dma_rw_cfg___en___bit 0
#define reg_dma_rw_cfg___stop___lsb 1
#define reg_dma_rw_cfg___stop___width 1
#define reg_dma_rw_cfg___stop___bit 1
#define reg_dma_rw_cfg_offset 132

/* Register rw_stat, scope dma, type rw */
#define reg_dma_rw_stat___mode___lsb 0
#define reg_dma_rw_stat___mode___width 5
#define reg_dma_rw_stat___list_state___lsb 5
#define reg_dma_rw_stat___list_state___width 3
#define reg_dma_rw_stat___stream_cmd_src___lsb 8
#define reg_dma_rw_stat___stream_cmd_src___width 8
#define reg_dma_rw_stat___buf___lsb 24
#define reg_dma_rw_stat___buf___width 8
#define reg_dma_rw_stat_offset 136

/* Register rw_intr_mask, scope dma, type rw */
#define reg_dma_rw_intr_mask___group___lsb 0
#define reg_dma_rw_intr_mask___group___width 1
#define reg_dma_rw_intr_mask___group___bit 0
#define reg_dma_rw_intr_mask___ctxt___lsb 1
#define reg_dma_rw_intr_mask___ctxt___width 1
#define reg_dma_rw_intr_mask___ctxt___bit 1
#define reg_dma_rw_intr_mask___data___lsb 2
#define reg_dma_rw_intr_mask___data___width 1
#define reg_dma_rw_intr_mask___data___bit 2
#define reg_dma_rw_intr_mask___in_eop___lsb 3
#define reg_dma_rw_intr_mask___in_eop___width 1
#define reg_dma_rw_intr_mask___in_eop___bit 3
#define reg_dma_rw_intr_mask___stream_cmd___lsb 4
#define reg_dma_rw_intr_mask___stream_cmd___width 1
#define reg_dma_rw_intr_mask___stream_cmd___bit 4
#define reg_dma_rw_intr_mask_offset 140

/* Register rw_ack_intr, scope dma, type rw */
#define reg_dma_rw_ack_intr___group___lsb 0
#define reg_dma_rw_ack_intr___group___width 1
#define reg_dma_rw_ack_intr___group___bit 0
#define reg_dma_rw_ack_intr___ctxt___lsb 1
#define reg_dma_rw_ack_intr___ctxt___width 1
#define reg_dma_rw_ack_intr___ctxt___bit 1
#define reg_dma_rw_ack_intr___data___lsb 2
#define reg_dma_rw_ack_intr___data___width 1
#define reg_dma_rw_ack_intr___data___bit 2
#define reg_dma_rw_ack_intr___in_eop___lsb 3
#define reg_dma_rw_ack_intr___in_eop___width 1
#define reg_dma_rw_ack_intr___in_eop___bit 3
#define reg_dma_rw_ack_intr___stream_cmd___lsb 4
#define reg_dma_rw_ack_intr___stream_cmd___width 1
#define reg_dma_rw_ack_intr___stream_cmd___bit 4
#define reg_dma_rw_ack_intr_offset 144

/* Register r_intr, scope dma, type r */
#define reg_dma_r_intr___group___lsb 0
#define reg_dma_r_intr___group___width 1
#define reg_dma_r_intr___group___bit 0
#define reg_dma_r_intr___ctxt___lsb 1
#define reg_dma_r_intr___ctxt___width 1
#define reg_dma_r_intr___ctxt___bit 1
#define reg_dma_r_intr___data___lsb 2
#define reg_dma_r_intr___data___width 1
#define reg_dma_r_intr___data___bit 2
#define reg_dma_r_intr___in_eop___lsb 3
#define reg_dma_r_intr___in_eop___width 1
#define reg_dma_r_intr___in_eop___bit 3
#define reg_dma_r_intr___stream_cmd___lsb 4
#define reg_dma_r_intr___stream_cmd___width 1
#define reg_dma_r_intr___stream_cmd___bit 4
#define reg_dma_r_intr_offset 148

/* Register r_masked_intr, scope dma, type r */
#define reg_dma_r_masked_intr___group___lsb 0
#define reg_dma_r_masked_intr___group___width 1
#define reg_dma_r_masked_intr___group___bit 0
#define reg_dma_r_masked_intr___ctxt___lsb 1
#define reg_dma_r_masked_intr___ctxt___width 1
#define reg_dma_r_masked_intr___ctxt___bit 1
#define reg_dma_r_masked_intr___data___lsb 2
#define reg_dma_r_masked_intr___data___width 1
#define reg_dma_r_masked_intr___data___bit 2
#define reg_dma_r_masked_intr___in_eop___lsb 3
#define reg_dma_r_masked_intr___in_eop___width 1
#define reg_dma_r_masked_intr___in_eop___bit 3
#define reg_dma_r_masked_intr___stream_cmd___lsb 4
#define reg_dma_r_masked_intr___stream_cmd___width 1
#define reg_dma_r_masked_intr___stream_cmd___bit 4
#define reg_dma_r_masked_intr_offset 152

/* Register rw_stream_cmd, scope dma, type rw */
#define reg_dma_rw_stream_cmd___cmd___lsb 0
#define reg_dma_rw_stream_cmd___cmd___width 10
#define reg_dma_rw_stream_cmd___n___lsb 16
#define reg_dma_rw_stream_cmd___n___width 8
#define reg_dma_rw_stream_cmd___busy___lsb 31
#define reg_dma_rw_stream_cmd___busy___width 1
#define reg_dma_rw_stream_cmd___busy___bit 31
#define reg_dma_rw_stream_cmd_offset 156


/* Constants */
#define regk_dma_ack_pkt                          0x00000100
#define regk_dma_anytime                          0x00000001
#define regk_dma_array                            0x00000008
#define regk_dma_burst                            0x00000020
#define regk_dma_client                           0x00000002
#define regk_dma_copy_next                        0x00000010
#define regk_dma_copy_up                          0x00000020
#define regk_dma_data_at_eol                      0x00000001
#define regk_dma_dis_c                            0x00000010
#define regk_dma_dis_g                            0x00000020
#define regk_dma_idle                             0x00000001
#define regk_dma_intern                           0x00000004
#define regk_dma_load_c                           0x00000200
#define regk_dma_load_c_n                         0x00000280
#define regk_dma_load_c_next                      0x00000240
#define regk_dma_load_d                           0x00000140
#define regk_dma_load_g                           0x00000300
#define regk_dma_load_g_down                      0x000003c0
#define regk_dma_load_g_next                      0x00000340
#define regk_dma_load_g_up                        0x00000380
#define regk_dma_next_en                          0x00000010
#define regk_dma_next_pkt                         0x00000010
#define regk_dma_no                               0x00000000
#define regk_dma_only_at_wait                     0x00000000
#define regk_dma_restore                          0x00000020
#define regk_dma_rst                              0x00000001
#define regk_dma_running                          0x00000004
#define regk_dma_rw_cfg_default                   0x00000000
#define regk_dma_rw_cmd_default                   0x00000000
#define regk_dma_rw_intr_mask_default             0x00000000
#define regk_dma_rw_stat_default                  0x00000101
#define regk_dma_rw_stream_cmd_default            0x00000000
#define regk_dma_save_down                        0x00000020
#define regk_dma_save_up                          0x00000020
#define regk_dma_set_reg                          0x00000050
#define regk_dma_set_w_size1                      0x00000190
#define regk_dma_set_w_size2                      0x000001a0
#define regk_dma_set_w_size4                      0x000001c0
#define regk_dma_stopped                          0x00000002
#define regk_dma_store_c                          0x00000002
#define regk_dma_store_descr                      0x00000000
#define regk_dma_store_g                          0x00000004
#define regk_dma_store_md                         0x00000001
#define regk_dma_sw                               0x00000008
#define regk_dma_update_down                      0x00000020
#define regk_dma_yes                              0x00000001
#endif /* __dma_defs_asm_h */
