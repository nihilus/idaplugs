
/*****************************************************************************
 *                                                                           *
 *  pluginsn.cpp: ida plugins shared code                                    *
 *  (c) 2005-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#include "pluginsn.hpp"

bool is_type_insn(ea_t ea, bool(& typefunc)(ushort)) throw() {
	//_ASSERTE(isEnabled(ea));
	ea = get_item_head(ea);
	return isCode(get_flags_novalue(ea)) && ua_ana0(ea) > 0 && typefunc(cmd.itype);
}

bool is_call_insn(ushort itype) throw() {
	switch (ph.id) {
		case PLFM_386:
			return itype == NN_call || itype == NN_callni || itype == NN_callfi || itype == NN_syscall;
		case PLFM_Z80:
			return itype == Z80_call || itype == I5_call || itype == Z80_calr;
		case PLFM_I860:
			return itype == I860_call || itype == I860_calli;
		case PLFM_8051:
			return itype == I51_acall || itype == I51_lcall || itype == I51_ecall;
		case PLFM_TMS:
			return itype >= TMS_cala && itype <= TMS_ccd || itype == TMS2_cala || itype == TMS2_call;
		case PLFM_6502:
			return itype == M65_jsr;
		case PLFM_PDP:
			return itype == pdp_jsr || itype == pdp_call;
		case PLFM_68K:
			return itype == mc8_jsr;
		case PLFM_JAVA:
			return itype == j_jsr || itype == j_jsr_w;
		case PLFM_6800:
			return itype == mc_bsr || itype == mc_callm;
		case PLFM_ST7:
			return itype == ST7_call || itype == ST7_callr;
		case PLFM_MC6812:
			return itype == MC12_call || itype == MC12_jsr || itype == MC12_bsr;
		case PLFM_MIPS:
			return itype == MIPS_syscall;
// 		case PLFM_ARM:
// 		case PLFM_TMSC6:
		case PLFM_PPC:
			return itype == PPC_sc;
		case PLFM_80196:
			return itype == I196_lcall || itype == I196_scall || itype == I196_ecall;
		case PLFM_Z8:
			return itype == Z8_call;
		case PLFM_SH:
			return itype == SH3_bsr || itype == SH3_bsrf;
		case PLFM_NET:
			return itype == NET_call || itype == NET_calli || itype == NET_callvirt || itype == NET_ann_call /*|| itype == NET_ann_hoisted || itype == NET_ann_hoisted_call*/;
		case PLFM_AVR:
			return itype == AVR_rcall || itype == AVR_icall || itype == AVR_call;
		case PLFM_H8:
			return itype == H8_bsr;
		case PLFM_PIC:
			return itype == PIC_call || itype == PIC_call2 || itype == PIC_rcall1;
		case PLFM_SPARC:
			return itype == SPARC_call;
		case PLFM_ALPHA:
			return itype == ALPHA_call_pal || itype == ALPHA_jsr || itype == ALPHA_bsr/* || itype == ALPHA_jsr_coroutine*/;
		case PLFM_HPPA:
			return itype == HPPA_call;
		case PLFM_H8500:
			return itype == H8500_bsr || itype == H8500_jsr || itype == H8500_pjsr;
// 		case PLFM_TRICORE:
		case PLFM_DSP56K:
			return itype == DSP56_jscc || itype == DSP56_jsclr || itype == DSP56_jsr || itype == DSP56_jsset || itype == DSP56_bsr || itype == DSP56_bsset;
		case PLFM_C166:
			return itype == C166_calla || itype == C166_calli || itype == C166_callr || itype == C166_calls || itype == C166_pcall;
		case PLFM_ST20:
			return itype == ST20_call || itype == ST20_gcall || itype == ST20_ecall || itype == ST20_fcall;
		case PLFM_IA64:
			return itype == IA64_call;
		case PLFM_I960:
			return itype == I960_call || itype == I960_calls || itype == I960_callx;
		case PLFM_F2MC:
			return itype == F2MC_call || itype == F2MC_callv || itype == F2MC_callp;
		case PLFM_TMS320C54:
			return itype >= TMS320C54_cala && itype <= TMS320C54_fcalld;
		case PLFM_TMS320C55:
			return itype == TMS320C55_callcc || itype == TMS320C55_call;
// 		case PLFM_TRIMEDIA:
// 		case PLFM_M32R:
		case PLFM_NEC_78K0:
			return itype == NEC_78K_0_call || itype == NEC_78K_0_callf || itype == NEC_78K_0_callt;
		case PLFM_NEC_78K0S:
			return itype == NEC_78K_0S_call || itype == NEC_78K_0S_callt;
		case PLFM_M740:
			return itype == m740_jsr;
		case PLFM_M7700:
			return itype == m7700_jsr;
		case PLFM_ST9:
			return itype == st9_call || itype == st9_calls;
		case PLFM_FR:
			return itype == fr_call;
		case PLFM_MC6816:
			return itype == MC6816_bsr || itype == MC6816_jsr || itype == MC6816_lbsr;
		case PLFM_M7900:
			return itype == m7900_jsr || itype == m7900_jsrl;
		case PLFM_TMS320C3:
			return itype == TMS320C3X_CALL || itype == TMS320C3X_CALLcond;
		case PLFM_KR1878:
			return itype == KR1878_jsr || itype == KR1878_ijsr;
		case PLFM_AD218X:
			return itype == AD218X_call || itype == AD218X_call_1 || itype == AD218X_call_2;
	}
	return false;
}

bool is_jump_insn(ushort itype) throw() {
	switch (ph.id) {
		case PLFM_386:
			return itype >= NN_ja && itype <= NN_jmpshort;
		case PLFM_Z80:
			return itype >= I5_jmp && itype <= I5_jp || itype == I5_jx5 || itype == I5_jnx5;
// 		case PLFM_I860:
		case PLFM_8051:
			return itype == I51_ajmp || itype >= I51_jb && itype <= I51_jz || itype == I51_ljmp || itype == I51_sjmp || itype >= I51_jsle && itype <= I51_jne || itype == I51_ejmp;
		case PLFM_TMS:
			return itype >= TMS_b && itype <= TMS_bd || itype >= TMS2_b && itype <= TMS2_bioz || itype == TMS2_blez || itype >= TMS2_blz && itype <= TMS2_bz;
		case PLFM_6502:
			return itype == M65_jmp || itype == M65_jmpi || itype >= M65_bbr0 && itype <= M65_bbs7 || itype == M65_bra;
		case PLFM_PDP:
			return itype == pdp_jmp || itype >= pdp_br && itype <= pdp_ble || itype >= pdp_bpl && itype <= pdp_bcs;
		case PLFM_68K:
			return itype == mc8_jmp || itype == mc8_bcc || itype >= mc8_bcs && itype <= mc8_bil || itype >= mc8_ble && itype <= mc8_brset || itype == mc8_bsr || itype == mc8_bvc || itype == mc8_bvs;
		case PLFM_JAVA:
			return itype >= j_ifeq && itype <= j_goto || itype == j_ifnull || itype == j_ifnonnull || itype == j_goto_w || itype == j_tableswitch || itype == j_lookupswitch;
		case PLFM_6800:
			return itype == mc_jmp || itype == mc_b || itype == mc_bra;
		case PLFM_ST7:
			return itype == ST7_btjf || itype == ST7_btjt || itype >= ST7_jp && itype <= ST7_jrule;
		case PLFM_MC6812:
			return itype == MC12_jmp || itype >= MC12_lbcc && itype <= MC12_lbvs || itype == MC12_bcc && itype == MC12_bcs || itype == MC12_beq || itype == MC12_bge || itype == MC12_bgt || itype == MC12_bhi || itype == MC12_bhs || itype >= MC12_ble && itype <= MC12_brset || itype == MC12_bvc || itype == MC12_bvs || itype == MC12_dbeq || itype == MC12_dbne || itype == MC12_ibeq || itype == MC12_ibne || itype >= MC12_lbcc && itype <= MC12_lbvs || itype == MC12_tbeq || itype == MC12_tbne;
		case PLFM_MIPS:
			return itype >= MIPS_bc0f && itype <= MIPS_jalx || itype >= MIPS_bnez && itype <= MIPS_bal || itype == MIPS16_b || itype == MIPS16_beqz || itype == MIPS16_bnez || itype == MIPS16_bteqz || itype == MIPS16_btnez || itype == MIPS_break;
		case PLFM_ARM:
			return itype == ARM_ldrpc || itype == ARM_b || itype == ARM_bl || itype == ARM_bx /* ?? */ || itype == ARM_blx1 /* ?? */ || itype == ARM_blx2 /* ?? */;
		case PLFM_TMSC6:
			return itype == TMS6_b;
		case PLFM_PPC:
			return itype == PPC_b || itype == PPC_bc || itype == PPC_bcctr || itype == PPC_bclr || itype >= PPC_balways && itype <= PPC_bns;
		case PLFM_80196:
			return itype == I196_djnz || itype == I196_djnzw || itype >= I196_jbc && itype <= I196_jvt || itype == I196_ljmp || itype == I196_sjmp || itype == I196_tijmp || itype == I196_ejmp || itype == I196_br || itype == I196_ebr;
		case PLFM_Z8:
			return itype == Z8_djnz || itype >= Z8_jp && itype <= Z8_jrcond;
		case PLFM_SH:
			return itype == SH3_jmp || itype == SH3_jsr || itype >= SH3_bf && itype <= SH3_braf || itype == SH3_bt || itype == SH3_bt_s;
		case PLFM_NET:
			return itype == NET_jmp || itype == NET_switch || itype >= NET_beq && itype <= NET_bne_un_s || itype >= NET_br && itype <= NET_brtrue_s;
		case PLFM_AVR:
			return itype == AVR_rjmp || itype == AVR_ijmp || itype == AVR_jmp || itype >= AVR_cpse && itype <= AVR_brid;
		case PLFM_H8:
			return itype == H8_jmp || itype == H8_jsr || itype >= H8_bra && itype <= H8_ble;
		case PLFM_PIC:
			return itype == PIC_b || itype >= PIC_skpc && itype <= PIC_bz || itype >= PIC_bc1 && itype <= PIC_bz1;
		case PLFM_SPARC:
			return itype == SPARC_jmp || itype == SPARC_jmpl || itype == SPARC_b || itype == SPARC_bp || itype == SPARC_bpr || itype == SPARC_fbp || itype == SPARC_fb;
		case PLFM_ALPHA:
			return itype == ALPHA_jmp || itype == ALPHA_beq || itype == ALPHA_bge || itype == ALPHA_bgt || itype >= ALPHA_blbc && itype <= ALPHA_br || itype >= ALPHA_fbeq && itype <= ALPHA_fbne || itype == ALPHA_br0;
		case PLFM_HPPA:
			return itype == HPPA_addb || itype == HPPA_addib || itype >= HPPA_b && itype <= HPPA_bve || itype == HPPA_cmpb || itype == HPPA_cmpib || itype == HPPA_movb || itype == HPPA_movib || itype == HPPA_break;
		case PLFM_H8500:
			return itype >= H8500_bra && itype <= H8500_pjmp;
// 		case PLFM_TRICORE:
		case PLFM_DSP56K:
			return itype == DSP56_jcc || itype == DSP56_jclr || itype == DSP56_jmp || itype == DSP56_jset || itype == DSP56_bcc || itype == DSP56_bra || itype == DSP56_brclr || itype == DSP56_brset || itype == DSP56_bscc || itype == DSP56_bsclr || itype == DSP56_brkcc || itype == DSP56_enddo;
		case PLFM_C166:
			return itype >= C166_jb && itype <= C166_jnbs;
		case PLFM_ST20:
			return itype == ST20_cj || itype == ST20_j || itype == ST20_jab || itype == ST20_lend;
		case PLFM_IA64:
			return itype == IA64_br || itype == IA64_break || itype == IA64_brl || itype == IA64_brp || itype == IA64_break;
		case PLFM_I960:
			return itype >= I960_b && itype <= I960_bx || itype >= I960_cmpibno && itype <= I960_cmpibo || itype >= I960_cmpobg && itype <= I960_cmpoble;
		case PLFM_F2MC:
			return itype >= F2MC_bz && itype <= F2MC_jmpp || itype >= F2MC_cbne && itype <= F2MC_dwbnz || itype == F2MC_jctx || itype == F2MC_bbc || itype == F2MC_bbs || itype == F2MC_sbbs || itype >= F2MC_bz16 && itype <= F2MC_sbbs16;
		case PLFM_TMS320C54:
			return itype >= TMS320C54_b && itype <= TMS320C54_fbaccd;
		case PLFM_TMS320C55:
			return itype == TMS320C55_bcc || itype == TMS320C55_bccu || itype == TMS320C55_b;
		case PLFM_TRIMEDIA:
			return itype >= TRIMEDIA_jmpt && itype <= TRIMEDIA_ijmpf;
		case PLFM_M32R:
			return itype == m32r_jl || itype == m32r_jmp || itype >= m32r_bc && itype <= m32r_bra || itype == m32rx_jc || itype == m32rx_jnc;
		case PLFM_NEC_78K0:
			return itype >= NEC_78K_0_br && itype <= NEC_78K_0_dbnz;
		case PLFM_NEC_78K0S:
			return itype >= NEC_78K_0S_br && itype <= NEC_78K_0S_dbnz;
		case PLFM_M740:
			return itype == m740_jmp || itype == m740_bbc || itype == m740_bbs || itype == m740_bcc || itype == m740_bcs || itype == m740_beq || itype == m740_bmi || itype == m740_bne || itype == m740_bpl || itype == m740_bra || itype == m740_brk || itype == m740_bvc || itype == m740_bvs;
		case PLFM_M7700:
			return itype == m7700_jmp || itype >= m7700_bbc && itype <= m7700_bvs;
		case PLFM_ST9:
			return itype == st9_jrcc || itype == st9_jpcc || itype == st9_jp || itype == st9_jps || itype >= st9_btjf && itype <= st9_cpjti;
		case PLFM_FR:
			return itype == fr_jmp || itype >= fr_bra && itype <= fr_bhi;
		case PLFM_MC6816:
			return itype >= MC6816_bra && itype <= MC6816_jmp;
		case PLFM_M7900:
			return itype == m7900_jmp || itype == m7900_jmpl || itype >= m7900_bbc && itype <= m7900_cbneb || itype == m7900_debne || itype == m7900_dxbne || itype == m7900_dybne;
		case PLFM_TMS320C3:
			return itype == TMS320C3X_BR || itype == TMS320C3X_BRD || itype == TMS320C3X_Bcond || itype == TMS320C3X_DBcond;
		case PLFM_KR1878:
			return itype == KR1878_jmp || itype >= KR1878_jnz && itype <= KR1878_ijmp;
		case PLFM_AD218X:
			return itype >= AD218X_jump && itype <= AD218X_jump_4;
	}
	return false;
}

bool is_ret_insn(ushort itype) throw() {
	switch (ph.id) {
		case PLFM_386:
			return itype == NN_retn || itype == NN_retf || itype >= NN_iretw && itype <= NN_iretq || itype == NN_sysret;
		case PLFM_Z80:
			return itype == I5_ret || itype == Z80_ret || itype == Z80_reti || itype == Z80_retn;
// 		case PLFM_I860:
		case PLFM_8051:
			return itype == I51_ret || itype == I51_reti || itype == I51_eret;
		case PLFM_TMS:
			return itype == TMS_ret || itype == TMS_retc || itype == TMS_retcd || itype == TMS_retd || itype == TMS_reti || itype == TMS2_ret;
		case PLFM_6502:
			return itype == M65_rti || itype == M65_rts;
		case PLFM_PDP:
			return itype == pdp_rti || itype == pdp_rtt || itype == pdp_rts || itype == pdp_mark || itype == pdp_return;
// 		case PLFM_68K:
		case PLFM_JAVA:
			return itype == j_ret || itype == j_ireturn || itype == j_lreturn || itype == j_freturn || itype == j_dreturn || itype == j_areturn || itype == j_return;
		case PLFM_6800:
			return itype == mc_rte || itype == mc_rtr || itype == mc_rts;
		case PLFM_ST7:
			return itype == ST7_ret || itype == ST7_iret;
		case PLFM_MC6812:
			return itype == MC12_rtc || itype == MC12_rti || itype == MC12_rts;
		case PLFM_MIPS:
			return itype == MIPS_eret;
		case PLFM_ARM:
			return itype == ARM_ret;
// 		case PLFM_TMSC6:
		case PLFM_PPC:
			return itype == PPC_rfi || itype == PPC_rfid || itype == PPC_rfci;
		case PLFM_80196:
			return itype == I196_ret;
		case PLFM_Z8:
			return itype == Z8_ret || itype == Z8_iret;
		case PLFM_SH:
			return itype == SH3_rte || itype == SH3_rts;
		case PLFM_NET:
			return itype == NET_ret;
		case PLFM_AVR:
			return itype == AVR_ret || itype == AVR_reti;
		case PLFM_H8:
			return itype == H8_rte || itype == H8_rts;
		case PLFM_PIC:
			return itype == PIC_retfie || itype == PIC_retlw || itype == PIC_return || itype == PIC_retfie1 || itype == PIC_return1;
		case PLFM_SPARC:
			return itype == SPARC_done || itype == SPARC_retry || itype == SPARC_return || itype == SPARC_ret || itype == SPARC_retl || itype == SPARC_rett;
		case PLFM_ALPHA:
			return itype == ALPHA_ret;
		case PLFM_HPPA:
			return itype == HPPA_ret || itype == HPPA_rfi;
		case PLFM_H8500:
			return itype == H8500_rts || itype == H8500_prts || itype == H8500_rtd || itype == H8500_prtd || itype == H8500_rte;
// 		case PLFM_TRICORE:
		case PLFM_DSP56K:
			return itype == DSP56_rti || itype == DSP56_rts;
		case PLFM_C166:
			return itype == C166_ret || itype == C166_reti || itype == C166_retp || itype == C166_rets;
		case PLFM_ST20:
			return itype == ST20_ret || itype == ST20_eret || itype == ST20_iret || itype == ST20_tret;
		case PLFM_IA64:
			return itype == IA64_ret || itype == IA64_rfi;
		case PLFM_I960:
			return itype == I960_ret;
		case PLFM_F2MC:
			return itype == F2MC_ret || itype == F2MC_retp || itype == F2MC_reti;
		case PLFM_TMS320C54:
			return itype >= TMS320C54_fret && itype <= TMS320C54_retfd;
		case PLFM_TMS320C55:
			return itype == TMS320C55_retcc || itype == TMS320C55_ret || itype == TMS320C55_reti;
// 		case PLFM_TRIMEDIA:
		case PLFM_M32R:
			return itype == m32r_rte;
		case PLFM_NEC_78K0:
			return itype == NEC_78K_0_ret || itype == NEC_78K_0_retb || itype == NEC_78K_0_reti;
		case PLFM_NEC_78K0S:
			return itype == NEC_78K_0S_ret || itype == NEC_78K_0S_reti;
		case PLFM_M740:
			return itype == m740_rti || itype == m740_rts;
		case PLFM_M7700:
			return itype == m7700_rti || itype == m7700_rtl || itype == m7700_rts;
		case PLFM_ST9:
			return itype == st9_ret || itype == st9_rets || itype == st9_iret || itype == st9_eret;
		case PLFM_FR:
			return itype == fr_ret || itype == fr_reti;
		case PLFM_MC6816:
			return itype == MC6816_rts || itype == MC6816_rti;
		case PLFM_M7900:
			return itype == m7900_rti || itype == m7900_rtl || itype == m7900_rtld || itype == m7900_rts || itype == m7900_rtsdn;
		case PLFM_TMS320C3:
			return itype == TMS320C3X_RETIcond || itype == TMS320C3X_RETScond || itype == TMS320C3X_RETIU || itype == TMS320C3X_RETSU;
		case PLFM_KR1878:
			return itype == KR1878_rts || itype == KR1878_rtsc || itype == KR1878_rti;
		case PLFM_AD218X:
			return itype == AD218X_rts || itype == AD218X_rts_cond || itype == AD218X_rti || itype == AD218X_rti_cond;
	}
	return false;
}

bool is_loop_insn(ushort itype) throw() {
	switch (ph.id) {
		case PLFM_386:
			return itype >= NN_loopw && itype <= NN_loopqne;
// 		case PLFM_Z80:
// 		case PLFM_I860:
// 		case PLFM_8051:
// 		case PLFM_TMS:
// 		case PLFM_6502:
// 		case PLFM_PDP:
// 		case PLFM_68K:
// 		case PLFM_JAVA:
// 		case PLFM_6800:
// 		case PLFM_ST7:
// 		case PLFM_MC6812:
// 		case PLFM_MIPS:
// 		case PLFM_ARM:
// 		case PLFM_TMSC6:
// 		case PLFM_PPC:
// 		case PLFM_80196:
// 		case PLFM_Z8:
// 		case PLFM_SH:
// 		case PLFM_NET:
// 		case PLFM_AVR:
// 		case PLFM_H8:
// 		case PLFM_PIC:
// 		case PLFM_SPARC:
// 		case PLFM_ALPHA:
// 		case PLFM_HPPA:
		case PLFM_H8500:
			return itype == H8500_scb;
// 		case PLFM_TRICORE:
// 		case PLFM_DSP56K:
// 		case PLFM_C166:
		case PLFM_ST20:
			return itype == ST20_smacloop;
		case PLFM_IA64:
			return itype == IA64_loop || itype == IA64_cloop;
// 		case PLFM_I960:
// 		case PLFM_F2MC:
// 		case PLFM_TMS320C54:
// 		case PLFM_TMS320C55:
// 		case PLFM_TRIMEDIA:
// 		case PLFM_M32R:
		case PLFM_NEC_78K0:
			return itype == NEC_78K_0_dbnz;
		case PLFM_NEC_78K0S:
			return itype == NEC_78K_0S_dbnz;
// 		case PLFM_M740:
// 		case PLFM_M7700:
// 		case PLFM_ST9:
// 		case PLFM_FR:
// 		case PLFM_MC6816:
// 		case PLFM_M7900:
// 		case PLFM_TMS320C3:
// 		case PLFM_KR1878:
// 		case PLFM_AD218X:
	}
	return false;
}

bool is_push_insn(ushort itype) throw() {
	switch (ph.id) {
		case PLFM_386:
			return itype >= NN_push && itype <= NN_pushfq;
		case PLFM_Z80:
			return itype == I5_push || itype == Z80_push;
// 		case PLFM_I860:
		case PLFM_8051:
			return itype == I51_push;
		case PLFM_TMS:
			return itype == TMS_pshd || itype == TMS_push || itype == TMS2_pshd || itype == TMS2_push;
		case PLFM_6502:
			return itype == M65_phy || itype == M65_phx;
// 		case PLFM_PDP:
		case PLFM_68K:
			return itype >= mc8_psh && itype <= mc8_pshx;
		case PLFM_JAVA:
			return itype >= j_aconst_null && itype <= j_saload;
// 		case PLFM_6800:
		case PLFM_ST7:
			return itype == ST7_push;
		case PLFM_MC6812:
			return itype >= MC12_psha && itype <= MC12_pshy;
// 		case PLFM_MIPS:
		case PLFM_ARM:
			return itype == ARM_push;
// 		case PLFM_TMSC6:
// 		case PLFM_PPC:
		case PLFM_80196:
			return itype == I196_push || itype == I196_pusha || itype == I196_pushf;
		case PLFM_Z8:
			return itype == Z8_push;
// 		case PLFM_SH:
		case PLFM_NET:
			return itype == NET_ceq || itype == NET_cgt || itype == NET_cgt_un || itype == NET_clt || itype == NET_clt_un || itype == NET_conv_i || itype == NET_conv_i1 || itype == NET_conv_i2 || itype == NET_conv_i4 || itype == NET_conv_i8 || itype == NET_conv_r4 || itype == NET_conv_r8 || itype == NET_conv_r_un || itype == NET_conv_u || itype == NET_conv_u1 || itype == NET_conv_u2 || itype == NET_conv_u4 || itype == NET_conv_u8 || itype >= NET_ldc_i4 && itype <= NET_ldstr || itype == NET_mkrefany || itype == NET_refanytype || itype == NET_refanyval || itype == NET_sizeof;
		case PLFM_AVR:
			return itype == AVR_push;
		case PLFM_H8:
			return itype == H8_push;
		case PLFM_PIC:
			return itype == PIC_push0;
// 		case PLFM_SPARC:
// 		case PLFM_ALPHA:
		case PLFM_HPPA:
			return itype == HPPA_pushbts || itype == HPPA_pushnom;
		case PLFM_H8500:
			return itype == H8500_stm;
// 		case PLFM_TRICORE:
// 		case PLFM_DSP56K:
		case PLFM_C166:
			return itype == C166_push;
// 		case PLFM_ST20:
// 		case PLFM_IA64:
// 		case PLFM_I960:
		case PLFM_F2MC:
			return itype == F2MC_pushw;
		case PLFM_TMS320C54:
			return itype == TMS320C54_pshd || itype == TMS320C54_pshm;
		case PLFM_TMS320C55:
			return itype == TMS320C55_psh1 || itype == TMS320C55_psh2 || itype == TMS320C55_pshboth;
// 		case PLFM_TRIMEDIA:
		case PLFM_M32R:
			return itype == m32r_push;
		case PLFM_NEC_78K0:
			return itype == NEC_78K_0_push;
		case PLFM_NEC_78K0S:
			return itype == NEC_78K_0S_push;
		case PLFM_M740:
			return itype == m740_pha || itype == m740_php;
		case PLFM_M7700:
			return itype == m7700_psh || itype >= m7700_pea && itype <= m7700_phy;
		case PLFM_ST9:
			return itype == st9_push || itype == st9_pushw || itype == st9_pea || itype == st9_pushu || itype == st9_pushuw || itype == st9_peau;
// 		case PLFM_FR:
		case PLFM_MC6816:
			return itype == MC6816_psha || itype == MC6816_pshb || itype == MC6816_pshm || itype == MC6816_pshmac;
		case PLFM_M7900:
			return itype == m7900_psh || itype >= m7900_pea || itype <= m7900_phy;
		case PLFM_TMS320C3:
			return itype == TMS320C3X_PUSH || itype == TMS320C3X_PUSHF;
		case PLFM_KR1878:
			return itype == KR1878_push;
// 		case PLFM_AD218X:
	}
	return false;
}

bool is_pop_insn(ushort itype) throw() {
	switch (ph.id) {
		case PLFM_386:
			return itype >= NN_pop && itype <= NN_popfq;
		case PLFM_Z80:
			return itype == I5_pop || itype == Z80_pop;
// 		case PLFM_I860:
		case PLFM_8051:
			return itype == I51_pop;
		case PLFM_TMS:
			return itype == TMS_pop || itype == TMS_popd || itype == TMS2_pop || itype == TMS2_popd;
		case PLFM_6502:
			return itype == M65_ply || itype == M65_plx;
// 		case PLFM_PDP:
		case PLFM_68K:
			return itype >= mc8_pul && itype <= mc8_pulx;
		case PLFM_JAVA:
			return itype >= j_istore && itype <= j_pop2;
// 		case PLFM_6800:
		case PLFM_ST7:
			return itype == ST7_pop;
		case PLFM_MC6812:
			return itype >= MC12_pula && itype <= MC12_puly;
// 		case PLFM_MIPS:
		case PLFM_ARM:
			return itype == ARM_pop;
// 		case PLFM_TMSC6:
// 		case PLFM_PPC:
		case PLFM_80196:
			return itype == I196_pop || itype == I196_popa || itype == I196_popf;
		case PLFM_Z8:
			return itype == Z8_pop;
// 		case PLFM_SH:
		case PLFM_NET:
			return itype == NET_pop || itype >= NET_stloc && itype <= NET_stloc_s;
		case PLFM_AVR:
			return itype == AVR_pop;
		case PLFM_H8:
			return itype == H8_pop;
		case PLFM_PIC:
			return itype == PIC_pop0;
// 		case PLFM_SPARC:
// 		case PLFM_ALPHA:
		case PLFM_HPPA:
			return itype == HPPA_popbts; /* ?? */
		case PLFM_H8500:
			return itype == H8500_ldm;
// 		case PLFM_TRICORE:
// 		case PLFM_DSP56K:
		case PLFM_C166:
			return itype == C166_pop;
		case PLFM_ST20:
			return itype == ST20_pop;
// 		case PLFM_IA64:
// 		case PLFM_I960:
		case PLFM_F2MC:
			return itype == F2MC_popw;
		case PLFM_TMS320C54:
			return itype == TMS320C54_popd || itype == TMS320C54_popm;
		case PLFM_TMS320C55:
			return itype == TMS320C55_pop1 || itype == TMS320C55_pop2 || itype == TMS320C55_popboth;
// 		case PLFM_TRIMEDIA:
		case PLFM_M32R:
			return itype == m32r_pop;
		case PLFM_NEC_78K0:
			return itype == NEC_78K_0_pop;
		case PLFM_NEC_78K0S:
			return itype == NEC_78K_0S_pop;
		case PLFM_M740:
			return itype == m740_pla || itype == m740_plp;
		case PLFM_M7700:
			return itype >= m7700_pla && itype <= m7700_ply || itype == m7700_pul;
		case PLFM_ST9:
			return itype == st9_pop || itype == st9_popw || itype == st9_popu || itype == st9_popuw;
// 		case PLFM_FR:
		case PLFM_MC6816:
			return itype == MC6816_pula || itype == MC6816_pulb || itype == MC6816_pulm || itype == MC6816_pulmac;
		case PLFM_M7900:
			return itype >= m7900_pla && itype <= m7900_ply || itype == m7900_pul;
		case PLFM_TMS320C3:
			return itype == TMS320C3X_POP || itype == TMS320C3X_POPF;
		case PLFM_KR1878:
			return itype == KR1878_pop;
// 		case PLFM_AD218X:
	}
	return false;
}

bool is_nop_insn(ushort itype) throw() {
	switch (ph.id) {
		case PLFM_386:
			return itype == NN_nop || itype == NN_fnop;
		case PLFM_Z80:
			return itype == I5_nop;
// 		case PLFM_I860:
		case PLFM_8051:
			return itype == I51_nop;
		case PLFM_TMS:
			return itype == TMS_nop || itype == TMS2_nop;
		case PLFM_6502:
			return itype == M65_nop;
		case PLFM_PDP:
			return itype == pdp_nop;
		case PLFM_68K:
			return itype == mc8_nop;
		case PLFM_JAVA:
			return itype == j_nop;
		case PLFM_6800:
			return itype == mc_nop || itype == mc_fnop;
		case PLFM_ST7:
			return itype == ST7_nop;
		case PLFM_MC6812:
			return itype == MC12_nop;
		case PLFM_MIPS:
			return itype == MIPS_nop || itype == MIPS16_nop;
		case PLFM_ARM:
			return itype == ARM_nop;
		case PLFM_TMSC6:
			return itype == TMS6_nop || itype == TMS6_idle;
		case PLFM_PPC:
			return itype == PPC_nop;
		case PLFM_80196:
			return itype == I196_nop;
		case PLFM_Z8:
			return itype == Z8_nop;
		case PLFM_SH:
			return itype == SH3_nop;
		case PLFM_NET:
			return itype == NET_nop;
		case PLFM_AVR:
			return itype == AVR_nop;
		case PLFM_H8:
			return itype == H8_nop;
		case PLFM_PIC:
			return itype == PIC_nop;
		case PLFM_SPARC:
			return itype == SPARC_nop;
		case PLFM_ALPHA:
			return itype == ALPHA_unop || itype == ALPHA_nop || itype == ALPHA_fnop;
		case PLFM_HPPA:
			return itype == HPPA_nop;
		case PLFM_H8500:
			return itype == H8500_nop;
// 		case PLFM_TRICORE:
		case PLFM_DSP56K:
			return itype == DSP56_nop;
		case PLFM_C166:
			return itype == C166_nop || itype == ST10_CoNOP;
		case PLFM_ST20:
			return itype == ST20_nop;
		case PLFM_IA64:
			return itype == IA64_nop;
// 		case PLFM_I960:
		case PLFM_F2MC:
			return itype == F2MC_nop;
		case PLFM_TMS320C54:
			return itype == TMS320C54_nop;
		case PLFM_TMS320C55:
			return itype == TMS320C55_nop || itype == TMS320C55_nop_16;
		case PLFM_TRIMEDIA:
			return itype == TRIMEDIA_nop;
		case PLFM_M32R:
			return itype == m32r_nop;
		case PLFM_NEC_78K0:
			return itype == NEC_78K_0_nop;
		case PLFM_NEC_78K0S:
			return itype == NEC_78K_0S_nop;
		case PLFM_M740:
			return itype == m740_nop;
		case PLFM_M7700:
			return itype == m7700_nop;
		case PLFM_ST9:
			return itype == st9_nop;
		case PLFM_FR:
			return itype == fr_nop;
		case PLFM_MC6816:
			return itype == MC6816_nop;
		case PLFM_M7900:
			return itype == m7900_nop;
		case PLFM_TMS320C3:
			return itype == TMS320C3X_NOP;
		case PLFM_KR1878:
			return itype == KR1878_nop;
		case PLFM_AD218X:
			return itype == AD218X_nop;
	}
	return false;
}

bool is_bpt_insn(ushort itype) throw() {
	switch (ph.id) {
		case PLFM_386:
			return itype == NN_icebp;
// 		case PLFM_Z80:
// 		case PLFM_I860:
// 		case PLFM_8051:
// 		case PLFM_TMS:
// 		case PLFM_6502:
		case PLFM_PDP:
			return itype == pdp_bpt;
// 		case PLFM_68K:
		case PLFM_JAVA:
			return itype == j_breakpoint;
// 		case PLFM_6800:
// 		case PLFM_ST7:
// 		case PLFM_MC6812:
		case PLFM_MIPS:
			return itype == MIPS16_break;
		case PLFM_ARM:
			return itype == ARM_bkpt || itype == ARM_swbkpt;
// 		case PLFM_TMSC6:
// 		case PLFM_PPC:
// 		case PLFM_80196:
// 		case PLFM_Z8:
// 		case PLFM_SH:
		case PLFM_NET:
			return itype == NET_break;
// 		case PLFM_AVR:
// 		case PLFM_H8:
// 		case PLFM_PIC:
// 		case PLFM_SPARC:
// 		case PLFM_ALPHA:
// 		case PLFM_HPPA:
		case PLFM_H8500:
			return itype == H8500_bpt;
// 		case PLFM_TRICORE:
// 		case PLFM_DSP56K:
// 		case PLFM_C166:
		case PLFM_ST20:
			return itype == ST20_breakpoint;
// 		case PLFM_IA64:
// 		case PLFM_I960:
// 		case PLFM_F2MC:
// 		case PLFM_TMS320C54:
// 		case PLFM_TMS320C55:
// 		case PLFM_TRIMEDIA:
// 		case PLFM_M32R:
		case PLFM_NEC_78K0:
			return itype == NEC_78K_0_brk;
// 		case PLFM_NEC_78K0S:
// 		case PLFM_M740:
// 		case PLFM_M7700:
// 		case PLFM_ST9:
// 		case PLFM_FR:
// 		case PLFM_MC6816:
// 		case PLFM_M7900:
// 		case PLFM_TMS320C3:
// 		case PLFM_KR1878:
// 		case PLFM_AD218X:
	}
	return false;
}
