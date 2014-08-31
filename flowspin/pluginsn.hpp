
/*****************************************************************************
 *                                                                           *
 *  pluginsn.hpp: ida plugins shared code                                    *
 *  (c) 2005-2008 servil                                                     *
 *                                                                           *
 *****************************************************************************/

#ifndef _PLUGINSN_HPP_
#define _PLUGINSN_HPP_ 1

#include "undbgnew.h"
#include "mscrtdbg.h"
#include "idasdk.hpp"
#include "dbgnew.h"

// instruction classification routines
#define DEFINE_IS_INSN(type, condition) \
	inline bool is_##type##_insn(ushort itype) throw() \
		{ return condition; } \
	inline bool is_##type##_insn() throw() \
		{ return is_##type##_insn(cmd.itype); } \
	inline bool is_##type##_insn(ea_t ea) throw() \
		{ return is_type_insn(ea, is_##type##_insn); }
#define DECLARE_IS_INSN(type) \
	bool is_##type##_insn(ushort itype) throw(); \
	inline bool is_##type##_insn() throw() \
		{ return is_##type##_insn(cmd.itype); } \
	inline bool is_##type##_insn(ea_t ea) throw() \
		{ return is_type_insn(ea, is_##type##_insn); }

bool is_type_insn(ea_t ea, bool(& typefunc)(ushort)) throw();
// all platforms
bool is_call_insn(ushort itype) throw();
inline bool is_call_insn() throw() { return is_call_insn(cmd.itype); }
#if IDP_INTERFACE_VERSION < 76
DECLARE_IS_INSN(ret)
#else // IDP_INTERFACE_VERSION >= 76
bool is_ret_insn(ushort itype) throw();
inline bool is_ret_insn() throw() { return is_ret_insn(cmd.itype); }
#endif // IDP_INTERFACE_VERSION
DECLARE_IS_INSN(jump)
DECLARE_IS_INSN(loop)
DEFINE_IS_INSN(flowchange, is_call_insn(itype) || is_ret_insn(itype)
	|| is_jump_insn(itype) || is_loop_insn(itype)/* || is_int_insn(itype)*/)
DECLARE_IS_INSN(push)
DECLARE_IS_INSN(pop)
DECLARE_IS_INSN(nop)
DECLARE_IS_INSN(bpt)
// ix86 only atm.
DEFINE_IS_INSN(enter, ph.id == PLFM_386 && itype >= NN_enterw && itype <= NN_enterq)
DEFINE_IS_INSN(leave, ph.id == PLFM_386 && itype >= NN_leavew && itype <= NN_leaveq)
DEFINE_IS_INSN(mov, ph.id == PLFM_386 && (itype == NN_mov || itype == NN_movsp || itype == NN_movsx
	|| itype == NN_movzx || itype >= NN_cmova && itype <= NN_fcmovnu))
DEFINE_IS_INSN(int, ph.id == PLFM_386 && itype >= NN_int && itype <= NN_iretq)
DEFINE_IS_INSN(set, ph.id == PLFM_386 && itype >= NN_seta && itype <= NN_setz)
DEFINE_IS_INSN(rep, ph.id == PLFM_386 && itype >= NN_rep && itype <= NN_repne)
DEFINE_IS_INSN(rot, ph.id == PLFM_386 && (itype == NN_rcl || itype == NN_rcr || itype == NN_rol
	|| itype == NN_ror || itype == NN_sal || itype == NN_sar || itype == NN_shl
	|| itype == NN_shr))
DEFINE_IS_INSN(multiply, ph.id == PLFM_386 && (itype == NN_imul || itype == NN_mul || itype == NN_fmul
	|| itype == NN_fmul || itype == NN_fimul || itype == NN_pmaddwd
	|| itype == NN_pmulhw || itype == NN_pmullw || itype == NN_pfmul
	|| itype == NN_pmulhrw || itype == NN_mulps || itype == NN_mulss
	|| itype == NN_pmulhuw || itype == NN_mulpd || itype == NN_mulsd
	|| itype == NN_pmuludq))
DEFINE_IS_INSN(divide, ph.id == PLFM_386 && (itype == NN_div || itype == NN_idiv || itype == NN_fdiv
	|| itype == NN_fdivp || itype == NN_fidiv || itype == NN_fdivr
	|| itype == NN_fdivrp || itype == NN_fidivr || itype == NN_divps
	|| itype == NN_divss || itype == NN_divpd || itype == NN_divsd))
DEFINE_IS_INSN(chflag, ph.id == PLFM_386 && (itype >= NN_clc && itype <= NN_clts || itype == NN_cmc
	|| itype >= NN_stc && itype <= NN_sti))
DEFINE_IS_INSN(string, ph.id == PLFM_386 && (itype == NN_cmps || itype == NN_ins || itype == NN_lods
	|| itype == NN_movs || itype == NN_scas || itype == NN_stos
	|| is_rep_insn(itype)))
DEFINE_IS_INSN(indirectflow, ph.id == PLFM_386 && (itype == NN_jmpni || itype == NN_jmpfi
	|| itype == NN_callni || itype == NN_callfi))
DEFINE_IS_INSN(condflow, ph.id == PLFM_386 && (itype >= NN_ja && itype <= NN_jz/* || itype == NN_into*/
	|| is_loop_insn(itype)))
DEFINE_IS_INSN(decision, ph.id == PLFM_386 && (is_condflow_insn(itype) || itype == NN_into
	|| itype >= NN_cmova && itype <= NN_fcmovnu || is_set_insn(itype)))
// floating-point operation
DEFINE_IS_INSN(fpu, ph.id == PLFM_386 && itype >= NN_fcmovb && itype <= NN_fucomip
	|| itype >= NN_fld && itype <= NN_fndisi || itype >= NN_fstp1 && itype <= NN_fstp9)
// CPU sub-family for IX86
DEFINE_IS_INSN(x86, ph.id == PLFM_386 && itype >= NN_aaa && itype <= NN_xor)
DEFINE_IS_INSN(386, ph.id == PLFM_386 && itype >= NN_fprem1 && itype <= NN_fucompp)
DEFINE_IS_INSN(486, ph.id == PLFM_386 && itype >= NN_cmpxchg && itype <= NN_invlpg)
DEFINE_IS_INSN(586, ph.id == PLFM_386 && itype >= NN_rdmsr && itype <= NN_rsm || itype >= NN_movddup
	&& itype <= NN_movsldup)
DEFINE_IS_INSN(686, ph.id == PLFM_386 && itype >= NN_cmova && itype <= NN_rdpmc)
DEFINE_IS_INSN(mmx, ph.id == PLFM_386 && itype >= NN_emms && itype <= NN_pxor)
DEFINE_IS_INSN(p2, ph.id == PLFM_386 && itype >= NN_sysenter && itype <= NN_sysexit)
DEFINE_IS_INSN(amd, ph.id == PLFM_386 && itype >= NN_syscall && itype <= NN_sysret)
DEFINE_IS_INSN(3dnow, ph.id == PLFM_386 && itype >= NN_pavgusb && itype <= NN_prefetchw)
DEFINE_IS_INSN(p3, ph.id == PLFM_386 && itype >= NN_addps && itype <= NN_cmpordss)
DEFINE_IS_INSN(amdk7, ph.id == PLFM_386 && itype >= NN_pf2iw && itype <= NN_pswapd)
DEFINE_IS_INSN(p4, ph.id == PLFM_386 && itype >= NN_addpd && itype <= NN_xorpd)
DEFINE_IS_INSN(amd64, ph.id == PLFM_386 && itype == NN_swapgs)

inline bool insn_changes_opnd(int icode, int opnd) {
	_ASSERTE(opnd >= 0 && opnd < UA_MAXOP);
	return InstrIsSet(icode, CF_CHG1 << opnd);
}
inline bool insn_uses_opnd(int icode, int opnd) {
	_ASSERTE(opnd >= 0 && opnd < UA_MAXOP);
	return InstrIsSet(icode, CF_USE1 << opnd);
}

#undef DEFINE_IS_INSN
#undef DECLARE_IS_INSN

#endif // _PLUGINSN_HPP_
