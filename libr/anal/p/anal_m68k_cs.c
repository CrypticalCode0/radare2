/* radare2 - LGPL - Copyright 2015-2018 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone/capstone.h>

#ifdef CAPSTONE_M68K_H
#define CAPSTONE_HAS_M68K 1
#else
#define CAPSTONE_HAS_M68K 0
#ifdef _MSC_VER
#pragma message ("Cannot find capstone-m68k support")
#else
#warning Cannot find capstone-m68k support
#endif
#endif

#if CAPSTONE_HAS_M68K
#include <capstone/m68k.h>
// http://www.mrc.uidaho.edu/mrc/people/jff/digital/M68Kir.html

#define OPERAND(x) insn->detail->m68k.operands[x]
#define REG(x) cs_reg_name (*handle, insn->detail->m68k.operands[x].reg)
#define IMM(x) insn->detail->m68k.operands[x].imm
#define MEMBASE(x) cs_reg_name(*handle, insn->detail->m68k.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->m68k.operands[x].mem.index
#define MEMDISP(x) insn->detail->m68k.operands[x].mem.disp

static inline ut64 make_64bits_address(ut64 address) {
	return UT32_MAX & address;
}

static inline void handle_branch_instruction(RAnalOp *op, ut64 addr, cs_m68k *m68k, ut32 type, int index) {
#if CS_API_MAJOR >= 4
		if (m68k->operands[index].type == M68K_OP_BR_DISP) {
			op->type = type;
			// TODO: disp_size is ignored
			op->jump = make_64bits_address (addr + m68k->operands[index].br_disp.disp + 2);
			op->fail = make_64bits_address (addr + op->size);
		}
#else
		op->type = type;
		// TODO: disp_size is ignored
		op->jump = make_64bits_address (addr + m68k->operands[index].br_disp.disp + 2);
		op->fail = make_64bits_address (addr + op->size);
#endif
}

static inline void handle_jump_instruction(RAnalOp *op, ut64 addr, cs_m68k *m68k, ut32 type) {
	op->type = type;

	// Handle PC relative mode jump
	if (m68k->operands[0].address_mode == M68K_AM_PCI_DISP) {
		op->jump = make_64bits_address (addr + m68k->operands[0].mem.disp + 2);
	} else {
		op->jump = make_64bits_address (m68k->operands[0].imm);
	}

	op->fail = make_64bits_address (addr + op->size);
}

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	r_strbuf_init (buf);
	r_strbuf_append (buf, "{");
	cs_m68k *x = &insn->detail->m68k;
	r_strbuf_append (buf, "\"operands\":[");
	for (i = 0; i < x->op_count; i++) {
		cs_m68k_op *op = &x->operands[i];
		if (i > 0) {
			r_strbuf_append (buf, ",");
		}
		r_strbuf_append (buf, "{");
		switch (op->type) {
		case M68K_OP_REG:
			r_strbuf_append (buf, "\"type\":\"reg\"");
			r_strbuf_appendf (buf, ",\"value\":\"%s\"", cs_reg_name (handle, op->reg));
			break;
		case M68K_OP_IMM:
			r_strbuf_append (buf, "\"type\":\"imm\"");
			r_strbuf_appendf (buf, ",\"value\":%"PFMT64d, op->imm);
			break;
		case M68K_OP_MEM:
			r_strbuf_append (buf, "\"type\":\"mem\"");
			if (op->mem.base_reg != M68K_REG_INVALID) {
				r_strbuf_appendf (buf, ",\"base_reg\":\"%s\"", cs_reg_name (handle, op->mem.base_reg));
			}
			if (op->mem.index_reg != M68K_REG_INVALID) {
				r_strbuf_appendf (buf, ",\"base_reg\":\"%s\"", cs_reg_name (handle, op->mem.index_reg));
			}
			if (op->mem.in_base_reg != M68K_REG_INVALID) {
				r_strbuf_appendf (buf, ",\"base_reg\":\"%s\"", cs_reg_name (handle, op->mem.in_base_reg));
			}
			r_strbuf_appendf (buf, ",\"in_disp\":%"PFMT64d"", op->mem.in_disp);
			r_strbuf_appendf (buf, ",\"out_disp\":%"PFMT64d"", op->mem.out_disp);
			r_strbuf_appendf (buf, ",\"disp\":%"PFMT64d"", (st64)op->mem.disp);
			r_strbuf_appendf (buf, ",\"scale\":%"PFMT64d"", (st64)op->mem.scale);
			r_strbuf_appendf (buf, ",\"bitfield\":%"PFMT64d"", (st64)op->mem.bitfield);
			r_strbuf_appendf (buf, ",\"width\":%"PFMT64d"", (st64)op->mem.width);
			r_strbuf_appendf (buf, ",\"offset\":%"PFMT64d"", (st64)op->mem.offset);
			r_strbuf_appendf (buf, ",\"index_size\":%"PFMT64d"", (st64)op->mem.index_size);
			break;
		default:
			r_strbuf_append (buf, "\"type\":\"invalid\"");
			break;
		}
		r_strbuf_append (buf, "}");
	}
	r_strbuf_append (buf, "]}");
}

static int parse_reg_name(RRegItem *reg, csh handle, cs_insn *insn, int reg_num) {
	if (!reg) {
		return -1;
	}
	switch (OPERAND (reg_num).type) {
	case M68K_OP_REG:
		reg->name = (char *)cs_reg_name (handle, OPERAND (reg_num).reg);
		break;
	case M68K_OP_MEM:
		if (OPERAND (reg_num).mem.base_reg != M68K_REG_INVALID) {
			reg->name = (char *)cs_reg_name (handle, OPERAND (reg_num).mem.base_reg);
		}
		break;
	default:
		break;
	}
	return 0;
}

static void op_fillval(RAnalOp *op, csh handle, cs_insn *insn) {
	static RRegItem reg;
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_MOV:
		ZERO_FILL (reg);
		if (OPERAND(1).type == M68K_OP_MEM) {
			op->src[0] = r_anal_value_new ();
			op->src[0]->reg = &reg;
			parse_reg_name (op->src[0]->reg, handle, insn, 1);
			op->src[0]->delta = OPERAND(0).mem.disp;
		} else if (OPERAND(0).type == M68K_OP_MEM) {
			op->dst = r_anal_value_new ();
			op->dst->reg = &reg;
			parse_reg_name (op->dst->reg, handle, insn, 0);
			op->dst->delta = OPERAND(1).mem.disp;
		}
		break;
	case R_ANAL_OP_TYPE_LEA:
		ZERO_FILL (reg);
		if (OPERAND(1).type == M68K_OP_MEM) {
			op->dst = r_anal_value_new ();
			op->dst->reg = &reg;
			parse_reg_name (op->dst->reg, handle, insn, 1);
			op->dst->delta = OPERAND(1).mem.disp;
		}
		break;
	}
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	int n, ret, opsize = -1;
	static csh handle = 0;
	static int omode = -1;
	static int obits = 32;
	cs_insn* insn;
	cs_m68k *m68k;
	cs_detail *detail;

	int mode = a->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;

	//mode |= (a->bits==64)? CS_MODE_64: CS_MODE_32;
	if (mode != omode || a->bits != obits) {
		cs_close (&handle);
		handle = 0;
		omode = mode;
		obits = a->bits;
	}
// XXX no arch->cpu ?!?! CS_MODE_MICRO, N64
	op->delay = 0;
	// replace this with the asm.features?
	if (a->cpu && strstr (a->cpu, "68000")) {
		mode |= CS_MODE_M68K_000;
	}
	if (a->cpu && strstr (a->cpu, "68010")) {
		mode |= CS_MODE_M68K_010;
	}
	if (a->cpu && strstr (a->cpu, "68020")) {
		mode |= CS_MODE_M68K_020;
	}
	if (a->cpu && strstr (a->cpu, "68030")) {
		mode |= CS_MODE_M68K_030;
	}
	if (a->cpu && strstr (a->cpu, "68040")) {
		mode |= CS_MODE_M68K_040;
	}
	if (a->cpu && strstr (a->cpu, "68060")) {
		mode |= CS_MODE_M68K_060;
	}
	op->size = 4;
	if (handle == 0) {
		ret = cs_open (CS_ARCH_M68K, mode, &handle);
		if (ret != CS_ERR_OK) {
			goto fin;
		}
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	n = cs_disasm (handle, (ut8*)buf, len, addr, 1, &insn);
	if (n < 1 || insn->size < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 2;
		opsize = -1;
		goto beach;
	}
	if (!memcmp (buf, "\xff\xff", R_MIN (len, 2))) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 2;
		opsize = -1;
		goto beach;
	}
	detail = insn->detail;
	m68k = &detail->m68k;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->delay = 0;
	op->id = insn->id;
	opsize = op->size = insn->size;
	if (mask & R_ANAL_OP_MASK_OPEX) {
		opex (&op->opex, handle, insn);
	}
	switch (insn->id) {
	case M68K_INS_INVALID:
		op->type  = R_ANAL_OP_TYPE_ILL;
		break;
	case M68K_INS_ADD:
	case M68K_INS_ADDA:
	case M68K_INS_ADDI:
	case M68K_INS_ADDQ:
	case M68K_INS_ADDX:
		op->type  = R_ANAL_OP_TYPE_ADD;
		break;
	case M68K_INS_AND:
	case M68K_INS_ANDI:
		op->type  = R_ANAL_OP_TYPE_AND;
		break;
	case M68K_INS_ASL:
		op->type  = R_ANAL_OP_TYPE_SHL;
		break;
	case M68K_INS_ASR:
		op->type  = R_ANAL_OP_TYPE_SHR;
		break;
	case M68K_INS_ABCD:
		break;
	case M68K_INS_BHS:
	case M68K_INS_BLO:
	case M68K_INS_BHI:
	case M68K_INS_BLS:
	case M68K_INS_BCC:
	case M68K_INS_BCS:
	case M68K_INS_BNE:
	case M68K_INS_BEQ:
	case M68K_INS_BVC:
	case M68K_INS_BVS:
	case M68K_INS_BPL:
	case M68K_INS_BMI:
	case M68K_INS_BGE:
	case M68K_INS_BLT:
	case M68K_INS_BGT:
	case M68K_INS_BLE:
		handle_branch_instruction (op, addr, m68k, R_ANAL_OP_TYPE_CJMP, 0);
		break;
	case M68K_INS_BRA:
		handle_branch_instruction (op, addr, m68k, R_ANAL_OP_TYPE_JMP, 0);
		break;
	case M68K_INS_BSR:
		handle_branch_instruction (op, addr, m68k, R_ANAL_OP_TYPE_CALL, 0);
		break;
	case M68K_INS_BCHG:
	case M68K_INS_BCLR:
	case M68K_INS_BSET:
	case M68K_INS_BTST:
	case M68K_INS_BFCHG:
	case M68K_INS_BFCLR:
	case M68K_INS_BFEXTS:
	case M68K_INS_BFEXTU:
	case M68K_INS_BFFFO:
	case M68K_INS_BFINS:
	case M68K_INS_BFSET:
	case M68K_INS_BFTST:
	case M68K_INS_BKPT:
	case M68K_INS_CALLM:
	case M68K_INS_CAS:
	case M68K_INS_CAS2:
	case M68K_INS_CHK:
	case M68K_INS_CHK2:
	case M68K_INS_CLR:
		// TODO:
		break;
	case M68K_INS_CMP:
	case M68K_INS_CMPA:
	case M68K_INS_CMPI:
	case M68K_INS_CMPM:
	case M68K_INS_CMP2:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case M68K_INS_CINVL:
	case M68K_INS_CINVP:
	case M68K_INS_CINVA:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case M68K_INS_CPUSHL:
	case M68K_INS_CPUSHP:
	case M68K_INS_CPUSHA:
		break;
	case M68K_INS_DBT:
	case M68K_INS_DBF:
	case M68K_INS_DBHI:
	case M68K_INS_DBLS:
	case M68K_INS_DBCC:
	case M68K_INS_DBCS:
	case M68K_INS_DBNE:
	case M68K_INS_DBEQ:
	case M68K_INS_DBVC:
	case M68K_INS_DBVS:
	case M68K_INS_DBPL:
	case M68K_INS_DBMI:
	case M68K_INS_DBGE:
	case M68K_INS_DBLT:
	case M68K_INS_DBGT:
	case M68K_INS_DBLE:
	case M68K_INS_DBRA:
		handle_branch_instruction (op, addr, m68k, R_ANAL_OP_TYPE_CJMP, 1);
		break;
	case M68K_INS_DIVS:
	case M68K_INS_DIVSL:
	case M68K_INS_DIVU:
	case M68K_INS_DIVUL:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case M68K_INS_EOR:
	case M68K_INS_EORI:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case M68K_INS_EXG:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case M68K_INS_EXT:
	case M68K_INS_EXTB:
		break;
	case M68K_INS_FABS:
	case M68K_INS_FSABS:
	case M68K_INS_FDABS:
	case M68K_INS_FACOS:
	case M68K_INS_FADD:
	case M68K_INS_FSADD:
	case M68K_INS_FDADD:
	case M68K_INS_FASIN:
	case M68K_INS_FATAN:
	case M68K_INS_FATANH:
	case M68K_INS_FBF:
	case M68K_INS_FBEQ:
	case M68K_INS_FBOGT:
	case M68K_INS_FBOGE:
	case M68K_INS_FBOLT:
	case M68K_INS_FBOLE:
	case M68K_INS_FBOGL:
	case M68K_INS_FBOR:
	case M68K_INS_FBUN:
	case M68K_INS_FBUEQ:
	case M68K_INS_FBUGT:
	case M68K_INS_FBUGE:
	case M68K_INS_FBULT:
	case M68K_INS_FBULE:
	case M68K_INS_FBNE:
	case M68K_INS_FBT:
	case M68K_INS_FBSF:
	case M68K_INS_FBSEQ:
	case M68K_INS_FBGT:
	case M68K_INS_FBGE:
	case M68K_INS_FBLT:
	case M68K_INS_FBLE:
	case M68K_INS_FBGL:
	case M68K_INS_FBGLE:
	case M68K_INS_FBNGLE:
	case M68K_INS_FBNGL:
	case M68K_INS_FBNLE:
	case M68K_INS_FBNLT:
	case M68K_INS_FBNGE:
	case M68K_INS_FBNGT:
	case M68K_INS_FBSNE:
	case M68K_INS_FBST:
	case M68K_INS_FCMP:
	case M68K_INS_FCOS:
	case M68K_INS_FCOSH:
	case M68K_INS_FDBF:
	case M68K_INS_FDBEQ:
	case M68K_INS_FDBOGT:
	case M68K_INS_FDBOGE:
	case M68K_INS_FDBOLT:
	case M68K_INS_FDBOLE:
	case M68K_INS_FDBOGL:
	case M68K_INS_FDBOR:
	case M68K_INS_FDBUN:
	case M68K_INS_FDBUEQ:
	case M68K_INS_FDBUGT:
	case M68K_INS_FDBUGE:
	case M68K_INS_FDBULT:
	case M68K_INS_FDBULE:
	case M68K_INS_FDBNE:
	case M68K_INS_FDBT:
	case M68K_INS_FDBSF:
	case M68K_INS_FDBSEQ:
	case M68K_INS_FDBGT:
	case M68K_INS_FDBGE:
	case M68K_INS_FDBLT:
	case M68K_INS_FDBLE:
	case M68K_INS_FDBGL:
	case M68K_INS_FDBGLE:
	case M68K_INS_FDBNGLE:
	case M68K_INS_FDBNGL:
	case M68K_INS_FDBNLE:
	case M68K_INS_FDBNLT:
	case M68K_INS_FDBNGE:
	case M68K_INS_FDBNGT:
	case M68K_INS_FDBSNE:
	case M68K_INS_FDBST:
	case M68K_INS_FDIV:
	case M68K_INS_FSDIV:
	case M68K_INS_FDDIV:
	case M68K_INS_FETOX:
	case M68K_INS_FETOXM1:
	case M68K_INS_FGETEXP:
	case M68K_INS_FGETMAN:
	case M68K_INS_FINT:
	case M68K_INS_FINTRZ:
	case M68K_INS_FLOG10:
	case M68K_INS_FLOG2:
	case M68K_INS_FLOGN:
	case M68K_INS_FLOGNP1:
	case M68K_INS_FMOD:
	case M68K_INS_FMOVE:
	case M68K_INS_FSMOVE:
	case M68K_INS_FDMOVE:
	case M68K_INS_FMOVECR:
	case M68K_INS_FMOVEM:
	case M68K_INS_FMUL:
	case M68K_INS_FSMUL:
	case M68K_INS_FDMUL:
	case M68K_INS_FNEG:
	case M68K_INS_FSNEG:
	case M68K_INS_FDNEG:
	case M68K_INS_FNOP:
	case M68K_INS_FREM:
	case M68K_INS_FRESTORE:
	case M68K_INS_FSAVE:
	case M68K_INS_FSCALE:
	case M68K_INS_FSGLDIV:
	case M68K_INS_FSGLMUL:
	case M68K_INS_FSIN:
	case M68K_INS_FSINCOS:
	case M68K_INS_FSINH:
	case M68K_INS_FSQRT:
	case M68K_INS_FSSQRT:
	case M68K_INS_FDSQRT:
	case M68K_INS_FSF:
	case M68K_INS_FSBEQ:
	case M68K_INS_FSOGT:
	case M68K_INS_FSOGE:
	case M68K_INS_FSOLT:
	case M68K_INS_FSOLE:
	case M68K_INS_FSOGL:
	case M68K_INS_FSOR:
	case M68K_INS_FSUN:
	case M68K_INS_FSUEQ:
	case M68K_INS_FSUGT:
	case M68K_INS_FSUGE:
	case M68K_INS_FSULT:
	case M68K_INS_FSULE:
	case M68K_INS_FSNE:
	case M68K_INS_FST:
	case M68K_INS_FSSF:
	case M68K_INS_FSSEQ:
	case M68K_INS_FSGT:
	case M68K_INS_FSGE:
	case M68K_INS_FSLT:
	case M68K_INS_FSLE:
	case M68K_INS_FSGL:
	case M68K_INS_FSGLE:
	case M68K_INS_FSNGLE:
	case M68K_INS_FSNGL:
	case M68K_INS_FSNLE:
	case M68K_INS_FSNLT:
	case M68K_INS_FSNGE:
	case M68K_INS_FSNGT:
	case M68K_INS_FSSNE:
	case M68K_INS_FSST:
	case M68K_INS_FSUB:
	case M68K_INS_FSSUB:
	case M68K_INS_FDSUB:
	case M68K_INS_FTAN:
	case M68K_INS_FTANH:
	case M68K_INS_FTENTOX:
	case M68K_INS_FTRAPF:
	case M68K_INS_FTRAPEQ:
	case M68K_INS_FTRAPOGT:
	case M68K_INS_FTRAPOGE:
	case M68K_INS_FTRAPOLT:
	case M68K_INS_FTRAPOLE:
	case M68K_INS_FTRAPOGL:
	case M68K_INS_FTRAPOR:
	case M68K_INS_FTRAPUN:
	case M68K_INS_FTRAPUEQ:
	case M68K_INS_FTRAPUGT:
	case M68K_INS_FTRAPUGE:
	case M68K_INS_FTRAPULT:
	case M68K_INS_FTRAPULE:
	case M68K_INS_FTRAPNE:
	case M68K_INS_FTRAPT:
	case M68K_INS_FTRAPSF:
	case M68K_INS_FTRAPSEQ:
	case M68K_INS_FTRAPGT:
	case M68K_INS_FTRAPGE:
	case M68K_INS_FTRAPLT:
	case M68K_INS_FTRAPLE:
	case M68K_INS_FTRAPGL:
	case M68K_INS_FTRAPGLE:
	case M68K_INS_FTRAPNGLE:
	case M68K_INS_FTRAPNGL:
	case M68K_INS_FTRAPNLE:
	case M68K_INS_FTRAPNLT:
	case M68K_INS_FTRAPNGE:
	case M68K_INS_FTRAPNGT:
	case M68K_INS_FTRAPSNE:
	case M68K_INS_FTRAPST:
	case M68K_INS_FTST:
	case M68K_INS_FTWOTOX:
		op->type = R_ANAL_OP_TYPE_UNK;
		op->family = R_ANAL_OP_FAMILY_FPU;
		break;
	case M68K_INS_HALT:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case M68K_INS_ILLEGAL:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case M68K_INS_JMP:
		handle_jump_instruction (op, addr, m68k, R_ANAL_OP_TYPE_JMP);
		break;
	case M68K_INS_JSR:
		handle_jump_instruction (op, addr, m68k, R_ANAL_OP_TYPE_CALL);
		break;
	case M68K_INS_LPSTOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case M68K_INS_LSL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case M68K_INS_LINK:
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -(st16)IMM(1);
		break;
	case M68K_INS_LSR:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case M68K_INS_PEA:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->stackop = R_ANAL_STACK_INC;
		break;
	case M68K_INS_LEA:
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
	case M68K_INS_MOVE:
	case M68K_INS_MOVEA:
	case M68K_INS_MOVEM:
	case M68K_INS_MOVEP:
	case M68K_INS_MOVEQ:
	case M68K_INS_MOVE16:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case M68K_INS_MOVEC:
    	case M68K_INS_MOVES:
        	op->type = R_ANAL_OP_FAMILY_PRIV;
        	op->type = R_ANAL_OP_TYPE_MOV;
        	break;
    	case M68K_INS_MULS:
	case M68K_INS_MULU:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case M68K_INS_NBCD:
	case M68K_INS_NEG:
	case M68K_INS_NEGX:
		break;
	case M68K_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case M68K_INS_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case M68K_INS_OR:
	case M68K_INS_ORI:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case M68K_INS_PACK:
        	break;
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHA:
	case M68K_INS_PFLUSHAN:
	case M68K_INS_PFLUSHN:
	case M68K_INS_PLOADR:
	case M68K_INS_PLOADW:
	case M68K_INS_PLPAR:
	case M68K_INS_PLPAW:
	case M68K_INS_PMOVE:
	case M68K_INS_PMOVEFD:
	case M68K_INS_PTESTR:
	case M68K_INS_PTESTW:
	case M68K_INS_PULSE:
	case M68K_INS_REMS:
	case M68K_INS_REMU:
	case M68K_INS_RESET:
        	op->type = R_ANAL_OP_FAMILY_PRIV;
		break;
	case M68K_INS_ROL:
		op->type = R_ANAL_OP_TYPE_ROL;
		break;
	case M68K_INS_ROR:
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case M68K_INS_ROXL:
	case M68K_INS_ROXR:
		break;
	case M68K_INS_RTD:
	case M68K_INS_RTM:
	case M68K_INS_RTR:
	case M68K_INS_RTS:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case M68K_INS_RTE:
        	op->type = R_ANAL_OP_TYPE_RET;
        	op->type = R_ANAL_OP_FAMILY_PRIV;
        	break;
    	case M68K_INS_SBCD:
	case M68K_INS_ST:
	case M68K_INS_SF:
	case M68K_INS_SHI:
	case M68K_INS_SLS:
	case M68K_INS_SCC:
	case M68K_INS_SHS:
	case M68K_INS_SCS:
	case M68K_INS_SLO:
	case M68K_INS_SNE:
	case M68K_INS_SEQ:
	case M68K_INS_SVC:
	case M68K_INS_SVS:
	case M68K_INS_SPL:
	case M68K_INS_SMI:
	case M68K_INS_SGE:
	case M68K_INS_SLT:
	case M68K_INS_SGT:
	case M68K_INS_SLE:
	case M68K_INS_STOP:
		break;
	case M68K_INS_SUB:
	case M68K_INS_SUBA:
	case M68K_INS_SUBI:
	case M68K_INS_SUBQ:
	case M68K_INS_SUBX:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case M68K_INS_SWAP:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case M68K_INS_TAS:
		break;
	case M68K_INS_TRAP:
	case M68K_INS_TRAPV:
	case M68K_INS_TRAPT:
	case M68K_INS_TRAPF:
	case M68K_INS_TRAPHI:
	case M68K_INS_TRAPLS:
	case M68K_INS_TRAPCC:
	case M68K_INS_TRAPHS:
	case M68K_INS_TRAPCS:
	case M68K_INS_TRAPLO:
	case M68K_INS_TRAPNE:
	case M68K_INS_TRAPEQ:
	case M68K_INS_TRAPVC:
	case M68K_INS_TRAPVS:
	case M68K_INS_TRAPPL:
	case M68K_INS_TRAPMI:
	case M68K_INS_TRAPGE:
	case M68K_INS_TRAPLT:
	case M68K_INS_TRAPGT:
	case M68K_INS_TRAPLE:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case M68K_INS_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case M68K_INS_UNPK: // unpack BCD
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case M68K_INS_UNLK:
		op->type = R_ANAL_OP_TYPE_POP;
		// reset stackframe
		op->stackop = R_ANAL_STACK_SET;
		op->stackptr = 0;
		break;
	}
	if (mask & R_ANAL_OP_MASK_VAL) {
		op_fillval (op, handle, insn);
	}
beach:
	cs_free (insn, n);
	//cs_close (&handle);
fin:
	return opsize;
}

static int set_reg_profile(RAnal *anal) {
	const char *p = \
	switch (anal->cpu_model) {
		switch (anal->cpu_model) {
		case 68060: p =
			"fpu	fp0	.96	98	0\n" //FPU reg0, 96bits for write & read.
			"fpu	fp1	.96	110	0\n" //FPU reg1, 96bits for write & read.
			"fpu	fp2	.96	122	0\n" //FPU reg2, 96bits for write & read.
			"fpu	fp3	.96	134	0\n" //FPU reg3, 96bits for write & read.
			"fpu	fp4	.96	146	0\n" //FPU reg4, 96bits for write & read.
			"fpu	fp5	.96	158	0\n" //FPU reg5, 96bits for write & read.
			"fpu	fp6	.96	170	0\n" //FPU reg6, 96bits for write & read.
			"fpu	fp7	.96	182	0\n" //FPU reg7, 96bits for write & read.
			"fpu	fpcr	.32	194	0\n" //FPU Control reg
			"fpu	fpsr	.32	198	0\n" //FPU Status reg
			"fpu	fpiar	.32	202	0\n" //FPU Instruction Address reg.
		case 68LC060: p = //without FPU
			"priv	urp	.32	220	0\n"
			"priv	srp	.32	228	0\n"
		case 68EC060: p = //without FPU and MMU
			"priv	tc	.16	206	0\n"
			"priv	dtt0	.32	210	0\n"
			"priv	dtt1	.32	214	0\n"
			"priv	itt0	.32	224	0\n"
			"priv	itt1	.32	232	0\n"
			"priv	buscr	.32	236	0\n"
			"priv	pcr	.32	240	0\n"
			break;
		case 68040: p =
			"fpu	fp0	.96	98	0\n" //FPU reg0, 96bits for write & read.
			"fpu	fp1	.96	110	0\n" //FPU reg1, 96bits for write & read.
			"fpu	fp2	.96	122	0\n" //FPU reg2, 96bits for write & read.
			"fpu	fp3	.96	134	0\n" //FPU reg3, 96bits for write & read.
			"fpu	fp4	.96	146	0\n" //FPU reg4, 96bits for write & read.
			"fpu	fp5	.96	158	0\n" //FPU reg5, 96bits for write & read.
			"fpu	fp6	.96	170	0\n" //FPU reg6, 96bits for write & read.
			"fpu	fp7	.96	182	0\n" //FPU reg7, 96bits for write & read.
			"fpu	fpcr	.32	194	0\n" //FPU Control reg
			"fpu	fpsr	.32	198	0\n" //FPU Status reg
			"fpu	fpiar	.32	202	0\n" //FPU Instruction Address reg.
		case 68LC040: p = //without FPU
			"priv	urp	.32	220	0\n"
			"priv	srp	.32	228	0\n"
			"priv	tc	.16	206	0\n"
			"priv	dtt0	.32	210	0\n"
			"priv	dtt1	.32	214	0\n"
			"priv	itt0	.32	224	0\n"
			"priv	itt1	.32	232	0\n"
			"priv	mmusr	.16	218	0\n"
			break;
		case 68EC040: p = //without FPU and MMU
			"priv	dacr0	.32	210	0\n"
			"priv	dacr1	.32	216	0\n"
			"priv	iacr0	.32	224	0\n"
			"priv	iacr1	.32	232	0\n"
			break;
		case 68EC030: p = //without MMU
			"priv	caar	.32	94	0\n" //cache addr reg, 68020, 68EC020, 68030 & 68EC030 only.
			"priv	ac0	.32	210	0\n"
			"priv	ac1	.32	214	0\n"
			"priv	acusr	.16	218	0\n"
			break;
		case 68030: p = //without FPU
			"priv	tc	.32	206	0\n"
			"priv	tt0	.32	210	0\n"
			"priv	tt1	.32	214	0\n"
			"priv	mmusr	.16	218	0\n"
			"priv	crp	.64	220	0\n"
			"priv	srp	.64	228	0\n";
		case 68020: p = //without FPU and MMU
			"priv	caar	.32	94	0\n" //cache addr reg, 68020, 68EC020, 68030 & 68EC030 only.
			break;
		case 68EC030+FPU: p = //without MMU
			"priv	caar	.32	94	0\n" //cache addr reg, 68020, 68EC020, 68030 & 68EC030 only.
			"fpu	fp0	.96	98	0\n" //FPU reg0, 96bits for write & read.
			"fpu	fp1	.96	110	0\n" //FPU reg1, 96bits for write & read.
			"fpu	fp2	.96	122	0\n" //FPU reg2, 96bits for write & read.
			"fpu	fp3	.96	134	0\n" //FPU reg3, 96bits for write & read.
			"fpu	fp4	.96	146	0\n" //FPU reg4, 96bits for write & read.
			"fpu	fp5	.96	158	0\n" //FPU reg5, 96bits for write & read.
			"fpu	fp6	.96	170	0\n" //FPU reg6, 96bits for write & read.
			"fpu	fp7	.96	182	0\n" //FPU reg7, 96bits for write & read.
			"fpu	fpcr	.32	194	0\n" //FPU Control reg
			"fpu	fpsr	.32	198	0\n" //FPU Status reg
			"fpu	fpiar	.32	202	0\n" //FPU Instruction Address reg.
			"priv	ac0	.32	210	0\n"
			"priv	ac1	.32	214	0\n"
			"priv	acusr	.16	218	0\n"
			break;
		case 68030+FPU: p =
			"priv	tc	.32	206	0\n"
			"priv	tt0	.32	210	0\n"
			"priv	tt1	.32	214	0\n"
			"priv	mmusr	.16	218	0\n"
			"priv	crp	.64	220	0\n"
			"priv	srp	.64	228	0\n";
		case 68020+FPU: p = //without MMU
			"priv	caar	.32	94	0\n" //cache addr reg, 68020, 68EC020, 68030 & 68EC030 only.
			"fpu	fp0	.96	98	0\n" //FPU reg0, 96bits for write & read.
			"fpu	fp1	.96	110	0\n" //FPU reg1, 96bits for write & read.
			"fpu	fp2	.96	122	0\n" //FPU reg2, 96bits for write & read.
			"fpu	fp3	.96	134	0\n" //FPU reg3, 96bits for write & read.
			"fpu	fp4	.96	146	0\n" //FPU reg4, 96bits for write & read.
			"fpu	fp5	.96	158	0\n" //FPU reg5, 96bits for write & read.
			"fpu	fp6	.96	170	0\n" //FPU reg6, 96bits for write & read.
			"fpu	fp7	.96	182	0\n" //FPU reg7, 96bits for write & read.
			"fpu	fpcr	.32	194	0\n" //FPU Control reg
			"fpu	fpsr	.32	198	0\n" //FPU Status reg
			"fpu	fpiar	.32	202	0\n" //FPU Instruction Address reg.
			break;
		}
		"priv	ms	.1	.588	0\n" //Master state flag.
		"priv	t0	.1	.590	0\n" //Trace 0, if set trace on change of flow.
		"priv	msp	.32	86	0\n" //Master stack ptr.
		"priv	cacr	.32	90	0\n" //Cache ctrl reg, implementation specific
	case cpu32: p = //Embedded version, 683XX
	case 68010: p =
		"priv	vbr	.32	74	0\n" //vector base reg, this is a ptr to the exception table.
		"priv	sfc	.32	78	0\n" //src fun code reg, top 29bit read NULL.
		"priv	dfc	.32	82	0\n" //dst fun code reg, top 29bit read NULL.
	default: p =
	case 68008: p = //8-bit bus version
	case 68000: p = //default, grandaddy of this family.
		"=PC    pc\n"
		"=SR	sr\n" //Status Reg.
		"=SP    a7\n" //conditional, should be set either to USP, MSP, or ISP.
		"=BP    a6\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"=A2    a2\n"
		"=A3    a3\n"
		"=A4	a4\n"
		"=A5	a5\n"
		"=ZF    zf\n"
		"=SF    nf\n"
		"=OF    vf\n"
		"=CF    cf\n"
		"gpr	d0	.32	0	0\n"
		"gpr	d1	.32	4	0\n"
		"gpr	d2	.32	8	0\n"
		"gpr	d3	.32	12	0\n"
		"gpr	d4	.32	16	0\n"
		"gpr	d5	.32	20	0\n"
		"gpr	d6	.32	24	0\n"
		"gpr	d7	.32	28	0\n"
		"gpr	a0	.32	32	0\n"
		"gpr	a1	.32	36	0\n"
		"gpr	a2 	.32	40	0\n"
		"gpr	a3 	.32	44	0\n"
		"gpr	a4 	.32	48	0\n"
		"gpr	a5	.32	52	0\n"
		"gpr	a6 	.32	56	0\n"
		"gpr	a7 	.32	60	0\n"
		"gpr	usp	.32	60	0\n" //usr stack ptr this is reg A7 during user mode.
		"priv	ssp	.32	64	0\n" //Supervisor stack ptr, this is reg A7 during supervisor mode.
		"gpr	pc	.32	68	0\n"
		"priv	sr	.16	72	0\n" //available for read & write access during supervisor mode.
		"priv	im	.3	.584	0\n" //Interrupt mask
		"priv	ss	.1	.589	0\n" //Supervisor state flag, set during boot
		"priv	t1	.1	.591	0\n" //Trace 1, if set trace on any instruction
		"gpr	ccr	.8	72	0\n" //subset of the SR, available during any mode.
		"flg	xf	.1	.580	0\n" //extended flag.
		"flg	nf	.1	.579	0\n" //negative flag.
		"flg	zf	.1	.578	0\n" //zero flag.
		"flg	vf	.1	.577	0\n" //overflow flag.
		"flg	cf	.1	.576	0\n" //carry flag.
		break;
	case 68881: p = //FPU
	case 68882: p = //the faster FPU
		"fpu	fp0	.96	98	0\n" //FPU reg0, 96bits for write & read.
		"fpu	fp1	.96	110	0\n" //FPU reg1, 96bits for write & read.
		"fpu	fp2	.96	122	0\n" //FPU reg2, 96bits for write & read.
		"fpu	fp3	.96	134	0\n" //FPU reg3, 96bits for write & read.
		"fpu	fp4	.96	146	0\n" //FPU reg4, 96bits for write & read.
		"fpu	fp5	.96	158	0\n" //FPU reg5, 96bits for write & read.
		"fpu	fp6	.96	170	0\n" //FPU reg6, 96bits for write & read.
		"fpu	fp7	.96	182	0\n" //FPU reg7, 96bits for write & read.
		"fpu	fpcr	.32	194	0\n" //FPU Control reg
		"fpu	mc	.8	194	0\n" //Mode Control
		"fpu	rnd	.2	.1556	0\n" //Rounding, default is nearest.
		"fpu	prec	.2	.1558	0\n" //Precision, default is extended.
		"fpu	ee	.8	195	0\n" //Exception Enable
		"fpu	inex1	.1	.1560	0\n" //Inexact Dec input
		"fpu	inex2	.1	.1561	0\n" //Inexact Op
		"fpu	dz	.1	.1562	0\n" //Divide by Zero
		"fpu	unfl	.1	.1563	0\n" //UnderFlow
		"fpu	ovfl	.1	.1564	0\n" //OverFlow
		"fpu	operr	.1	.1565	0\n" //Op Error
		"fpu	snan	.1	.1566	0\n" //Signalling Not a Number.
		"fpu	bsun	.1	.1567	0\n" //Branch/Set on Unordered.
		"fpu	fpsr	.32	198	0\n" //FPU Status reg
		"fpu	ae	.8	198	0\n" //Accured Exception
		"fpu	inex	.1	.1587	0\n" //Inexact
		"fpu	dz	.1	.1588	0\n" //Divide by Zero
		"fpu	unfl	.1	.1589	0\n" //UnderFlow
		"fpu	ovfl	.1	.1590	0\n" //OverFlow
		"fpu	iop	.1	.1591	0\n" //Invalid Op
		"fpu	es	.8	199	0\n" //Exception Status
		"fpu	inex1	.1	.1592	0\n" //Inexact Dec input
		"fpu	inex2	.1	.1593	0\n" //Inexact Op
		"fpu	dz	.1	.1594	0\n" //Divide by Zero
		"fpu	unfl	.1	.1595	0\n" //UnderFlow
		"fpu	ovfl	.1	.1596	0\n" //OverFlow
		"fpu	operr	.1	.1597	0\n" //Op Error
		"fpu	snan	.1	.1598	0\n" //Signalling Not a Number.
		"fpu	bsun	.1	.1599	0\n" //Branch/Set on Unordered.
		"fpu	qb	.8	200	0\n" //Quotient byte
		"fpu	ql	.7	.1600	0\n" //Quotient, least significant bits.
		"fpu	qs	.1	.1607	0\n" //Quotient, Sign.
		"fpu	ccb	.8	201	0\n" //Condition Code byte
		"fpu	nan	.1	.1608	0\n" //Not a Number
		"fpu	in	.1	.1609	0\n" //Infinity
		"fpu	ze	.1	.1610	0\n" //Zero
		"fpu	ne	.1	.1611	0\n" //Negative
		"fpu	fpiar	.32	202	0\n" //FPU Instruction Address reg.
		break;
	case 68851: p =	//MMU
		"priv	tc	.32	206	0\n"
		"priv	ac	.16	210	0\n"
		"priv	pcsr	.16	212	0\n"
		"priv	cal	.8	214	0\n"
		"priv	scc	.8	215	0\n"
		"priv	val	.8	216	0\n"
		"priv	pmmusr	.16	218	0\n"
		"priv	crp	.64	220	0\n"
		"priv	srp	.64	228	0\n"
		"priv	drp	.64	236	0\n"
		break;
	}
	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_m68k_cs = {
	.name = "m68k",
	.desc = "Capstone M68K analyzer",
	.license = "BSD",
	.esil = false,
	.arch = "m68k",
	.set_reg_profile = &set_reg_profile,
	.bits = 32,
	.op = &analop,
};
#else
RAnalPlugin r_anal_plugin_m68k_cs = {
	.name = "m68k (unsupported)",
	.desc = "Capstone M68K analyzer (unsupported)",
	.license = "BSD",
	.arch = "m68k",
	.bits = 32,
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_m68k_cs,
	.version = R2_VERSION
};
#endif
