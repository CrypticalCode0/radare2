/* radare - LGPL - Copyright 2016 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <r_lib.h>
#include <r_util.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_parse.h>

static bool can_replace(const char *str, int idx, int max_operands) {
	if (str[idx] > '9' || str[idx] < '1') {
		return false;
	}
	if (str[idx + 1] != '\x00' && str[idx + 1] <= '9' && str[idx + 1] >= '1') {
		return false;
	}
	if ((int)((int)str[idx] - 0x30) > max_operands) {
		return false;
	}
	return true;
}

static int replace(int argc, const char *argv[], char *newstr) {
	int i,j,k;
	struct {
		char *op;
		char *str;
		int max_operands;
	} ops[] = {
		{ "move",  "1 -> 2", 2},
		{ "movea",  "1 -> 2", 2},
		{ "moveq",  "N -> 2", 2},
		{ "movem",  "<list> -> 2", 2},
		{ "lea",  "1 -> 2", 2}, //<ea>->An
		{ "bsr",  "1()", 1}, //sp-4->sp; pc->(sp);pc+displacement->pc
		{ "jsr",  "1()", 1}, //sp-4->sp; pc->(sp);<ea>->pc
		{ "beq",  "if (==) jmp 1", 1}, //if Z flag true;then pc+displacement->pc
		{ "bne",  "if != jmp 1", 1}, //if Z flag false;then pc+displacement->pc
		{ "blt",  "if (<) jmp 1", 1}, //if N && !V || !N && V;then pc+displacement->pc
		{ "ble",  "if (<=) jmp 1", 1}, //if Z || N && !V || !N && V;then pc+displacement->pc
		{ "bgt",  "if (>) jmp 1", 1}, //if N && V && !Z || !N && !V && !Z;then cp+displacement->pc
		{ "bge",  "if (>=) jmp 1", 1}, //if N && V || !N && !V;then pc->displacement->pc
		{ "bcs",  "if (cs) jmp 1", 1}, //if C flag true; then pc+displacement->pc
		{ "bcc",  "if (cc) jmp 1", 1}, //if C flag false; then pc+displacement->pc
		{ "bvs",  "if (vs) jmp 1", 1}, //if V flag true;then pc+displacement->pc
		{ "bvc",  "if (vc) jmp 1", 1}, //if V flag false;then pc+displacement->pc
		{ "bpl",  "if (pl) jmp 1", 1}, //if N flag false;then pc+displacement->pc
		{ "bmi",  "if (mi) jmp 1", 1}, //if N flag true;then pc+displacement->pc
		{ "bhi",  "if (hi) jmp 1", 1}, //if !Z && !C;then pc+displacement->pc
		{ "bls",  "if (ls) jmp 1", 1}, //if Z || C;then pc+displacement->pc
		{ "bra",  "jmp 1", 1}, //pc+displacement->pc
		{ "jmp",  "jmp 1", 1}, //<ea>->pc
		{ "rts",  "ret", 0},   //(sp)->pc;sp+4->sp
		{ "bchg",  "1 != 2", 2}, //test (<bit N> of dest)->Z flag;test (<bit N> of dest)-><bit N> of dest
		{ "bclr",  "0x0->(1 >> 2)", 2}, //test (<bit N> of dest)->Z flag;0x0-><bit N> of dest
		{ "",  "", },
		{ "btst", "1 == 2", 2}, //test (<bit N> of dest)->Z flag
		{ "cmp",  "1 == 2", 2}, //src-dest->ccr register
		{ "cmpi", "N == 2", 2}, //src-imm->ccr register
		{ "add",  "1 += 2", 2}, //src+dest->dest
		{ "addi", "N += 2", 2}, //imm+dest->dest
		{ "adda", "1 += 2", 2}, //src+An->An
		{ "addq", "N += 2", 2}, //imm+dest->dest
		{ "addx", "1 += 2+X", 2}, //src+dest+X flag->dest
		{ "sub",  "1 -= 2", 2}, //src-dest->dest
		{ "subi", "N -= 2", 2}, //imm+dest->dest
		{ "suba", "1 -= 2", 2}, //src+An->An
		{ "subq", "N -= 2", 2}, //imm+dest->dest
		{ "subx", "1-X -= 2", 2}, //dest-src-X flag->dest
		{ "tst",  "1 == NULL", 1}, //dest==0x0->ccr register
		{ "ori",  "2 |= 1", 2},
		{ "or",   "2 |= 1", 2},
		{ "lsr",  "2 >>= 1", 2},
		{ "lsl",  "2 <<= 1", 2},
		{ "and",  "1 &= 2", 2}, //src&&dest->dest
		{ "andi", "N &= 2", 2}, //imm&&dest->dest
		{ "andi to ccr", "N &= ccr", 1}, //imm&&ccr->ccr
		{ "asl",  "2 <<= 1", 2}, //dest shifted by count->dest
		{ "asr",  "2 >>= 1", 2}, //dest shifted by count->dest
		{ "nop",  "nop", 0},
//
		{ NULL }
	};

	for (i=0; ops[i].op != NULL; i++) {
		if (!strcmp (ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j=k=0;ops[i].str[j]!='\0';j++,k++) {
					if (can_replace(ops[i].str, j, ops[i].max_operands)) {
						const char *w = argv[ ops[i].str[j]-'0' ];
						if (w != NULL) {
							strcpy (newstr+k, w);
							k += strlen(w)-1;
						}
					} else {
						newstr[k] = ops[i].str[j];
					}
				}
				newstr[k]='\0';
			}
			return true;
		}
	}

	/* TODO: this is slow */
	if (newstr != NULL) {
		newstr[0] = '\0';
		for (i=0; i<argc; i++) {
			strcat (newstr, argv[i]);
			strcat (newstr, (i == 0 || i== argc - 1)?" ":", ");
		}
	}

	return false;
}

#define WSZ 64
static int parse(RParse *p, const char *data, char *str) {
	int i, len = strlen (data);
	char w0[WSZ];
	char w1[WSZ];
	char w2[WSZ];
	char w3[WSZ];
	char w4[WSZ];
	char *buf, *ptr, *optr;

	if (!strcmp (data, "jr ra")) {
		strcpy (str, "ret");
		return true;
	}

	// malloc can be slow here :?
	if (!(buf = malloc (len + 1))) {
		return false;
	}
	memcpy (buf, data, len+1);

	r_str_replace_in (buf, len+1, ".l", "", 1);
	r_str_replace_in (buf, len+1, ".w", "", 1);
	r_str_replace_in (buf, len+1, ".d", "", 1);
	r_str_replace_in (buf, len+1, ".b", "", 1);
	r_str_trim (buf);

	if (*buf) {
		w0[0]='\0';
		w1[0]='\0';
		w2[0]='\0';
		w3[0]='\0';
		w4[0]='\0';
		ptr = strchr (buf, ' ');
		if (!ptr) {
			ptr = strchr (buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr == ' '; ptr++) {
				;
			}
			strncpy (w0, buf, WSZ - 1);
			strncpy (w1, ptr, WSZ - 1);

			optr=ptr;
			ptr = strchr (ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr == ' '; ptr++) {
					;
				}
				strncpy (w1, optr, WSZ - 1);
				strncpy (w2, ptr, WSZ - 1);
				optr=ptr;
				ptr = strchr (ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr == ' '; ptr++) {
						;
					}
					strncpy (w2, optr, WSZ - 1);
					strncpy (w3, ptr, WSZ - 1);
					optr=ptr;
// bonus
					ptr = strchr (ptr, ',');
					if (ptr) {
						*ptr = '\0';
						for (++ptr; *ptr == ' '; ptr++) {
							;
						}
						strncpy (w3, optr, WSZ - 1);
						strncpy (w4, ptr, WSZ - 1);
					}
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3, w4 };
			int nw = 0;
			for (i = 0; i < 5; i++) {
				if (wa[i][0] != '\0') {
					nw++;
				}
			}
			replace (nw, wa, str);
			{
				char *pluseq = strstr (str, "+ =");
				if (pluseq) {
					memcpy (pluseq, " +=", 3);
				}
			}
		}
	}
	free (buf);
	return true;
}

RParsePlugin r_parse_plugin_m68k_pseudo = {
	.name = "m68k.pseudo",
	.desc = "M68K pseudo syntax",
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_PARSE,
	.data = &r_parse_plugin_m68k_pseudo,
	.version = R2_VERSION
};
#endif
