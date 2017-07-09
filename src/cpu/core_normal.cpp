/*
 *  Copyright (C) 2002-2015  The DOSBox Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include "dosbox.h"
#include "mem.h"
#include "cpu.h"
#include "lazyflags.h"
#include "inout.h"
#include "callback.h"
#include "pic.h"
#include "fpu.h"
#include "paging.h"

#if C_DEBUG
#include "debug.h"
#endif

#if (!C_CORE_INLINE)
#define LoadMb(off) mem_readb(off)
#define LoadMw(off) mem_readw(off)
#define LoadMd(off) mem_readd(off)
#define SaveMb(off,val)	mem_writeb(off,val)
#define SaveMw(off,val)	mem_writew(off,val)
#define SaveMd(off,val)	mem_writed(off,val)
#else 
#error "Inline is set"
#include "paging.h"
#define LoadMb(off) mem_readb_inline(off)
#define LoadMw(off) mem_readw_inline(off)
#define LoadMd(off) mem_readd_inline(off)
#define SaveMb(off,val)	mem_writeb_inline(off,val)
#define SaveMw(off,val)	mem_writew_inline(off,val)
#define SaveMd(off,val)	mem_writed_inline(off,val)
#endif

extern Bitu cycle_count;

#if C_FPU
#define CPU_FPU	1						//Enable FPU escape instructions
#endif

#define CPU_PIC_CHECK 1
#define CPU_TRAP_CHECK 1

#define OPCODE_NONE			0x000
#define OPCODE_0F			0x100
#define OPCODE_SIZE			0x200

#define PREFIX_ADDR			0x1
#define PREFIX_REP			0x2

#define TEST_PREFIX_ADDR	(core.prefixes & PREFIX_ADDR)
#define TEST_PREFIX_REP		(core.prefixes & PREFIX_REP)

#define DO_PREFIX_SEG(_SEG)					\
	BaseDS=SegBase(_SEG);					\
	BaseSS=SegBase(_SEG);					\
	core.base_val_ds=_SEG;					\
	goto restart_opcode;

#define DO_PREFIX_ADDR()								\
	core.prefixes=(core.prefixes & ~PREFIX_ADDR) |		\
	(cpu.code.big ^ PREFIX_ADDR);						\
	core.ea_table=&EATable[(core.prefixes&1) * 256];	\
	goto restart_opcode;

#define DO_PREFIX_REP(_ZERO)				\
	core.prefixes|=PREFIX_REP;				\
	core.rep_zero=_ZERO;					\
	goto restart_opcode;

typedef PhysPt (*GetEAHandler)(void);

static const Bit32u AddrMaskTable[2]={0x0000ffff,0xffffffff};

static struct {
	Bitu opcode_index;
	PhysPt cseip;
	PhysPt base_ds,base_ss;
	SegNames base_val_ds;
	bool rep_zero;
	Bitu prefixes;
	GetEAHandler * ea_table;
} core;

#define GETIP		(core.cseip-SegBase(cs))
#define SAVEIP		reg_eip=GETIP;
#define LOADIP		core.cseip=(SegBase(cs)+reg_eip);

#define SegBase(c)	SegPhys(c)
#define BaseDS		core.base_ds
#define BaseSS		core.base_ss

static INLINE Bit8u Fetchb() {
	Bit8u temp=LoadMb(core.cseip);
	core.cseip+=1;
	return temp;
}

static INLINE Bit16u Fetchw() {
	Bit16u temp=LoadMw(core.cseip);
	core.cseip+=2;
	return temp;
}
static INLINE Bit32u Fetchd() {
	Bit32u temp=LoadMd(core.cseip);
	core.cseip+=4;
	return temp;
}

#define Push_16 CPU_Push16
#define Push_32 CPU_Push32
#define Pop_16 CPU_Pop16
#define Pop_32 CPU_Pop32

#include "instructions.h"
#include "core_normal/support.h"
#include "core_normal/string.h"


#define EALookupTable (core.ea_table)

#if defined(FUNARRAY_CORE) && !defined(GET_X86_FUNCTIONS)
#include "core_funarray.h"
#include "core_normal_fun.h"
#endif

Bit32u GetAddress(Bit16u seg, Bit32u offset);

FILE *memlog = fopen("/tmp/mem.txt", "a");
FILE *debuglog = fopen("/tmp/debug.txt", "a");

int fire_fifo = open("/tmp/fire.fifo", O_RDONLY|O_NONBLOCK);

int manualDoDamage = 0;

void process_network() {
#if 0
    static int ctr = 0;
    if ((ctr++ % 500) == 0) {
        /*fprintf(memlog, "pos: ");
        for (int addr = 0x1E6F2; addr < 0x1e6f2 + 12; addr += 4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%d ", (int)val);
        }*/
        for (int addr = 0xA9C2+0x13d30, i=0; i<0x3e; i += 1, addr+=12) {
            unsigned int valx;
            unsigned int valy;
            unsigned int valz;
            mem_readd_checked(addr, &valx);
            mem_readd_checked(addr + 0x4, &valy);
            mem_readd_checked(addr + 0x8, &valz);
            if (valx != 0 || valy != 0 || valz != 0) {
                fprintf(memlog, "%d:(%8d,%8d,%8d)", i, valx, valy, valz);
            }
        }
        /*
        fprintf(memlog, " pos: ");
        for (int addr = 0xA9C2+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        fprintf(memlog, " vel: ");
        for (int addr = 0xCAE2+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        fprintf(memlog, " RGT: ");
        for (int addr = 0xAEB6+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        fprintf(memlog, " UP: ");
        for (int addr = 0xB1B6+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        fprintf(memlog, " FWD: ");
        for (int addr = 0xB4B6+0x13d30, i=0; i<6; i += 1, addr+=4) {
            unsigned int val;
            mem_readd_checked(addr, &val);
            fprintf(memlog, "%.02f ", ((float)(int)val)/256.);
            if (i == 2) {
                addr += (0x3d - 1) * 12;
            }
        }
        */
        fprintf(memlog, "\n");
        fflush(memlog);
    }
#endif
    {
        char buf[1];
        if (read(fire_fifo, &buf, 1) > 0) {
            fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
            CPU_Push16((Bit16u)SegValue(cs));
            CPU_Push16((Bit16u)reg_eip);
            uint32_t data_segment_start = 0x13d30;
            uint32_t loading_wing_commander_start = 0x0187;
            if (buf[0] == ' ') { // fire all guns
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags, push all regs, xor si,si, push si
                    0x9C, 0x60, 0x33, 0xF6, 0x56,
                    // call far 12d7:0156
                    0x9A, 0x56, 0x01, 0xd7, 0x12,
                    // pop si, pop all regs, pop flags, retf
                    0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }
            } else if (buf[0] == ',') {
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags, push all regs, xor si,si, push si
                    0x9C, 0x60, 0x33, 0xF6, 0x56, 0x56,
                    // call far 12d7:012E
                    0x9A, 0x56, 0x01, 0xd7, 0x12,
                    // pop si, pop all regs, pop flags, retf
                    0x5E, 0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }
            } else if (buf[0] == '.') {
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags, push all regs, xor si,si, push si
                    0x9C, 0x60,
                    0xbe, 0, 0,// mov si <-- gun_id
                    0x56,
                    // call far 12d7:0156
                    0x9A, 0x56, 0x01, 0xd7, 0x12,
                    // pop si, pop all regs, pop flags, retf
                    0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }
            } else if (buf[0] == 'f') { // fire one gun from a selected ship
                buf[0] = 0;
                read(fire_fifo, &buf, 1);
                uint32_t gun_id = 0;
                uint32_t ship_id = 0;
                if (buf[0] >= '0' && buf[0] <= '9') {
                    gun_id = buf[0] - '0';
                } else if (buf[0] >= 'a' && buf[0] <= 'z') {
                    gun_id = buf[0] - 'a';
                    ship_id = 1;
                } else if (buf[0] >= 'A' && buf[0] <= 'Z') {
                    gun_id = buf[0] - 'A';
                    ship_id = 2;
                }
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags,
                    0x9C, //PUSHF
                    //push all regs, xor si,si, push si
                    0x60, //PUSHA
                    0xbe, gun_id & 0xff, gun_id >> 8,// mov si <-- gun_id
                    0x56, // push si
                    0xbe, ship_id & 0xff, ship_id >> 8, // mov si <- ship_id
                    0x56, // push si
                    // call far 12d7:012E
                    0x9A, 0x2E, 0x01, 0xd7, 0x12,
                    // pop si, pop si, pop all regs, pop flags, retf
                    0x5E, 0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }                
            } else if (buf[0] == 'd') {
                unsigned short arg_0, arg_2, arg_4, arg_6;
                char argbuf[100] = {0};
                int i;
                for (i = 0; i < 99;) {
                    if (read(fire_fifo, argbuf + i, 1) <= 0) {
                        if (errno != EAGAIN && errno != EINTR) {
                            break;
                        }
                    } else {
                        if (argbuf[i] == '\n') {
                            break;
                        }
                        i++;
                    }
                }
                argbuf[i] = '\0';
                sscanf(argbuf ,"%hd %hd %hd %hd", &arg_0, &arg_2, &arg_4, &arg_6);
                Bit8u shellcode[] = {
                    0x00, // nul terminate string
                    // push flags,
                    0x9C, //PUSHF
                    //push all regs, xor si,si, push si
                    0x60, //PUSHA
                    0xbe, arg_6 & 0xff, arg_6 >> 8,
                    0x56, // push si
                    0xbe, arg_4 & 0xff, arg_4 >> 8,
                    0x56, // push si
                    0xbe, arg_2 & 0xff, arg_2 >> 8,
                    0x56, // push si
                    0xbe, arg_0 & 0xff, arg_0 >> 8,
                    0x56, // push si
                    // call far 12d7:012E
                    0x9A, 0x84, 0x00, 0xd7, 0x12,
                    // pop si, pop si, pop all regs, pop flags, retf
                    0x5E, 0x5E, 0x5E, 0x5E, 0x61, 0x9D, 0xCB
                };
                for (int i = 0; i < sizeof(shellcode); i++) {
                    mem_writeb_checked(data_segment_start + loading_wing_commander_start + i, shellcode[i]);
                }                
            }
            manualDoDamage ++;
            SegSet16(cs, data_segment_start >> 4);
            reg_eip = loading_wing_commander_start + 1;
            fprintf(debuglog, "cs:eip = %04x:%04x\n", SegValue(cs), reg_eip);
        }
    }

}

bool isExecutingFunction(Bit16u stubSeg, Bit16u stubOff) {
    Bit8u instType = mem_readb(stubSeg * 0x10 + stubOff);
    if (instType != 0xea) {
        return false;
    }
    Bit16u realOff = mem_readw(stubSeg * 0x10 + stubOff + 1);
    Bit16u realSeg = mem_readw(stubSeg * 0x10 + stubOff + 3);
    if (SegValue(cs) == realSeg && reg_eip == realOff) {
        return true;
    }
    return false;
}

Bits CPU_Core_Normal_Run(void) {
	while (CPU_Cycles-->0) {
        if (isExecutingFunction(0x12d7, 0x0084)) {
            // beginning of doDamage.
            if (manualDoDamage) {
                manualDoDamage --;
            } else {
                Bit16u arg0 = mem_readw(0x13d30 + reg_esp + 4);
                Bit16u arg2 = mem_readw(0x13d30 + reg_esp + 6);
                Bit16u arg4 = mem_readw(0x13d30 + reg_esp + 8);
                Bit16u arg6 = mem_readw(0x13d30 + reg_esp + 10);
                Bit32u xcoord = mem_readd(0x13d30 + arg6);
                Bit32u ycoord = mem_readd(0x13d30 + arg6 + 4);
                Bit32u zcoord = mem_readd(0x13d30 + arg6 + 8);
                Bit32u randomSeed = mem_readd(0x13d30 + 0x7728);
                fprintf(stderr, "\r\ndoDamage(%d, %d, %d, <%d, %d, %d>) rng=%x\r\n",
                    arg0, arg2, arg4, xcoord, ycoord, zcoord, randomSeed);
                reg_eip = 0x0d44;
            }
        }
        if (SegValue(cs) == 0x0560 && reg_eip == 0x20e3) {
            // this is the beginning of the WC main loop while in fighting.
            // then we can process network commands here and introduce things
            // before the frame is processed in a predictable place
            process_network();
        }
		LOADIP;
		core.opcode_index=cpu.code.big*0x200;
		core.prefixes=cpu.code.big;
		core.ea_table=&EATable[cpu.code.big*256];
		BaseDS=SegBase(ds);
		BaseSS=SegBase(ss);
		core.base_val_ds=ds;
#if C_DEBUG
#if C_HEAVY_DEBUG
		if (DEBUG_HeavyIsBreakpoint()) {
			FillFlags();
			return debugCallback;
		};
#endif
		cycle_count++;
#endif
restart_opcode:
#if defined(FUNARRAY_CORE) && !defined(GET_X86_FUNCTIONS)
		FUNARRAY_CODE(core.opcode_index+Fetchb(), x86_funptr)
#else /* Switch statement core */
		switch (core.opcode_index+Fetchb()) {
		#include "core_normal/prefix_none.h"
		#include "core_normal/prefix_0f.h"
		#include "core_normal/prefix_66.h"
		#include "core_normal/prefix_66_0f.h"
		default:
		illegal_opcode:
#endif /* Switch statement core */
#if C_DEBUG	
			{
				Bitu len=(GETIP-reg_eip);
				LOADIP;
				if (len>16) len=16;
				char tempcode[16*2+1];char * writecode=tempcode;
				for (;len>0;len--) {
					sprintf(writecode,"%02X",mem_readb(core.cseip++));
					writecode+=2;
				}
				LOG(LOG_CPU,LOG_NORMAL)("Illegal/Unhandled opcode %s",tempcode);
			}
#endif
			CPU_Exception(6,0);
			continue;
		}
		SAVEIP;
	}
	FillFlags();
	return CBRET_NONE;
decode_end:
	SAVEIP;
	FillFlags();
	return CBRET_NONE;
}

Bits CPU_Core_Normal_Trap_Run(void) {
	Bits oldCycles = CPU_Cycles;
	CPU_Cycles = 1;
	cpu.trap_skip = false;

	Bits ret=CPU_Core_Normal_Run();
	if (!cpu.trap_skip) CPU_HW_Interrupt(1);
	CPU_Cycles = oldCycles-1;
	cpudecoder = &CPU_Core_Normal_Run;

	return ret;
}



void CPU_Core_Normal_Init(void) {

}

