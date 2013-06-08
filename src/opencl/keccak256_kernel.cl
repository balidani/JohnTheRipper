/*
 * Keccak-f[1600] 256bit OpenCL
 * This software is Copyright (2013) Daniel Bali <balijanosdaniel at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Code is based on:
 * - public domain code by Matt Mahoney
 */

#include "opencl_device_info.h"

#define R 136

// One round of keccak::f()
#define F(ROUND) {                                      \
    BCa = a[0]^a[5]^a[10]^a[15]^a[20];                  \
    BCe = a[1]^a[6]^a[11]^a[16]^a[21];                  \
    BCi = a[2]^a[7]^a[12]^a[17]^a[22];                  \
    BCo = a[3]^a[8]^a[13]^a[18]^a[23];                  \
    BCu = a[4]^a[9]^a[14]^a[19]^a[24];                  \
                                                        \
    Da = BCu ^ (BCe << (1) | BCe >> (64-(1)));          \
    De = BCa ^ (BCi << (1) | BCi >> (64-(1)));          \
    Di = BCe ^ (BCo << (1) | BCo >> (64-(1)));          \
    Do = BCi ^ (BCu << (1) | BCu >> (64-(1)));          \
    Du = BCo ^ (BCa << (1) | BCa >> (64-(1)));          \
                                                        \
    a[0] ^= Da;                                         \
    BCa = a[0];                                         \
    a[6] ^= De;                                         \
                                                        \
    BCe = (a[6] << (44) | a[6] >> (64-(44)));           \
    a[12] ^= Di;                                        \
    BCi = (a[12] << (43) | a[12] >> (64-(43)));         \
    a[18] ^= Do;                                        \
    BCo = (a[18] << (21) | a[18] >> (64-(21)));         \
    a[24] ^= Du;                                        \
    BCu = (a[24] << (14) | a[24] >> (64-(14)));         \
    Eba = BCa ^((~BCe)&BCi );                           \
    Eba ^= (ulong) round_constants[ROUND];              \
    Ebe = BCe ^((~BCi)&BCo );                           \
    Ebi = BCi ^((~BCo)&BCu );                           \
    Ebo = BCo ^((~BCu)&BCa );                           \
    Ebu = BCu ^((~BCa)&BCe );                           \
                                                        \
    a[3] ^= Do;                                         \
    BCa = (a[3] << (28) | a[3] >> (64-(28)));           \
    a[9] ^= Du;                                         \
    BCe = (a[9] << (20) | a[9] >> (64-(20)));           \
    a[10] ^= Da;                                        \
    BCi = (a[10] << (3) | a[10] >> (64-(3)));           \
    a[16] ^= De;                                        \
    BCo = (a[16] << (45) | a[16] >> (64-(45)));         \
    a[22] ^= Di;                                        \
    BCu = (a[22] << (61) | a[22] >> (64-(61)));         \
    Ega = BCa ^((~BCe)&BCi );                           \
    Ege = BCe ^((~BCi)&BCo );                           \
    Egi = BCi ^((~BCo)&BCu );                           \
    Ego = BCo ^((~BCu)&BCa );                           \
    Egu = BCu ^((~BCa)&BCe );                           \
                                                        \
    a[1] ^= De;                                         \
    BCa = (a[1] << (1) | a[1] >> (64-(1)));             \
    a[7] ^= Di;                                         \
    BCe = (a[7] << (6) | a[7] >> (64-(6)));             \
    a[13] ^= Do;                                        \
    BCi = (a[13] << (25) | a[13] >> (64-(25)));         \
    a[19] ^= Du;                                        \
    BCo = (a[19] << (8) | a[19] >> (64-(8)));           \
    a[20] ^= Da;                                        \
    BCu = (a[20] << (18) | a[20] >> (64-(18)));         \
    Eka = BCa ^((~BCe)&BCi );                           \
    Eke = BCe ^((~BCi)&BCo );                           \
    Eki = BCi ^((~BCo)&BCu );                           \
    Eko = BCo ^((~BCu)&BCa );                           \
    Eku = BCu ^((~BCa)&BCe );                           \
                                                        \
    a[4] ^= Du;                                         \
    BCa = (a[4] << (27) | a[4] >> (64-(27)));           \
    a[5] ^= Da;                                         \
    BCe = (a[5] << (36) | a[5] >> (64-(36)));           \
    a[11] ^= De;                                        \
    BCi = (a[11] << (10) | a[11] >> (64-(10)));         \
    a[17] ^= Di;                                        \
    BCo = (a[17] << (15) | a[17] >> (64-(15)));         \
    a[23] ^= Do;                                        \
    BCu = (a[23] << (56) | a[23] >> (64-(56)));         \
    Ema = BCa ^((~BCe)&BCi );                           \
    Eme = BCe ^((~BCi)&BCo );                           \
    Emi = BCi ^((~BCo)&BCu );                           \
    Emo = BCo ^((~BCu)&BCa );                           \
    Emu = BCu ^((~BCa)&BCe );                           \
                                                        \
    a[2] ^= Di;                                         \
    BCa = (a[2] << (62) | a[2] >> (64-(62)));           \
    a[8] ^= Do;                                         \
    BCe = (a[8] << (55) | a[8] >> (64-(55)));           \
    a[14] ^= Du;                                        \
    BCi = (a[14] << (39) | a[14] >> (64-(39)));         \
    a[15] ^= Da;                                        \
    BCo = (a[15] << (41) | a[15] >> (64-(41)));         \
    a[21] ^= De;                                        \
    BCu = (a[21] << (2) | a[21] >> (64-(2)));           \
    Esa = BCa ^((~BCe)&BCi );                           \
    Ese = BCe ^((~BCi)&BCo );                           \
    Esi = BCi ^((~BCo)&BCu );                           \
    Eso = BCo ^((~BCu)&BCa );                           \
    Esu = BCu ^((~BCa)&BCe );                           \
                                                        \
    BCa = Eba^Ega^Eka^Ema^Esa;                          \
    BCe = Ebe^Ege^Eke^Eme^Ese;                          \
    BCi = Ebi^Egi^Eki^Emi^Esi;                          \
    BCo = Ebo^Ego^Eko^Emo^Eso;                          \
    BCu = Ebu^Egu^Eku^Emu^Esu;                          \
                                                        \
    Da = BCu ^ (BCe << (1) | BCe >> (64-(1)));          \
    De = BCa ^ (BCi << (1) | BCi >> (64-(1)));          \
    Di = BCe ^ (BCo << (1) | BCo >> (64-(1)));          \
    Do = BCi ^ (BCu << (1) | BCu >> (64-(1)));          \
    Du = BCo ^ (BCa << (1) | BCa >> (64-(1)));          \
                                                        \
    Eba ^= Da;                                          \
    BCa = Eba;                                          \
    Ege ^= De;                                          \
    BCe = (Ege << (44) | Ege >> (64-(44)));             \
    Eki ^= Di;                                          \
    BCi = (Eki << (43) | Eki >> (64-(43)));             \
    Emo ^= Do;                                          \
    BCo = (Emo << (21) | Emo >> (64-(21)));             \
    Esu ^= Du;                                          \
    BCu = (Esu << (14) | Esu >> (64-(14)));             \
    a[0] = BCa ^((~BCe)&BCi );                          \
    a[0] ^= (ulong) round_constants[ROUND+1];           \
    a[1] = BCe ^((~BCi)&BCo );                          \
    a[2] = BCi ^((~BCo)&BCu );                          \
    a[3] = BCo ^((~BCu)&BCa );                          \
    a[4] = BCu ^((~BCa)&BCe );                          \
                                                        \
    Ebo ^= Do;                                          \
    BCa = (Ebo << (28) | Ebo >> (64-(28)));             \
    Egu ^= Du;                                          \
    BCe = (Egu << (20) | Egu >> (64-(20)));             \
    Eka ^= Da;                                          \
    BCi = (Eka << (3) | Eka >> (64-(3)));               \
    Eme ^= De;                                          \
    BCo = (Eme << (45) | Eme >> (64-(45)));             \
    Esi ^= Di;                                          \
    BCu = (Esi << (61) | Esi >> (64-(61)));             \
    a[5] = BCa ^((~BCe)&BCi );                          \
    a[6] = BCe ^((~BCi)&BCo );                          \
    a[7] = BCi ^((~BCo)&BCu );                          \
    a[8] = BCo ^((~BCu)&BCa );                          \
    a[9] = BCu ^((~BCa)&BCe );                          \
                                                        \
    Ebe ^= De;                                          \
    BCa = (Ebe << (1) | Ebe >> (64-(1)));               \
    Egi ^= Di;                                          \
    BCe = (Egi << (6) | Egi >> (64-(6)));               \
    Eko ^= Do;                                          \
    BCi = (Eko << (25) | Eko >> (64-(25)));             \
    Emu ^= Du;                                          \
    BCo = (Emu << (8) | Emu >> (64-(8)));               \
    Esa ^= Da;                                          \
    BCu = (Esa << (18) | Esa >> (64-(18)));             \
    a[10] = BCa ^((~BCe)&BCi );                         \
    a[11] = BCe ^((~BCi)&BCo );                         \
    a[12] = BCi ^((~BCo)&BCu );                         \
    a[13] = BCo ^((~BCu)&BCa );                         \
    a[14] = BCu ^((~BCa)&BCe );                         \
                                                        \
    Ebu ^= Du;                                          \
    BCa = (Ebu << (27) | Ebu >> (64-(27)));             \
    Ega ^= Da;                                          \
    BCe = (Ega << (36) | Ega >> (64-(36)));             \
    Eke ^= De;                                          \
    BCi = (Eke << (10) | Eke >> (64-(10)));             \
    Emi ^= Di;                                          \
    BCo = (Emi << (15) | Emi >> (64-(15)));             \
    Eso ^= Do;                                          \
    BCu = (Eso << (56) | Eso >> (64-(56)));             \
    a[15] = BCa ^((~BCe)&BCi );                         \
    a[16] = BCe ^((~BCi)&BCo );                         \
    a[17] = BCi ^((~BCo)&BCu );                         \
    a[18] = BCo ^((~BCu)&BCa );                         \
    a[19] = BCu ^((~BCa)&BCe );                         \
                                                        \
    Ebi ^= Di;                                          \
    BCa = (Ebi << (62) | Ebi >> (64-(62)));             \
    Ego ^= Do;                                          \
    BCe = (Ego << (55) | Ego >> (64-(55)));             \
    Eku ^= Du;                                          \
    BCi = (Eku << (39) | Eku >> (64-(39)));             \
    Ema ^= Da;                                          \
    BCo = (Ema << (41) | Ema >> (64-(41)));             \
    Ese ^= De;                                          \
    BCu = (Ese << (2) | Ese >> (64-(2)));               \
    a[20] = BCa ^((~BCe)&BCi );                         \
    a[21] = BCe ^((~BCi)&BCo );                         \
    a[22] = BCi ^((~BCo)&BCu );                         \
    a[23] = BCo ^((~BCu)&BCa );                         \
    a[24] = BCu ^((~BCa)&BCe );                         \
} 

__constant ulong round_constants[] = 
{
    (ulong)0x0000000000000001UL,
    (ulong)0x0000000000008082UL,
    (ulong)0x800000000000808aUL,
    (ulong)0x8000000080008000UL,
    (ulong)0x000000000000808bUL,
    (ulong)0x0000000080000001UL,
    (ulong)0x8000000080008081UL,
    (ulong)0x8000000000008009UL,
    (ulong)0x000000000000008aUL,
    (ulong)0x0000000000000088UL,
    (ulong)0x0000000080008009UL,
    (ulong)0x000000008000000aUL,
    (ulong)0x000000008000808bUL,
    (ulong)0x800000000000008bUL,
    (ulong)0x8000000000008089UL,
    (ulong)0x8000000000008003UL,
    (ulong)0x8000000000008002UL,
    (ulong)0x8000000000000080UL,
    (ulong)0x000000000000800aUL,
    (ulong)0x800000008000000aUL,
    (ulong)0x8000000080008081UL,
    (ulong)0x8000000000008080UL,
    (ulong)0x0000000080000001UL,
    (ulong)0x8000000080008008UL
};

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) ((uchar)(buf >> index*8) & 0xff)
#define PUTCHAR(buf, index, val) (buf |= (val << index*8))

/* 
 * OpenCL kernel entry point. Copy key to be hashed from
 * global to local (thread) memory. Keccak256 hash of a key is 256 bit.
 *
 */
__kernel void keccak256(__global const uint *keys, __global const uint *index, __global uint *hashes)
{
    // Kernel variables
	uint gid = get_global_id(0);
	uint num_keys = get_global_size(0);
    
	uint base = index[gid];
	uint len = base & 63;
	uint W[16] = { 0 };
	uint i;
    
    // Keccak variables
    ulong a[25];
    uint ch;
    uint ptr;

    // keccak::f()
    ulong Da, De, Di, Do, Du;
    ulong BCa, BCe, BCi, BCo, BCu;
    ulong Eba, Ebe, Ebi, Ebo, Ebu;
    ulong Ega, Ege, Egi, Ego, Egu;
    ulong Eka, Eke, Eki, Eko, Eku;
    ulong Ema, Eme, Emi, Emo, Emu;
    ulong Esa, Ese, Esi, Eso, Esu;
    
    // Adjust keys
	keys += base >> 6;

	for (i = 0; i < (len+3)/4; i++) {
		W[i] = *keys++;
    }
    
    // keccak::init()
    for (i = 0; i < 25; ++i) {
        a[i] = 0;
    }
    ptr = 0;
        
    // keccak::put()
    for (i = 0; i < len; ++i) {
        a[ptr/8] ^= (ulong) GETCHAR(W[i/4], i%4) << (ptr%8 * 8);
        if (++ptr == R) {
            // keccak::f() * (rounds / 2)
            F(0);  F(2);  F(4);
            F(6);  F(8);  F(10);
            F(12); F(14); F(16);
            F(18); F(20); F(22);
            ptr = 0;
        }
    }
    
    // first keccak::get() (ABSORB -> SQUEEZE transition)
    if (ptr == R - 1) {
    
        // put(0x81), f() will be called afterwards
        a[ptr/8] ^= (ulong) 0x81 << (ptr%8 * 8);
        ptr++;
        
    } else {
        // put(0x01), f() won't be reached here
        a[ptr/8] ^= (ulong) 0x01 << (ptr%8 * 8);
        ptr++;
        
        while (ptr < R - 1) {
            // put(0x00, f() won't be reached here
            a[ptr/8] ^= (ulong) 0x00 << (ptr%8 * 8);
            ptr++;
        }
        
        // put(0x80), f() will be called afterwards
        a[ptr/8] ^= (ulong) 0x80 << (ptr%8 * 8);
        ptr++;
    }
    
    F(0);  F(2);  F(4);
    F(6);  F(8);  F(10);
    F(12); F(14); F(16);
    F(18); F(20); F(22);
    ptr = 0;
    
    // (Hack) clear output buffers first
    for (i = 0; i < 32; ++i) {
        hashes[(i/4) * num_keys + gid] = 0;
    }
    
    // keccak::get()
    for (i = 0; i < 32; ++i) {
    
        if (ptr == R) {
            F(0);  F(2);  F(4);
            F(6);  F(8);  F(10);
            F(12); F(14); F(16);
            F(18); F(20); F(22);
            ptr = 0;
        }
        
        ch = (a[ptr / 8] >> (ptr%8 * 8)) & 0xFF;
        ptr++;
        PUTCHAR(hashes[(i/4) * num_keys + gid], i%4, ch);
        
        //4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    }
}
