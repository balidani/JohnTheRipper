/* 
 * Keccak-256 OpenCL version
 * by Daniel Bali <balijanosdaniel at gmail.com>
 * based on public domain code by Matt Mahoney
 * based on rawKeccak256_fmt.c by Dhiru Kholia
 *
 * Usage: john --format:raw-keccak-256-opencl <hash file>
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 *
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"

#define FORMAT_TAG			"$keccak256$"
#define TAG_LENGTH			11

#define FORMAT_LABEL		"raw-keccak-256-opencl"
#define FORMAT_NAME			"Keccak 256"
#define ALGORITHM_NAME		"OpenCL (inefficient, development use only)"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	125
#define CIPHERTEXT_LENGTH	64

#define BINARY_SIZE			32
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define uint64_t unsigned long long int

// Keccak related variables

const int r = 1088;						// Rate
uint64_t a[25];							// Keccak hash
unsigned ptr;							// Next byte to get/put (range 0..136)
enum {ABSORB, SQUEEZE} sponge_state;	// Sponge's current state
int i;

static struct fmt_tests tests[] = {
	{"$keccak256$4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", "abc"},
	{NULL}
};

static int (*saved_key_length);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)
	[(BINARY_SIZE + sizeof(ARCH_WORD_32) - 1) / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
	saved_key_length = mem_calloc_tiny(sizeof(*saved_key_length) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
	p += TAG_LENGTH;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
	q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
	return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + TAG_LENGTH);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < BINARY_SIZE; i++) {
	out[i] =
	(atoi16[ARCH_INDEX(*p)] << 4) |
	atoi16[ARCH_INDEX(p[1])];
	p += 2;
	}
	return out;
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
	return crypt_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
	return crypt_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
	return crypt_out[index][0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return crypt_out[index][0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return crypt_out[index][0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	return crypt_out[index][0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return crypt_out[index][0] & 0x7FFFFFF;
}

static void set_key(char *key, int index)
{
	int len = strlen(key);
	saved_key_length[index] = len;
	if (len > PLAINTEXT_LENGTH)
	len = saved_key_length[index] = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
}

static char *get_key(int index)
{
	saved_key[index][saved_key_length[index]] = 0;
	return saved_key[index];
}

// keccak::rol()
static uint64_t rol(uint64_t x, unsigned ro) 
{
	ro &= 63;
	return x << ro | x >> (64-ro);
}

// keccak::f()
static void f() 
{
	static const uint64_t keccak_round_constants[] = 
	{
	(uint64_t)0x0000000000000001ULL,
	(uint64_t)0x0000000000008082ULL,
	(uint64_t)0x800000000000808aULL,
	(uint64_t)0x8000000080008000ULL,
	(uint64_t)0x000000000000808bULL,
	(uint64_t)0x0000000080000001ULL,
	(uint64_t)0x8000000080008081ULL,
	(uint64_t)0x8000000000008009ULL,
	(uint64_t)0x000000000000008aULL,
	(uint64_t)0x0000000000000088ULL,
	(uint64_t)0x0000000080008009ULL,
	(uint64_t)0x000000008000000aULL,
	(uint64_t)0x000000008000808bULL,
	(uint64_t)0x800000000000008bULL,
	(uint64_t)0x8000000000008089ULL,
	(uint64_t)0x8000000000008003ULL,
	(uint64_t)0x8000000000008002ULL,
	(uint64_t)0x8000000000000080ULL,
	(uint64_t)0x000000000000800aULL,
	(uint64_t)0x800000008000000aULL,
	(uint64_t)0x8000000080008081ULL,
	(uint64_t)0x8000000000008080ULL,
	(uint64_t)0x0000000080000001ULL,
	(uint64_t)0x8000000080008008ULL
	};

	uint64_t Da, De, Di, Do, Du;
	uint64_t BCa, BCe, BCi, BCo, BCu;
	uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
	uint64_t Ega, Ege, Egi, Ego, Egu;
	uint64_t Eka, Eke, Eki, Eko, Eku;
	uint64_t Ema, Eme, Emi, Emo, Emu;
	uint64_t Esa, Ese, Esi, Eso, Esu;
	// const int rounds=2*(9+(sizeof(T)>=2)+(sizeof(T)>=4)+(sizeof(T)==8));
	const int rounds = 24;
	int round;
	for (round = 0; round < rounds; round += 2)
	{
		// prepareTheta
		BCa = a[0]^a[5]^a[10]^a[15]^a[20];
		BCe = a[1]^a[6]^a[11]^a[16]^a[21];
		BCi = a[2]^a[7]^a[12]^a[17]^a[22];
		BCo = a[3]^a[8]^a[13]^a[18]^a[23];
		BCu = a[4]^a[9]^a[14]^a[19]^a[24];

		// thetaRhoPiChiIotaPrepareTheta(round, A, E)
		Da = BCu ^ rol(BCe, 1);
		De = BCa ^ rol(BCi, 1);
		Di = BCe ^ rol(BCo, 1);
		Do = BCi ^ rol(BCu, 1);
		Du = BCo ^ rol(BCa, 1);

		a[0] ^= Da;
		BCa = a[0];
		a[6] ^= De;
		BCe = rol(a[6], 44);
		a[12] ^= Di;
		BCi = rol(a[12], 43);
		a[18] ^= Do;
		BCo = rol(a[18], 21);
		a[24] ^= Du;
		BCu = rol(a[24], 14);
		Eba =   BCa ^((~BCe)&  BCi );
		Eba ^= (uint64_t)keccak_round_constants[round];
		Ebe =   BCe ^((~BCi)&  BCo );
		Ebi =   BCi ^((~BCo)&  BCu );
		Ebo =   BCo ^((~BCu)&  BCa );
		Ebu =   BCu ^((~BCa)&  BCe );

		a[3] ^= Do;
		BCa = rol(a[3], 28);
		a[9] ^= Du;
		BCe = rol(a[9], 20);
		a[10] ^= Da;
		BCi = rol(a[10],  3);
		a[16] ^= De;
		BCo = rol(a[16], 45);
		a[22] ^= Di;
		BCu = rol(a[22], 61);
		Ega =   BCa ^((~BCe)&  BCi );
		Ege =   BCe ^((~BCi)&  BCo );
		Egi =   BCi ^((~BCo)&  BCu );
		Ego =   BCo ^((~BCu)&  BCa );
		Egu =   BCu ^((~BCa)&  BCe );

		a[1] ^= De;
		BCa = rol(a[1],  1);
		a[7] ^= Di;
		BCe = rol(a[7],  6);
		a[13] ^= Do;
		BCi = rol(a[13], 25);
		a[19] ^= Du;
		BCo = rol(a[19],  8);
		a[20] ^= Da;
		BCu = rol(a[20], 18);
		Eka =   BCa ^((~BCe)&  BCi );
		Eke =   BCe ^((~BCi)&  BCo );
		Eki =   BCi ^((~BCo)&  BCu );
		Eko =   BCo ^((~BCu)&  BCa );
		Eku =   BCu ^((~BCa)&  BCe );

		a[4] ^= Du;
		BCa = rol(a[4], 27);
		a[5] ^= Da;
		BCe = rol(a[5], 36);
		a[11] ^= De;
		BCi = rol(a[11], 10);
		a[17] ^= Di;
		BCo = rol(a[17], 15);
		a[23] ^= Do;
		BCu = rol(a[23], 56);
		Ema =   BCa ^((~BCe)&  BCi );
		Eme =   BCe ^((~BCi)&  BCo );
		Emi =   BCi ^((~BCo)&  BCu );
		Emo =   BCo ^((~BCu)&  BCa );
		Emu =   BCu ^((~BCa)&  BCe );

		a[2] ^= Di;
		BCa = rol(a[2], 62);
		a[8] ^= Do;
		BCe = rol(a[8], 55);
		a[14] ^= Du;
		BCi = rol(a[14], 39);
		a[15] ^= Da;
		BCo = rol(a[15], 41);
		a[21] ^= De;
		BCu = rol(a[21],  2);
		Esa =   BCa ^((~BCe)&  BCi );
		Ese =   BCe ^((~BCi)&  BCo );
		Esi =   BCi ^((~BCo)&  BCu );
		Eso =   BCo ^((~BCu)&  BCa );
		Esu =   BCu ^((~BCa)&  BCe );

		// prepareTheta
		BCa = Eba^Ega^Eka^Ema^Esa;
		BCe = Ebe^Ege^Eke^Eme^Ese;
		BCi = Ebi^Egi^Eki^Emi^Esi;
		BCo = Ebo^Ego^Eko^Emo^Eso;
		BCu = Ebu^Egu^Eku^Emu^Esu;

		// thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
		Da = BCu ^ rol(BCe, 1);
		De = BCa ^ rol(BCi, 1);
		Di = BCe ^ rol(BCo, 1);
		Do = BCi ^ rol(BCu, 1);
		Du = BCo ^ rol(BCa, 1);

		Eba ^= Da;
		BCa = Eba;
		Ege ^= De;
		BCe = rol(Ege, 44);
		Eki ^= Di;
		BCi = rol(Eki, 43);
		Emo ^= Do;
		BCo = rol(Emo, 21);
		Esu ^= Du;
		BCu = rol(Esu, 14);
		a[0] =   BCa ^((~BCe)&  BCi );
		a[0] ^= (uint64_t)keccak_round_constants[round+1];
		a[1] =   BCe ^((~BCi)&  BCo );
		a[2] =   BCi ^((~BCo)&  BCu );
		a[3] =   BCo ^((~BCu)&  BCa );
		a[4] =   BCu ^((~BCa)&  BCe );

		Ebo ^= Do;
		BCa = rol(Ebo, 28);
		Egu ^= Du;
		BCe = rol(Egu, 20);
		Eka ^= Da;
		BCi = rol(Eka, 3);
		Eme ^= De;
		BCo = rol(Eme, 45);
		Esi ^= Di;
		BCu = rol(Esi, 61);
		a[5] =   BCa ^((~BCe)&  BCi );
		a[6] =   BCe ^((~BCi)&  BCo );
		a[7] =   BCi ^((~BCo)&  BCu );
		a[8] =   BCo ^((~BCu)&  BCa );
		a[9] =   BCu ^((~BCa)&  BCe );

		Ebe ^= De;
		BCa = rol(Ebe, 1);
		Egi ^= Di;
		BCe = rol(Egi, 6);
		Eko ^= Do;
		BCi = rol(Eko, 25);
		Emu ^= Du;
		BCo = rol(Emu, 8);
		Esa ^= Da;
		BCu = rol(Esa, 18);
		a[10] =   BCa ^((~BCe)&  BCi );
		a[11] =   BCe ^((~BCi)&  BCo );
		a[12] =   BCi ^((~BCo)&  BCu );
		a[13] =   BCo ^((~BCu)&  BCa );
		a[14] =   BCu ^((~BCa)&  BCe );

		Ebu ^= Du;
		BCa = rol(Ebu, 27);
		Ega ^= Da;
		BCe = rol(Ega, 36);
		Eke ^= De;
		BCi = rol(Eke, 10);
		Emi ^= Di;
		BCo = rol(Emi, 15);
		Eso ^= Do;
		BCu = rol(Eso, 56);
		a[15] =   BCa ^((~BCe)&  BCi );
		a[16] =   BCe ^((~BCi)&  BCo );
		a[17] =   BCi ^((~BCo)&  BCu );
		a[18] =   BCo ^((~BCu)&  BCa );
		a[19] =   BCu ^((~BCa)&  BCe );

		Ebi ^= Di;
		BCa = rol(Ebi, 62);
		Ego ^= Do;
		BCe = rol(Ego, 55);
		Eku ^= Du;
		BCi = rol(Eku, 39);
		Ema ^= Da;
		BCo = rol(Ema, 41);
		Ese ^= De;
		BCu = rol(Ese, 2);
		a[20] =   BCa ^((~BCe)&  BCi );
		a[21] =   BCe ^((~BCi)&  BCo );
		a[22] =   BCi ^((~BCo)&  BCu );
		a[23] =   BCo ^((~BCu)&  BCa );
		a[24] =   BCu ^((~BCa)&  BCe );
	}
	ptr = 0;
}

// keccak::put(c)
static void put(int c) 
{
	a[ptr/8] ^= (uint64_t)c << (ptr % 8*8);
	if (++ptr == r/8) 
	{
		f();
	}
}

// keccak::get()
static int get()
{
	int c;
	if (sponge_state == ABSORB) {   // first get()
	
		if (ptr == r/8 - 1) {
			put(0x81);
		} else {
			put(1);
			
			while (ptr < r/8-1) {
				put(0);
			}
			
			put(0x80);
		}
		
		sponge_state = SQUEEZE;
	}
	
	if (ptr == r/8) {
		f();
	}
	
	c = (a[ptr / 8] >> (ptr % 8*8)) & 0xFF;
	++ptr;
	return c;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
	for (index = 0; index < count; index++)
	{
		// Counter that is needed to set crypt_out
		int byte_count;
		
		// keccak::init()
		memset(a, 0, sizeof(a));
		ptr = 0;
		sponge_state = ABSORB;
		memset(crypt_out[index], 0, sizeof(crypt_out[index]));
		
		for (i = 0; i < saved_key_length[index]; ++i)
		{
			// keccak::put()
			put(saved_key[index][i]);
		}
		
		byte_count = 0;
		
		for (i = 0; i < 32; ++i) 
		{
			// keccak::get()
			int c = get();
			crypt_out[index][byte_count / sizeof(ARCH_WORD_32)] |= c << (8 * (byte_count % sizeof(ARCH_WORD_32)));
			byte_count++;
		}
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
	if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
	return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_rawKeccak256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
}; 