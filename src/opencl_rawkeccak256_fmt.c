/*
 * Keccak-f[1600] 256bit OpenCL
 * This software is Copyright (2013) Daniel Bali <balijanosdaniel at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Code is based on:
 * - rawKeccak256_fmt.c by Dhiru Kholia
 */

// Remove me
#include <stdio.h>

#include <string.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "common.h"
#include "formats.h"
#include "common-opencl.h"
#include "config.h"
#include "options.h"

#define PLAINTEXT_LENGTH	55 // TODO
#define BUFSIZE				((PLAINTEXT_LENGTH+3)/4*4)
#define FORMAT_LABEL		"raw-keccak256-opencl"
#define FORMAT_NAME			"Raw Keccak256"
#define ALGORITHM_NAME		"OpenCL (inefficient, development use only)"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define CIPHERTEXT_LENGTH	64
#define DIGEST_SIZE			32
#define BINARY_SIZE			8
#define SALT_SIZE			0

#define FORMAT_TAG			"$keccak256$"
#define TAG_LENGTH			(sizeof(FORMAT_TAG) - 1)

cl_command_queue queue_prof;
cl_mem pinned_saved_keys, pinned_saved_idx, pinned_partial_hashes;
cl_mem buffer_keys, buffer_idx, buffer_out;
static cl_uint *partial_hashes;
static cl_uint *res_hashes;
static unsigned int *saved_plain, *saved_idx;
static unsigned int key_idx = 0;

#define MIN(a, b)			(((a) > (b)) ? (b) : (a))
#define MAX(a, b)			(((a) > (b)) ? (a) : (b))

#define MIN_KEYS_PER_CRYPT	1024
#define MAX_KEYS_PER_CRYPT	(1024 * 2048)

#define CONFIG_NAME			"rawkeccak256"
#define STEP				65536

static int have_full_hashes;
static int benchmark;

static const char * warn[] = {
	"pass xfer: "  ,  ", crypt: "	,  ", result xfer: "
};

extern void common_find_best_lws(size_t group_size_limit,
		unsigned int sequential_id, cl_kernel crypt_kernel);
extern void common_find_best_gws(int sequential_id, unsigned int rounds, int step,
		unsigned long long int max_run_time);

static int crypt_all(int *pcount, struct db_salt *_salt);

static struct fmt_tests tests[] = {
	{"$keccak256$03e4e5ecfffaffe3728385714072a7db00700be157e11a9c21002071bd6788d9", "openwall"},
	{"$keccak256$9c4b7a6b4af91b44be8d9bb66d41e82589f01974702d3bf1d9b4407a55593c3c", "john"},
	{"$keccak256$4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", "abc"},
	{"$keccak256$c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", ""},
	{"$keccak256$64a9ecdbdf4acaf9e5ff535ee9b20fa371b352133bda4d9e159b36f428adad16", 
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	{NULL}
};

static void create_clobj(int kpc, struct fmt_main * self)
{
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = kpc;

	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");
	saved_plain = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_saved_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");
	saved_idx = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	res_hashes = malloc(sizeof(cl_uint) * (BINARY_SIZE - 1) * kpc);

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, BUFSIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	buffer_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_idx");

	buffer_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, DIGEST_SIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_idx), (void *) &buffer_idx), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 3");

	global_work_size = kpc;
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes, partial_hashes, 0,NULL,NULL), "Error Unmapping partial_hashes");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");

	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys");
	HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Error Releasing buffer_idx");
	HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Error Releasing buffer_out");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys");
	HANDLE_CLERROR(clReleaseMemObject(pinned_partial_hashes), "Error Releasing pinned_partial_hashes");
	MEM_FREE(res_hashes);
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

/* ------- Try to find the best configuration ------- */
/* --
   This function could be used to calculate the best num
   for the workgroup
   Work-items that make up a work-group (also referred to
   as the size of the work-group)
   -- */
static void find_best_lws(struct fmt_main * self, int sequential_id) {

	// Call the default function.
	common_find_best_lws(
		get_current_work_group_size(ocl_gpu_id, crypt_kernel),
		sequential_id, crypt_kernel
		);
}

/* --
   This function could be used to calculated the best num
   of keys per crypt for the given format
   -- */
static void find_best_gws(struct fmt_main * self, int sequential_id) {

	// Call the common function.
	common_find_best_gws(
		sequential_id, 1, 0,
		(cpu(device_info[ocl_gpu_id]) ? 500000000ULL : 1000000000ULL)
		);

	create_clobj(global_work_size, self);
}

static void init(struct fmt_main *self)
{
	size_t selected_gws, max_mem;

	opencl_init("$JOHN/kernels/keccak256_kernel.cl", ocl_gpu_id);
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "keccak256", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	local_work_size = global_work_size = 0;
	opencl_get_user_preferences(CONFIG_NAME);

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(STEP, 0, 3, NULL, warn,
			&multi_profilingEvent[1], self, create_clobj,
			release_clobj, BUFSIZE, 0);

	benchmark = 1;
	self->methods.crypt_all = crypt_all;

	self->params.max_keys_per_crypt = (global_work_size ?
			global_work_size : MAX_KEYS_PER_CRYPT);
	selected_gws = global_work_size;

	if (!local_work_size) {
		create_clobj(self->params.max_keys_per_crypt, self);
		find_best_lws(self, ocl_gpu_id);
		release_clobj();
	}
	global_work_size = selected_gws;

	// Obey device limits
	if (local_work_size > get_current_work_group_size(ocl_gpu_id, crypt_kernel))
		local_work_size = get_current_work_group_size(ocl_gpu_id, crypt_kernel);
	clGetDeviceInfo(devices[ocl_gpu_id], CL_DEVICE_MAX_MEM_ALLOC_SIZE,
			sizeof(max_mem), &max_mem, NULL);
	while (global_work_size > MIN((1<<26)*4/56, max_mem / BUFSIZE))
		global_work_size -= local_work_size;

	if (global_work_size)
		create_clobj(global_work_size, self);
	else {
		find_best_gws(self, ocl_gpu_id);
	}
	if (options.verbosity > 2)
		fprintf(stderr,
				"Local worksize (LWS) %zd, global worksize (GWS) %zd\n",
				local_work_size, global_work_size);
	self->params.min_keys_per_crypt = local_work_size;
	self->params.max_keys_per_crypt = global_work_size;

	benchmark = 0;
	// self->methods.crypt_all = crypt_all;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'A' && *q <= 'F') /* support lowercase only */
			return 0;
		q++;
	}
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[DIGEST_SIZE];
	char *p;
	int i;
	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < sizeof(out); i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}
static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *) binary & 0xF; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFF; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFF; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *) binary & 0x7FFFFFF; }

static int get_hash_0(int index) { return partial_hashes[index] & 0xF; }
static int get_hash_1(int index) { return partial_hashes[index] & 0xFF; }
static int get_hash_2(int index) { return partial_hashes[index] & 0xFFF; }
static int get_hash_3(int index) { return partial_hashes[index] & 0xFFFF; }
static int get_hash_4(int index) { return partial_hashes[index] & 0xFFFFF; }
static int get_hash_5(int index) { return partial_hashes[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return partial_hashes[index] & 0x7FFFFFF; }

static void clear_keys(void)
{
	key_idx = 0;
}

static void set_key(char *_key, int index)
{
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	int len = strlen(_key);

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		saved_plain[key_idx++] = *key++;
		len -= 4;
	}
	if (len)
		saved_plain[key_idx++] = *key & (0xffffffffU >> (32 - (len << 3)));
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index] & 63;
	char *key = (char*)&saved_plain[saved_idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;
	return out;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
    cl_event *event = NULL;
	
	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

#define HANDLE_BENCHCL(cl_error, message)								\
        	if (benchmark) { BENCH_CLERROR((cl_error), (message)); }	\
        	else { HANDLE_CLERROR((cl_error), (message)); }

	// copy keys to the device
	if (benchmark) event = &multi_profilingEvent[0];
	HANDLE_BENCHCL(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0, 4 * key_idx, saved_plain, 0, NULL, event), "failed in clEnqueueWriteBuffer buffer_keys");
	HANDLE_BENCHCL(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_idx, CL_TRUE, 0, 4 * global_work_size, saved_idx, 0, NULL, event), "failed in clEnqueueWriteBuffer buffer_idx");

	if (benchmark) event = &multi_profilingEvent[1];
	HANDLE_BENCHCL(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, event), "failed in clEnqueueNDRangeKernel");

	// read back partial hashes
	if (benchmark) event = &multi_profilingEvent[2];
	HANDLE_BENCHCL(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * global_work_size, partial_hashes, 0, NULL, event), "failed in reading data back");

#undef HANDLE_BENCHCL

	have_full_hashes = 0;
	
	return count;
}

static int cmp_all(void *binary, int count)
{
	unsigned int i;
	unsigned int b = ((unsigned int *) binary)[0];

	for (i = 0; i < count; i++)
		if (b == partial_hashes[i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (((unsigned int*)binary)[0] == partial_hashes[index]);
}

static int cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) get_binary(source);
	int i;
	
	if (!have_full_hashes) 
	{
		clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE,
				sizeof(cl_uint) * (global_work_size),
				sizeof(cl_uint) * (BINARY_SIZE - 1) * global_work_size,
				res_hashes, 0, NULL, NULL);
		have_full_hashes = 1;
	}
	
	if (t[1]!=res_hashes[index]) 
		return 0;
	
	for (i = 2; i < BINARY_SIZE; ++i) 
		if (t[i]!=res_hashes[(i-1)*global_work_size+index]) 
			return 0;
	
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
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		done,
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
		clear_keys,
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