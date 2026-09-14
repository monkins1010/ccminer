/*
 * This uses veriations of the clhash algorithm for Verus Coin, licensed
 * with the Apache-2.0 open source license.
 * 
 * Copyright (c) 2018 Michael Toutonghi
 * Distributed under the Apache 2.0 software license, available in the original form for clhash
 * here: https://github.com/lemire/clhash/commit/934da700a2a54d8202929a826e2763831bd43cf7#diff-9879d6db96fd29134fc802214163b95a
 * 
 * Original CLHash code and any portions herein, (C) 2017, 2018 Daniel Lemire and Owen Kaser
 * Faster 64-bit universal hashing
 * using carry-less multiplications, Journal of Cryptographic Engineering (to appear)
 *
 * Best used on recent x64 processors (Haswell or better).
 * 
 * This implements an intermediate step in the last part of a Verus block hash. The intent of this step
 * is to more effectively equalize FPGAs over GPUs and CPUs.
 *
 **/


#include "haraka_portable.h"

#include <assert.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#	pragma push_macro("FORCE_INLINE")
#	pragma push_macro("ALIGN_STRUCT")
#	define FORCE_INLINE       static inline __attribute__((always_inline))
#	define ALIGN_STRUCT(x)    __attribute__((aligned(x)))
#else
#	error "Macro name collisions may happens with unknown compiler"
#	define FORCE_INLINE       static inline
#	define ALIGN_STRUCT(x)    __declspec(align(x))
#endif


#ifdef __APPLE__
#include <sys/types.h>
#endif// APPLE

#ifdef _WIN32
#pragma warning (disable : 4146)
#include <intrin.h>
#else
//#include <x86intrin.h>
//#include "arm_neon.h"

#   include "SSE2NEON.h"
//#include "softaesnc.h"


#endif //WIN32

#define AES2(s0, s1, rci) \
  s0 = _mm_aesenc_si128(s0, rc[rci]); \
  s1 = _mm_aesenc_si128(s1, rc[rci + 1]); \
  s0 = _mm_aesenc_si128(s0, rc[rci + 2]); \
  s1 = _mm_aesenc_si128(s1, rc[rci + 3]);

FORCE_INLINE __m128i _mm_clmulepi64_si128_emu(const __m128i a, const __m128i &b, int imm)
{
	__m128i result;
   
 // uint64x2_t aa = *(uint64x2_t*)&a;
 // uint64x2_t bb = *(uint64x2_t*)&b;
  
 result = _mm_clmulepi64_si128(a, b, 0x01); /* lane1(a) x lane0(b); via SSE2NEON so the non-crypto polyfill is used */ 

	return result;

}

FORCE_INLINE __m128i _mm_mulhrs_epi16_emu(__m128i _a, __m128i _b)
{
//	int16_t result[8];
//	int16_t *a = (int16_t*)&_a, *b = (int16_t*)&_b;
//	for (int i = 0; i < 8; i++)
//	{
//		result[i] = (int16_t)((((int32_t)(a[i]) * (int32_t)(b[i])) + 0x4000) >> 15);
//	}

	return vqrdmulhq_s16(_a,_b); //*(__m128i *)result;
}

 __m128i _mm_set_epi64x_emu(uint64_t hi, uint64_t lo)
{
	__m128i result;
	((uint64_t *)&result)[0] = lo;
	((uint64_t *)&result)[1] = hi;
	return result;
}

 __m128i _mm_cvtsi64_si128_emu(uint64_t lo)
{
	__m128i result;
	((uint64_t *)&result)[0] = lo;
	((uint64_t *)&result)[1] = 0;
	return result;
}

 int64_t _mm_cvtsi128_si64_emu(const __m128i &a)
{
	return *(int64_t *)&a;
}

 int32_t _mm_cvtsi128_si32_emu(__m128i &a)
{
	return *(int32_t *)&a;
}

 FORCE_INLINE __m128i _mm_cvtsi32_si128_emu(uint32_t lo)
{
//	__m128i result;
//	((uint32_t *)&result)[0] = lo;
//	((uint32_t *)&result)[1] = 0;
//	((uint64_t *)&result)[1] = 0;
return vreinterpretq_m128i_s32(vsetq_lane_s32(lo, vdupq_n_s32(0), 0));
	/*
	const __m128i testresult = _mm_cvtsi32_si128(lo);
	if (!memcmp(&testresult, &result, 16))
	{
	printf("_mm_cvtsi32_si128_emu: Portable version passed!\n");
	}
	else
	{
	printf("_mm_cvtsi32_si128_emu: Portable version failed!\n");
	}
	*/

//	return result;
}
typedef uint8_t u_char;

__m128i _mm_setr_epi8_emu(u_char c0, u_char c1, u_char c2, u_char c3, u_char c4, u_char c5, u_char c6, u_char c7, u_char c8, u_char c9, u_char c10, u_char c11, u_char c12, u_char c13, u_char c14, u_char c15)
{
	__m128i result;
	((uint8_t *)&result)[0] = c0;
	((uint8_t *)&result)[1] = c1;
	((uint8_t *)&result)[2] = c2;
	((uint8_t *)&result)[3] = c3;
	((uint8_t *)&result)[4] = c4;
	((uint8_t *)&result)[5] = c5;
	((uint8_t *)&result)[6] = c6;
	((uint8_t *)&result)[7] = c7;
	((uint8_t *)&result)[8] = c8;
	((uint8_t *)&result)[9] = c9;
	((uint8_t *)&result)[10] = c10;
	((uint8_t *)&result)[11] = c11;
	((uint8_t *)&result)[12] = c12;
	((uint8_t *)&result)[13] = c13;
	((uint8_t *)&result)[14] = c14;
	((uint8_t *)&result)[15] = c15;

	/*
	const __m128i testresult = _mm_setr_epi8(c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15);
	if (!memcmp(&testresult, &result, 16))
	{
	printf("_mm_setr_epi8_emu: Portable version passed!\n");
	}
	else
	{
	printf("_mm_setr_epi8_emu: Portable version failed!\n");
	}
	*/

	return result;
}

#define _mm_srli_si128_emu(a, imm) \
({ \
	__m128i ret; \
	if ((imm) <= 0) { \
		ret = a; \
	} \
	else if ((imm) > 15) { \
		ret = _mm_setzero_si128(); \
	} \
	else { \
		ret = vreinterpretq_m128i_s8(vextq_s8(vreinterpretq_s8_m128i(a), vdupq_n_s8(0), (imm))); \
	} \
	ret; \
})

 __m128i _mm_srli_si128_emu_old(__m128i a, int imm8)
{
	unsigned char result[16];
	uint8_t shift = imm8 & 0xff;
	if (shift > 15) shift = 16;

	int i;
	for (i = 0; i < (16 - shift); i++)
	{
		result[i] = ((unsigned char *)&a)[shift + i];
	}
	for (; i < 16; i++)
	{
		result[i] = 0;
	}

	/*
	const __m128i tmp1 = _mm_load_si128(&a);
	__m128i testresult = _mm_srli_si128(tmp1, imm8);
	if (!memcmp(&testresult, result, 16))
	{
	printf("_mm_srli_si128_emu: Portable version passed!\n");
	}
	else
	{
	printf("_mm_srli_si128_emu: Portable version failed! val: %lx%lx imm: %x emu: %lx%lx, intrin: %lx%lx\n",
	*((uint64_t *)&a + 1), *(uint64_t *)&a,
	imm8,
	*((uint64_t *)result + 1), *(uint64_t *)result,
	*((uint64_t *)&testresult + 1), *(uint64_t *)&testresult);
	}
	*/

	return *(__m128i *)result;
}

 __m128i _mm_xor_si128_emu(__m128i a, __m128i b)
{
	return a^ b; //vreinterpretq_m128i_s32( veorq_s32(vreinterpretq_s32_m128i(a), vreinterpretq_s32_m128i(b)) );

}

 __m128i _mm_load_si128_emu(const void *p)
{

return vreinterpretq_m128i_s32(vld1q_s32((int32_t *)p));
//	return *(__m128i *)p;
}

 void _mm_store_si128_emu(void *p, __m128i val)
{
	
  vst1q_s32((int32_t*) p, vreinterpretq_s32_m128i(val));
 // *(__m128i *)p = val;
}

__m128i _mm_shuffle_epi8_emu(__m128i a, __m128i b)
{
	__m128i result;
	for (int i = 0; i < 16; i++)
	{
		if (((uint8_t *)&b)[i] & 0x80)
		{
			((uint8_t *)&result)[i] = 0;
		}
		else
		{
			((uint8_t *)&result)[i] = ((uint8_t *)&a)[((uint8_t *)&b)[i] & 0xf];
		}
	}

	/*
	const __m128i tmp1 = _mm_load_si128(&a);
	const __m128i tmp2 = _mm_load_si128(&b);
	__m128i testresult = _mm_shuffle_epi8(tmp1, tmp2);
	if (!memcmp(&testresult, &result, 16))
	{
	printf("_mm_shuffle_epi8_emu: Portable version passed!\n");
	}
	else
	{
	printf("_mm_shuffle_epi8_emu: Portable version failed!\n");
	}
	*/

	return result;
}

// portable
__m128i lazyLengthHash_port(uint64_t keylength, uint64_t length) {
	const __m128i lengthvector = _mm_set_epi64x_emu(keylength, length);
	const __m128i clprod1 = _mm_clmulepi64_si128_emu(lengthvector, lengthvector, 0x10);
	return clprod1;
}

// modulo reduction to 64-bit value. The high 64 bits contain garbage, see precompReduction64
__m128i precompReduction64_si128_port(__m128i A) {

	//const __m128i C = _mm_set_epi64x(1U,(1U<<4)+(1U<<3)+(1U<<1)+(1U<<0)); // C is the irreducible poly. (64,4,3,1,0)
	const __m128i C = _mm_cvtsi64_si128_emu((1U << 4) + (1U << 3) + (1U << 1) + (1U << 0));
	__m128i Q2 = _mm_clmulepi64_si128_emu(A, C, 0x01);
	__m128i Q3 = _mm_shuffle_epi8_emu(_mm_setr_epi8_emu(0, 27, 54, 45, 108, 119, 90, 65, (char)216, (char)195, (char)238, (char)245, (char)180, (char)175, (char)130, (char)153),
		_mm_srli_si128_emu(Q2, 8));
	__m128i Q4 = _mm_xor_si128_emu(Q2, A);
	const __m128i final = _mm_xor_si128_emu(Q3, Q4);
	return final;/// WARNING: HIGH 64 BITS SHOULD BE ASSUMED TO CONTAIN GARBAGE
}

uint64_t precompReduction64_port(__m128i A) {
	__m128i tmp = precompReduction64_si128_port(A);
	return _mm_cvtsi128_si64_emu(tmp);
}

uint8x16_t _mm_aesenc_si128 (uint8x16_t a, uint8x16_t RoundKey)
{
    /* Delegate to SSE2NEON's __m128i overload, which uses a software AES
       round when __ARM_FEATURE_CRYPTO is undefined. */
    return vreinterpretq_u8_m128i(
        _mm_aesenc_si128(vreinterpretq_m128i_u8(a), vreinterpretq_m128i_u8(RoundKey)));
}


// verus intermediate hash extra
__m128i __verusclmulwithoutreduction64alignedrepeat_port2_1(__m128i *randomsource, const __m128i buf[4], uint64_t keyMask, uint32_t * __restrict fixrand, uint32_t * __restrict fixrandex)
{
	__m128i const *pbuf;
   const __m128i pbuf_copy[4] = {_mm_xor_si128(buf[0],buf[2]), _mm_xor_si128(buf[1],buf[3]), buf[2], buf[3]}; 
	/*
	std::cout << "Random key start: ";
	std::cout << LEToHex(*randomsource) << ", ";
	std::cout << LEToHex(*(randomsource + 1));
	std::cout << std::endl;
	*/

	// divide key mask by 16 from bytes to __m128i
//	keyMask >>= 4;

	// the random buffer must have at least 32 16 byte dwords after the keymask to work with this
	// algorithm. we take the value from the last element inside the keyMask + 2, as that will never
	// be used to xor into the accumulator before it is hashed with other values first
	__m128i acc = _mm_load_si128_emu(randomsource + (keyMask + 2));

	for (int64_t i = 0; i < 32; i++)
	{
		//std::cout << "LOOP " << i << " acc: " << LEToHex(acc) << std::endl;

		const uint64_t selector = _mm_cvtsi128_si64_emu(acc);

		// get two random locations in the key, which will be mutated and swapped
		__m128i *prand = randomsource + ((selector >> 5) & keyMask);
		__m128i *prandex = randomsource + ((selector >> 32) & keyMask);

	

		// select random start and order of pbuf processing
		pbuf = pbuf_copy + (selector & 3);
	uint32_t prand_idx = (selector >> 5) & keyMask;
	uint32_t prandex_idx = (selector >>32) & keyMask;
  


		switch (selector & 0x1c)
		{
		case 0:
		{
			const __m128i temp1 = _mm_load_si128_emu(prandex);
			const __m128i temp2 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
			acc = _mm_xor_si128_emu(clprod1, acc);

			/*
			std::cout << "temp1: " << LEToHex(temp1) << std::endl;
			std::cout << "temp2: " << LEToHex(temp2) << std::endl;
			std::cout << "add1: " << LEToHex(add1) << std::endl;
			std::cout << "clprod1: " << LEToHex(clprod1) << std::endl;
			std::cout << "acc: " << LEToHex(acc) << std::endl;
			*/

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			const __m128i temp12 = _mm_load_si128_emu(prand);
			_mm_store_si128_emu(prand, tempa2);

			const __m128i temp22 = _mm_load_si128_emu(pbuf);
			const __m128i add12 = _mm_xor_si128_emu(temp12, temp22);
			const __m128i clprod12 = _mm_clmulepi64_si128_emu(add12, add12, 0x10);
			acc = _mm_xor_si128_emu(clprod12, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128_emu(tempb1, temp12);
			_mm_store_si128_emu(prandex, tempb2);
			break;
		}
		case 4:
		{
			const __m128i temp1 = _mm_load_si128_emu(prand);
			const __m128i temp2 = _mm_load_si128_emu(pbuf);
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
			acc = _mm_xor_si128_emu(clprod1, acc);
			const __m128i clprod2 = _mm_clmulepi64_si128_emu(temp2, temp2, 0x10);
			acc = _mm_xor_si128_emu(clprod2, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			const __m128i temp12 = _mm_load_si128_emu(prandex);
			_mm_store_si128_emu(prandex, tempa2);

			const __m128i temp22 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			const __m128i add12 = _mm_xor_si128_emu(temp12, temp22);
			acc = _mm_xor_si128_emu(add12, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128_emu(tempb1, temp12);
			_mm_store_si128_emu(prand, tempb2);
			break;
		}
		case 8:
		{
			const __m128i temp1 = _mm_load_si128_emu(prandex);
			const __m128i temp2 = _mm_load_si128_emu(pbuf);
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);
			acc = _mm_xor_si128_emu(add1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			const __m128i temp12 = _mm_load_si128_emu(prand);
			_mm_store_si128_emu(prand, tempa2);

			const __m128i temp22 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			const __m128i add12 = _mm_xor_si128_emu(temp12, temp22);
			const __m128i clprod12 = _mm_clmulepi64_si128_emu(add12, add12, 0x10);
			acc = _mm_xor_si128_emu(clprod12, acc);
			const __m128i clprod22 = _mm_clmulepi64_si128_emu(temp22, temp22, 0x10);
			acc = _mm_xor_si128_emu(clprod22, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128_emu(tempb1, temp12);
			_mm_store_si128_emu(prandex, tempb2);
			break;
		}
		case 0xc:
		{
			const __m128i temp1 = _mm_load_si128_emu(prand);
			const __m128i temp2 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);

			// cannot be zero here
			const int32_t divisor = (uint32_t)selector;

			acc = _mm_xor_si128_emu(add1, acc);

			const int64_t dividend = _mm_cvtsi128_si64_emu(acc);
			const __m128i modulo = _mm_cvtsi32_si128_emu(dividend % divisor);
			acc = _mm_xor_si128_emu(modulo, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			if (dividend & 1)
			{
				const __m128i temp12 = _mm_load_si128_emu(prandex);
				_mm_store_si128_emu(prandex, tempa2);

				const __m128i temp22 = _mm_load_si128_emu(pbuf);
				const __m128i add12 = _mm_xor_si128_emu(temp12, temp22);
				const __m128i clprod12 = _mm_clmulepi64_si128_emu(add12, add12, 0x10);
				acc = _mm_xor_si128_emu(clprod12, acc);
				const __m128i clprod22 = _mm_clmulepi64_si128_emu(temp22, temp22, 0x10);
				acc = _mm_xor_si128_emu(clprod22, acc);

				const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
				const __m128i tempb2 = _mm_xor_si128_emu(tempb1, temp12);
				_mm_store_si128_emu(prand, tempb2);
			}
			else
			{
				const __m128i tempb3 = _mm_load_si128_emu(prandex);
				_mm_store_si128_emu(prandex, tempa2);
				_mm_store_si128_emu(prand, tempb3);
			}
			break;
		}
		case 0x10:
		{
			// a few AES operations
			const __m128i *rc = prand;
			__m128i tmp;

			__m128i temp1 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			__m128i temp2 = _mm_load_si128_emu(pbuf);

			AES2(temp1, temp2, 0);
			MIX2_EMU(temp1, temp2);

			AES2(temp1, temp2, 4);
			MIX2_EMU(temp1, temp2);

			AES2(temp1, temp2, 8);
			MIX2_EMU(temp1, temp2);

			acc = _mm_xor_si128_emu(temp1, acc);
			acc = _mm_xor_si128_emu(temp2, acc);

			const __m128i tempa1 = _mm_load_si128_emu(prand);
			const __m128i tempa2 = _mm_mulhrs_epi16_emu(acc, tempa1);
			const __m128i tempa3 = _mm_xor_si128_emu(tempa1, tempa2);

			const __m128i tempa4 = _mm_load_si128_emu(prandex);
			_mm_store_si128_emu(prandex, tempa3);
			_mm_store_si128_emu(prand, tempa4);
			break;
		}
		case 0x14:
		{
			// we'll just call this one the monkins loop, inspired by Chris
			const __m128i *buftmp = pbuf - (((selector & 1) << 1) - 1);
			__m128i tmp; // used by MIX2

			uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
			__m128i *rc = prand;
			uint64_t aesround = 0;
			__m128i onekey;

			do
			{
				//std::cout << "acc: " << LEToHex(acc) << ", round check: " << LEToHex((selector & (0x10000000 << rounds))) << std::endl;

				// note that due to compiler and CPUs, we expect this to do:
				// if (selector & ((0x10000000 << rounds) & 0xffffffff) if rounds != 3 else selector & 0xffffffff80000000):
				if (selector & ((uint64_t)0x10000000 << rounds))
				{
					onekey = _mm_load_si128_emu(rc++);
					const __m128i temp2 = _mm_load_si128_emu(rounds & 1 ? pbuf : buftmp);
					const __m128i add1 = _mm_xor_si128_emu(onekey, temp2);
					const __m128i clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
					acc = _mm_xor_si128_emu(clprod1, acc);
				}
				else
				{
					onekey = _mm_load_si128_emu(rc++);
					__m128i temp2 = _mm_load_si128_emu(rounds & 1 ? buftmp : pbuf);
					const uint64_t roundidx = aesround++ << 2;
					AES2(onekey, temp2, roundidx);

					/*
					std::cout << " onekey1: " << LEToHex(onekey) << std::endl;
					std::cout << "  temp21: " << LEToHex(temp2) << std::endl;
					std::cout << "roundkey: " << LEToHex(rc[roundidx]) << std::endl;

					aesenc((unsigned char *)&onekey, (unsigned char *)&(rc[roundidx]));

					std::cout << "onekey2: " << LEToHex(onekey) << std::endl;
					std::cout << "roundkey: " << LEToHex(rc[roundidx + 1]) << std::endl;

					aesenc((unsigned char *)&temp2, (unsigned char *)&(rc[roundidx + 1]));

					std::cout << " temp22: " << LEToHex(temp2) << std::endl;
					std::cout << "roundkey: " << LEToHex(rc[roundidx + 2]) << std::endl;

					aesenc((unsigned char *)&onekey, (unsigned char *)&(rc[roundidx + 2]));

					std::cout << "onekey2: " << LEToHex(onekey) << std::endl;

					aesenc((unsigned char *)&temp2, (unsigned char *)&(rc[roundidx + 3]));

					std::cout << " temp22: " << LEToHex(temp2) << std::endl;
					*/

					MIX2_EMU(onekey, temp2);

					/*
					std::cout << "onekey3: " << LEToHex(onekey) << std::endl;
					*/

					acc = _mm_xor_si128_emu(onekey, acc);
					acc = _mm_xor_si128_emu(temp2, acc);
				}
			} while (rounds--);

			const __m128i tempa1 = _mm_load_si128_emu(prand);
			const __m128i tempa2 = _mm_mulhrs_epi16_emu(acc, tempa1);
			const __m128i tempa3 = _mm_xor_si128_emu(tempa1, tempa2);

			const __m128i tempa4 = _mm_load_si128_emu(prandex);
			_mm_store_si128_emu(prandex, tempa3);
			_mm_store_si128_emu(prand, tempa4);
			break;
		}
		case 0x18:
   {   
             const __m128i *buftmp = pbuf - (((selector & 1) << 1) - 1);
                __m128i tmp; // used by MIX2

                uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
                __m128i *rc = prand;
                __m128i onekey;

                do
                {
                    if (selector & (((uint64_t)0x10000000) << rounds))
                    {
                        onekey = _mm_load_si128_emu(rc++);
                        const __m128i temp2 = _mm_load_si128_emu(rounds & 1 ? pbuf : buftmp);
                        const __m128i add1 = _mm_xor_si128_emu(onekey, temp2);
                        // cannot be zero here, may be negative
                        const int32_t divisor = (uint32_t)selector;
                        const int64_t dividend = _mm_cvtsi128_si64_emu(add1);
                        const __m128i modulo = _mm_cvtsi32_si128_emu(dividend % divisor);
                        acc = _mm_xor_si128_emu(modulo, acc);
                    }
                    else
                    {
                        onekey = _mm_load_si128_emu(rc++);
                        __m128i temp2 = _mm_load_si128_emu(rounds & 1 ? buftmp : pbuf);
                        const __m128i add1 = _mm_xor_si128_emu(onekey, temp2);
                        const __m128i clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
                        const __m128i clprod2 = _mm_mulhrs_epi16_emu(acc, clprod1);
                        acc = _mm_xor_si128_emu(clprod2, acc);
                    }
                } while (rounds--);

                const __m128i tempa3 = _mm_load_si128_emu(prandex);
                const __m128i tempa4 = _mm_xor_si128_emu(tempa3, acc);
                _mm_store_si128_emu(prandex, tempa4);
                _mm_store_si128_emu(prand, onekey);
                break;
            }
		case 0x1c:
		{
			const __m128i temp1 = _mm_load_si128_emu(pbuf);
			const __m128i temp2 = _mm_load_si128_emu(prandex);
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
			acc = _mm_xor_si128_emu(clprod1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp2);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp2);

			const __m128i tempa3 = _mm_load_si128_emu(prand);
			_mm_store_si128_emu(prand, tempa2);

			acc = _mm_xor_si128_emu(tempa3, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, tempa3);
			const __m128i tempb2 = _mm_xor_si128_emu(tempb1, tempa3);
			_mm_store_si128_emu(prandex, tempb2);
			break;
		}
		}
   fixrand[i] = prand_idx;
		fixrandex[i] = prandex_idx;
   
	}
	return acc;
}
__m128i __verusclmulwithoutreduction64alignedrepeat_port2_2(__m128i *randomsource, const __m128i buf[4], uint64_t keyMask, uint32_t * __restrict fixrand, 
										uint32_t * __restrict fixrandex, __m128i *g_prand, __m128i *g_prandex)
{
	__m128i const *pbuf;
   const __m128i pbuf_copy[4] = {_mm_xor_si128(buf[0],buf[2]), _mm_xor_si128(buf[1],buf[3]), buf[2], buf[3]}; 
	/*
	std::cout << "Random key start: ";
	std::cout << LEToHex(*randomsource) << ", ";
	std::cout << LEToHex(*(randomsource + 1));
	std::cout << std::endl;
	*/

	// divide key mask by 16 from bytes to __m128i
	//keyMask >>= 4;

	// the random buffer must have at least 32 16 byte dwords after the keymask to work with this
	// algorithm. we take the value from the last element inside the keyMask + 2, as that will never
	// be used to xor into the accumulator before it is hashed with other values first
	__m128i acc = _mm_load_si128_emu(randomsource + (keyMask + 2));

	for (int64_t i = 0; i < 32; i++)
	{
		//std::cout << "LOOP " << i << " acc: " << LEToHex(acc) << std::endl;

		const uint64_t selector = _mm_cvtsi128_si64_emu(acc);

		// get two random locations in the key, which will be mutated and swapped
		__m128i *prand = randomsource + ((selector >> 5) & keyMask);
		__m128i *prandex = randomsource + ((selector >> 32) & keyMask);



		// select random start and order of pbuf processing
		pbuf = pbuf_copy + (selector & 3);
		uint32_t prand_idx = (selector >> 5) & keyMask;
		uint32_t prandex_idx = (selector >>32) & keyMask;
  
		_mm_store_si128_emu(&g_prand[i], prand[0]);
		_mm_store_si128_emu(&g_prandex[i], prandex[0]);
   		fixrand[i] = prand_idx;
		fixrandex[i] = prandex_idx;


		switch (selector & 0x1c)
		{
		case 0:
		{
			const __m128i temp1 = _mm_load_si128_emu(prandex);
			const __m128i temp2 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
			acc = _mm_xor_si128_emu(clprod1, acc);

			/*
			std::cout << "temp1: " << LEToHex(temp1) << std::endl;
			std::cout << "temp2: " << LEToHex(temp2) << std::endl;
			std::cout << "add1: " << LEToHex(add1) << std::endl;
			std::cout << "clprod1: " << LEToHex(clprod1) << std::endl;
			std::cout << "acc: " << LEToHex(acc) << std::endl;
			*/

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			const __m128i temp12 = _mm_load_si128_emu(prand);
			_mm_store_si128_emu(prand, tempa2);

			const __m128i temp22 = _mm_load_si128_emu(pbuf);
			const __m128i add12 = _mm_xor_si128_emu(temp12, temp22);
			const __m128i clprod12 = _mm_clmulepi64_si128_emu(add12, add12, 0x10);
			acc = _mm_xor_si128_emu(clprod12, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128_emu(tempb1, temp12);
			_mm_store_si128_emu(prandex, tempb2);
			break;
		}
		case 4:
		{
			const __m128i temp1 = _mm_load_si128_emu(prand);
			const __m128i temp2 = _mm_load_si128_emu(pbuf);
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
			acc = _mm_xor_si128_emu(clprod1, acc);
			const __m128i clprod2 = _mm_clmulepi64_si128_emu(temp2, temp2, 0x10);
			acc = _mm_xor_si128_emu(clprod2, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			const __m128i temp12 = _mm_load_si128_emu(prandex);
			_mm_store_si128_emu(prandex, tempa2);

			const __m128i temp22 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			const __m128i add12 = _mm_xor_si128_emu(temp12, temp22);
			acc = _mm_xor_si128_emu(add12, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128_emu(tempb1, temp12);
			_mm_store_si128_emu(prand, tempb2);
			break;
		}
		case 8:
		{
			const __m128i temp1 = _mm_load_si128_emu(prandex);
			const __m128i temp2 = _mm_load_si128_emu(pbuf);
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);
			acc = _mm_xor_si128_emu(add1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			const __m128i temp12 = _mm_load_si128_emu(prand);
			_mm_store_si128_emu(prand, tempa2);

			const __m128i temp22 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			const __m128i add12 = _mm_xor_si128_emu(temp12, temp22);
			const __m128i clprod12 = _mm_clmulepi64_si128_emu(add12, add12, 0x10);
			acc = _mm_xor_si128_emu(clprod12, acc);
			const __m128i clprod22 = _mm_clmulepi64_si128_emu(temp22, temp22, 0x10);
			acc = _mm_xor_si128_emu(clprod22, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128_emu(tempb1, temp12);
			_mm_store_si128_emu(prandex, tempb2);
			break;
		}
		case 0xc:
		{
			const __m128i temp1 = _mm_load_si128_emu(prand);
			const __m128i temp2 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);

			// cannot be zero here
			const int32_t divisor = (uint32_t)selector;

			acc = _mm_xor_si128_emu(add1, acc);

			const int64_t dividend = _mm_cvtsi128_si64_emu(acc);
			const __m128i modulo = _mm_cvtsi32_si128_emu(dividend % divisor);
			acc = _mm_xor_si128_emu(modulo, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp1);

			if (dividend & 1)
			{
				const __m128i temp12 = _mm_load_si128_emu(prandex);
				_mm_store_si128_emu(prandex, tempa2);

				const __m128i temp22 = _mm_load_si128_emu(pbuf);
				const __m128i add12 = _mm_xor_si128_emu(temp12, temp22);
				const __m128i clprod12 = _mm_clmulepi64_si128_emu(add12, add12, 0x10);
				acc = _mm_xor_si128_emu(clprod12, acc);
				const __m128i clprod22 = _mm_clmulepi64_si128_emu(temp22, temp22, 0x10);
				acc = _mm_xor_si128_emu(clprod22, acc);

				const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, temp12);
				const __m128i tempb2 = _mm_xor_si128_emu(tempb1, temp12);
				_mm_store_si128_emu(prand, tempb2);
			}
			else
			{
				const __m128i tempb3 = _mm_load_si128_emu(prandex);
				_mm_store_si128_emu(prandex, tempa2);
				_mm_store_si128_emu(prand, tempb3);
				const __m128i tempb4 = _mm_load_si128_emu(pbuf);
				acc = _mm_xor_si128_emu(tempb4, acc);
			}
			break;
		}
		case 0x10:
		{
			// a few AES operations
			const __m128i *rc = prand;
			__m128i tmp;

			__m128i temp1 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			__m128i temp2 = _mm_load_si128_emu(pbuf);

			AES2(temp1, temp2, 0);
			MIX2_EMU(temp1, temp2);

			AES2(temp1, temp2, 4);
			MIX2_EMU(temp1, temp2);

			AES2(temp1, temp2, 8);
			MIX2_EMU(temp1, temp2);

			acc = _mm_xor_si128_emu(temp1, acc);
			acc = _mm_xor_si128_emu(temp2, acc);

			const __m128i tempa1 = _mm_load_si128_emu(prand);
			const __m128i tempa2 = _mm_mulhrs_epi16_emu(acc, tempa1);
			const __m128i tempa3 = _mm_xor_si128_emu(tempa1, tempa2);

			const __m128i tempa4 = _mm_load_si128_emu(prandex);
			_mm_store_si128_emu(prandex, tempa3);
			_mm_store_si128_emu(prand, tempa4);
			break;
		}
		case 0x14:
		{
			// we'll just call this one the monkins loop, inspired by Chris
			const __m128i *buftmp = pbuf - (((selector & 1) << 1) - 1);
			__m128i tmp; // used by MIX2

			int rounds = (int) (selector >> 61); // loop randomly between 1 and 8 times
			__m128i *rc = prand;
			uint64_t aesround = 0;
			__m128i onekey;

#pragma GCC unroll 8
			for ( int count = 1; count <= 8; count++ )
			{
				onekey = _mm_load_si128_emu(rc++);
				if ( rounds >= 0 )
				{
				//printf("selector %" PRIu64 "\n", selector);

						if (selector & ((uint64_t)0x10000000 << rounds))
						{
							const __m128i temp2 = _mm_load_si128_emu(rounds & 1 ? pbuf : buftmp);  //rounds is odd
							const __m128i add1 = _mm_xor_si128_emu(onekey, temp2);
							const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
							acc = _mm_xor_si128_emu(clprod1, acc);
						}
						else
						{
							__m128i temp2 = _mm_load_si128_emu(rounds & 1 ? buftmp : pbuf);  //rounds is odd
							const uint64_t roundidx = aesround++ << 2;
							AES2(onekey, temp2, roundidx);

							MIX2_EMU(onekey, temp2);

							acc = _mm_xor_si128_emu(onekey, acc);
							acc = _mm_xor_si128_emu(temp2, acc);
						}
				rounds--;
				}
			} 

			const __m128i tempa1 = _mm_load_si128_emu(prand);
			const __m128i tempa2 = _mm_mulhrs_epi16_emu(acc, tempa1);
			const __m128i tempa3 = _mm_xor_si128_emu(tempa1, tempa2);

			const __m128i tempa4 = _mm_load_si128_emu(prandex);
			_mm_store_si128_emu(prandex, tempa3);
			_mm_store_si128_emu(prand, tempa4);
			break;
		}
		case 0x18:
   {   
             const __m128i *buftmp = pbuf - (((selector & 1) << 1) - 1);
                __m128i tmp; // used by MIX2

                int rounds = (int) (selector >> 61); // loop randomly between 1 and 8 times
                __m128i *rc = prand;
                __m128i onekey;

		for ( int count = 1; count <= 8; count++ )
                {
			if ( rounds >= 0 )
			{
				    if (selector & (((uint64_t)0x10000000) << rounds))
				    {
					onekey = vld1q_s32((const int32_t *)rc++);
					const __m128i temp2 = vld1q_s32((const int32_t *) (rounds & 1 ? pbuf : buftmp));
					onekey = veorq_s32(onekey, temp2);
					// cannot be zero here, may be negative
					const int32_t divisor = (uint32_t)selector;
					const int64_t dividend = _mm_cvtsi128_si64_emu(onekey);
					const __m128i modulo = _mm_cvtsi32_si128_emu(dividend % divisor);
					acc = veorq_s32(modulo, acc);
				    }
				    else
				    {
					onekey = _mm_load_si128_emu(rc++);
					__m128i temp2 = _mm_load_si128_emu(rounds & 1 ? buftmp : pbuf);
					const __m128i add1 = veorq_s32(onekey, temp2);
					onekey = _mm_clmulepi64_si128(add1, add1, 0x10);
					const __m128i clprod2 = _mm_mulhrs_epi16_emu(acc, onekey);
					acc = veorq_s32(clprod2, acc);
				    }
			}
			rounds--;
                } 

                const __m128i tempa3 = _mm_load_si128_emu(prandex);
                const __m128i tempa4 = veorq_s32(tempa3, acc);

                _mm_store_si128_emu(prandex, onekey);
                _mm_store_si128_emu(prand, tempa4);
                break;
            }
		case 0x1c:
		{
			const __m128i temp1 = _mm_load_si128_emu(pbuf);
			const __m128i temp2 = _mm_load_si128_emu(prandex);
			const __m128i add1 = _mm_xor_si128_emu(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128_emu(add1, add1, 0x10);
			acc = _mm_xor_si128_emu(clprod1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16_emu(acc, temp2);
			const __m128i tempa2 = _mm_xor_si128_emu(tempa1, temp2);

			const __m128i tempa3 = _mm_load_si128_emu(prand);
			_mm_store_si128_emu(prand, tempa2);

			acc = _mm_xor_si128_emu(tempa3, acc);
			const __m128i temp4 = _mm_load_si128_emu(pbuf - (((selector & 1) << 1) - 1));
			acc = _mm_xor_si128(temp4, acc);
			const __m128i tempb1 = _mm_mulhrs_epi16_emu(acc, tempa3);
			const __m128i tempb2 = _mm_xor_si128_emu(tempb1, tempa3);
			_mm_store_si128_emu(prandex, tempb2);
			break;
		}
		}

   
	}
	return acc;
}
// hashes 64 bytes only by doing a carryless multiplication and reduction of the repeated 64 byte sequence 16 times, 
// returning a 64 bit hash value
uint64_t verusclhash_port2_1(void * random, const unsigned char buf[64], uint64_t keyMask, uint32_t *  __restrict fixrand, uint32_t * __restrict fixrandex) {
    const unsigned int  m = 128;// we process the data in chunks of 16 cache lines
    __m128i * rs64 = (__m128i *)random;
    const __m128i * string = (const __m128i *) buf;

    __m128i  acc = __verusclmulwithoutreduction64alignedrepeat_port2_1(rs64, string, keyMask, fixrand, fixrandex);
    acc = _mm_xor_si128_emu(acc, lazyLengthHash_port(1024, 64));
    return precompReduction64_port(acc);
}
uint64_t verusclhash_port2_2(void * random, const unsigned char buf[64], uint64_t keyMask, uint32_t *  __restrict fixrand, uint32_t * __restrict fixrandex,
								 __m128i *g_prand, __m128i *g_prandex) {
    const unsigned int  m = 128;// we process the data in chunks of 16 cache lines
    __m128i * rs64 = (__m128i *)random;
    const __m128i * string = (const __m128i *) buf;

    __m128i  acc = __verusclmulwithoutreduction64alignedrepeat_port2_2(rs64, string, keyMask, fixrand, fixrandex, g_prand, g_prandex);
    acc = _mm_xor_si128_emu(acc, lazyLengthHash_port(1024, 64));
    return precompReduction64_port(acc);
}