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


#include "verus_clhash.h"


#include <assert.h>
#include <string.h>
//#include <intrin.h>
//#include "cpu_verushash.hpp"

#ifdef _WIN32
#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif


int __cpuverusoptimized = 0x80;

// multiply the length and the some key, no modulo
__m128i lazyLengthHash(uint64_t keylength, uint64_t length) {
	const __m128i lengthvector = _mm_set_epi64x(keylength, length);
	const __m128i clprod1 = _mm_clmulepi64_si128(lengthvector, lengthvector, 0x10);
	return clprod1;
}

// modulo reduction to 64-bit value. The high 64 bits contain garbage, see precompReduction64
__m128i precompReduction64_si128(__m128i A) {

	//const __m128i C = _mm_set_epi64x(1U,(1U<<4)+(1U<<3)+(1U<<1)+(1U<<0)); // C is the irreducible poly. (64,4,3,1,0)
	const __m128i C = _mm_cvtsi64_si128((1U << 4) + (1U << 3) + (1U << 1) + (1U << 0));
	const  __m128i Q2 = _mm_clmulepi64_si128(A, C, 0x01);
	const __m128i Q3 = _mm_shuffle_epi8(_mm_setr_epi8(0, 27, 54, 45, 108, 119, 90, 65, (char)216, (char)195, (char)238, (char)245, (char)180, (char)175, (char)130, (char)153),
		_mm_srli_si128(Q2, 8));
	const __m128i Q4 = _mm_xor_si128(Q2, A);
	const __m128i final = _mm_xor_si128(Q3, Q4);
	return final;/// WARNING: HIGH 64 BITS CONTAIN GARBAGE
}

uint64_t precompReduction64(__m128i A) {
	return _mm_cvtsi128_si64(precompReduction64_si128(A));
}

__m128i __verusclmulwithoutreduction64alignedrepeatv2_2(__m128i *randomsource, const __m128i buf[4], uint64_t keyMask,
	uint32_t *fixrand, uint32_t *fixrandex, u128 *g_prand, u128 *g_prandex)
{
	const __m128i pbuf_copy[4] = { _mm_xor_si128(buf[0], buf[2]), _mm_xor_si128(buf[1], buf[3]), buf[2], buf[3] };
	const __m128i *pbuf;

	// divide key mask by 16 from bytes to __m128i
	//keyMask >>= 4;

	// the random buffer must have at least 32 16 byte dwords after the keymask to work with this
	// algorithm. we take the value from the last element inside the keyMask + 2, as that will never
	// be used to xor into the accumulator before it is hashed with other values first
	__m128i acc = _mm_load_si128(randomsource + (keyMask + 2));

	for (int64_t i = 0; i < 32; i++)
	{
		const uint64_t selector = _mm_cvtsi128_si64(acc);

		uint32_t prand_idx = (selector >> 5) & keyMask;
		uint32_t prandex_idx = (selector >> 32) & keyMask;
		// get two random locations in the key, which will be mutated and swapped
		__m128i *prand = randomsource + prand_idx;
		__m128i *prandex = randomsource + prandex_idx;

		// select random start and order of pbuf processing
		pbuf = pbuf_copy + (selector & 3);
		_mm_store_si128(&g_prand[i], prand[0]);
		_mm_store_si128(&g_prandex[i], prandex[0]);
		fixrand[i] = prand_idx;
		fixrandex[i] = prandex_idx;

		switch (selector & 0x1c)
		{
		case 0:
		{
			const __m128i temp1 = _mm_load_si128(prandex);
			const __m128i temp2 = pbuf[(selector & 1) ? -1 : 1];
			const __m128i add1 = _mm_xor_si128(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
			acc = _mm_xor_si128(clprod1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

			const __m128i temp12 = _mm_load_si128(prand);
			_mm_store_si128(prand, tempa2);

			const __m128i temp22 = _mm_load_si128(pbuf);
			const __m128i add12 = _mm_xor_si128(temp12, temp22);
			const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
			acc = _mm_xor_si128(clprod12, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
			_mm_store_si128(prandex, tempb2);
			break;
		}
		case 4:
		{
			const __m128i temp1 = _mm_load_si128(prand);
			const __m128i temp2 = _mm_load_si128(pbuf);
			const __m128i add1 = _mm_xor_si128(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
			acc = _mm_xor_si128(clprod1, acc);
			const __m128i clprod2 = _mm_clmulepi64_si128(temp2, temp2, 0x10);
			acc = _mm_xor_si128(clprod2, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

			const __m128i temp12 = _mm_load_si128(prandex);
			_mm_store_si128(prandex, tempa2);

			const __m128i temp22 = pbuf[(selector & 1) ? -1 : 1];
			const __m128i add12 = _mm_xor_si128(temp12, temp22);
			acc = _mm_xor_si128(add12, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
			_mm_store_si128(prand,_mm_xor_si128(tempb1, temp12));
			//_mm_store_si128(prand, tempb2);
			break;
		}
		case 8:
		{
			const __m128i temp1 = _mm_load_si128(prandex);
			const __m128i temp2 = _mm_load_si128(pbuf);
			const __m128i add1 = _mm_xor_si128(temp1, temp2);
			acc = _mm_xor_si128(add1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

			const __m128i temp12 = _mm_load_si128(prand);
			_mm_store_si128(prand, tempa2);

			const __m128i temp22 = pbuf[(selector & 1) ? -1 : 1];
			const __m128i add12 = _mm_xor_si128(temp12, temp22);
			const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
			acc = _mm_xor_si128(clprod12, acc);
			const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
			acc = _mm_xor_si128(clprod22, acc);

			const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
			const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
			_mm_store_si128(prandex, tempb2);
			break;
		}
		case 0xc:
		{
			const __m128i temp1 = _mm_load_si128(prand);
			const __m128i temp2 = pbuf[(selector & 1) ? -1 : 1];
			const __m128i add1 = _mm_xor_si128(temp1, temp2);

			// cannot be zero here
			const int32_t divisor = (uint32_t)selector;

			acc = _mm_xor_si128(add1, acc);

			const int64_t dividend = _mm_cvtsi128_si64(acc);
			const __m128i modulo = _mm_cvtsi32_si128(dividend % divisor);
			acc = _mm_xor_si128(modulo, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

			if (dividend & 1)
			{
				const __m128i temp12 = _mm_load_si128(prandex);
				_mm_store_si128(prandex, tempa2);

				const __m128i temp22 = _mm_load_si128(pbuf);
				const __m128i add12 = _mm_xor_si128(temp12, temp22);
				const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
				acc = _mm_xor_si128(clprod12, acc);
				const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
				acc = _mm_xor_si128(clprod22, acc);

				const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
				const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
				_mm_store_si128(prand, tempb2);
			}
			else
			{
				_mm_store_si128(prand, _mm_load_si128(prandex));
				_mm_store_si128(prandex, tempa2);
				acc = _mm_xor_si128(_mm_load_si128(pbuf), acc);
			}
			break;
		}
		case 0x10:
		{
			// a few AES operations
			const __m128i *rc = prand;
			__m128i tmp;

			__m128i temp1 = pbuf[(selector & 1) ? -1 : 1];
			__m128i temp2 = _mm_load_si128(pbuf);

			AES2(temp1, temp2, 0);
			MIX2(temp1, temp2);

			AES2(temp1, temp2, 4);
			MIX2(temp1, temp2);

			AES2(temp1, temp2, 8);
			MIX2(temp1, temp2);

			acc = _mm_xor_si128(temp2, _mm_xor_si128(temp1, acc));

			const __m128i tempa1 = _mm_load_si128(prand);
			const __m128i tempa2 = _mm_mulhrs_epi16(acc, tempa1);

			_mm_store_si128(prand, _mm_load_si128(prandex));
			_mm_store_si128(prandex, _mm_xor_si128(tempa1, tempa2));

			break;
		}
		case 0x14:
		{
			// we'll just call this one the monkins loop, inspired by Chris - modified to cast to uint64_t on shift for more variability in the loop
			const __m128i *buftmp = &pbuf[(selector & 1) ? -1 : 1];
			__m128i tmp; // used by MIX2

			uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
			__m128i *rc = prand;
			uint64_t aesroundoffset = 0;
			__m128i onekey;

			do
			{
				if (selector & (((uint64_t)0x10000000) << rounds))
				{
					//onekey = _mm_load_si128(rc++);
					const __m128i temp2 = _mm_load_si128(rounds & 1 ? pbuf : buftmp);
					const __m128i add1 = _mm_xor_si128(rc[0], temp2); rc++;
					const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
					acc = _mm_xor_si128(clprod1, acc);
				}
				else
				{
					onekey = _mm_load_si128(rc++);
					__m128i temp2 = _mm_load_si128(rounds & 1 ? buftmp : pbuf);
					AES2(onekey, temp2, aesroundoffset);
					aesroundoffset += 4;
					MIX2(onekey, temp2);
					acc = _mm_xor_si128(onekey, acc);
					acc = _mm_xor_si128(temp2, acc);
				}
			} while (rounds--);

			const __m128i tempa1 = _mm_load_si128(prand);
			const __m128i tempa2 = _mm_mulhrs_epi16(acc, tempa1);
			const __m128i tempa3 = _mm_xor_si128(tempa1, tempa2);

			const __m128i tempa4 = _mm_load_si128(prandex);
			_mm_store_si128(prandex, tempa3);
			_mm_store_si128(prand, tempa4);
			break;
		}
		case 0x18:
		{
			const __m128i *buftmp = &pbuf[(selector & 1) ? -1 : 1];
			__m128i tmp; // used by MIX2

			uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
			__m128i *rc = prand;
			__m128i onekey;

			do
			{
				if (selector & (((uint64_t)0x10000000) << rounds))
				{
					//	onekey = _mm_load_si128(rc++);
					const __m128i temp2 = _mm_load_si128(rounds & 1 ? pbuf : buftmp);
					onekey = _mm_xor_si128(rc[0], temp2); rc++;
					// cannot be zero here, may be negative
					const int32_t divisor = (uint32_t)selector;
					const int64_t dividend = _mm_cvtsi128_si64(onekey);
					const __m128i modulo = _mm_cvtsi32_si128(dividend % divisor);
					acc = _mm_xor_si128(modulo, acc);
				}
				else
				{
					//	onekey = _mm_load_si128(rc++);
					__m128i temp2 = _mm_load_si128(rounds & 1 ? buftmp : pbuf);
					const __m128i add1 = _mm_xor_si128(rc[0], temp2); rc++;
					onekey = _mm_clmulepi64_si128(add1, add1, 0x10);
					const __m128i clprod2 = _mm_mulhrs_epi16(acc, onekey);
					acc = _mm_xor_si128(clprod2, acc);
				}
			} while (rounds--);

			const __m128i tempa3 = _mm_load_si128(prandex);

			_mm_store_si128(prandex, onekey);
			_mm_store_si128(prand, _mm_xor_si128(tempa3, acc));
			//	_mm_store_si128(prand, tempa4);
			break;
		}
		case 0x1c:
		{
			const __m128i temp1 = _mm_load_si128(pbuf);
			const __m128i temp2 = _mm_load_si128(prandex);
			const __m128i add1 = _mm_xor_si128(temp1, temp2);
			const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
			acc = _mm_xor_si128(clprod1, acc);

			const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp2);
			const __m128i tempa2 = _mm_xor_si128(tempa1, temp2);

			const __m128i tempa3 = _mm_load_si128(prand);
			_mm_store_si128(prand, tempa2);

			acc = _mm_xor_si128(tempa3, acc);
			const __m128i temp4 = pbuf[(selector & 1) ? -1 : 1];
			acc = _mm_xor_si128(temp4, acc);
			const __m128i tempb1 = _mm_mulhrs_epi16(acc, tempa3);
			*prandex = _mm_xor_si128(tempb1, tempa3);
			//	_mm_store_si128(prandex, tempb2);
			break;
		}
		}
	}
	return acc;
}

// hashes 64 bytes only by doing a carryless multiplication and reduction of the repeated 64 byte sequence 16 times, 
// returning a 64 bit hash value

uint64_t verusclhashv2_2(void * random, const unsigned char buf[64], uint64_t keyMask, uint32_t *fixrand, uint32_t *fixrandex,
	u128 *g_prand, u128 *g_prandex) {
	__m128i  acc = __verusclmulwithoutreduction64alignedrepeatv2_2((__m128i *)random, (const __m128i *)buf, 511, fixrand, fixrandex, g_prand, g_prandex);
	acc = _mm_xor_si128(acc, lazyLengthHash(1024, 64));


	return precompReduction64(acc);
}

#ifdef _WIN32

#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif
