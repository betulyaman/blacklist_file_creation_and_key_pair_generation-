#ifdef __cplusplus
extern "C" {
#endif

#pragma once
#ifndef sss_RANDOMBYTES_H
#define sss_RANDOMBYTES_H

	/*
	We can change this random generator with CHACHASTREAM
	*/

#ifdef _WIN32
	/* Load size_t on windows */
#include <CRTDEFS.H>
#else
#include <sys/syscall.h>
#include <unistd.h>
#endif /* _WIN32 */


	/*
	 * Write `n` bytes of high quality random bytes to `buf`
	 */
	int icr_randombytes(void* buf, size_t n);


#endif /* sss_RANDOMBYTES_H */

#ifdef __cplusplus
}
#endif