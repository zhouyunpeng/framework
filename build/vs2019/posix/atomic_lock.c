#include "atomic_lock.h"
#include <pthread.h>


#ifndef _M_X64
#define  declspace_naked __declspec(naked)
#else
#define  declspace_naked
static pthread_mutex_t __mx = PTHREAD_MUTEX_INITIALIZER;
#endif


declspace_naked int __sync_fetch_and_sub(int *p, int n) {
#ifndef _M_X64
	__asm {
		push	ebp
		mov		ebp,esp
		mov		edx,[n]
		mov		eax,[p]
		neg		edx
		lock	xadd [eax],edx
		mov		edx,eax
		pop		ebp
		ret
	}
#else
	//__debugbreak();
	int ifetch = 0;
	pthread_mutex_lock(&__mx);
	ifetch = *p;
	*p = ifetch - n;
	pthread_mutex_unlock(&__mx);
	return ifetch;
#endif
}

declspace_naked int __sync_fetch_and_add(int *p, int n) {
#ifndef _M_X64
	__asm {
		push	ebp
		mov		ebp,esp
		mov		edx,[n]
		mov		eax,[p]
		lock	xadd [eax],edx
		mov		eax,edx
		pop		ebp
		ret
	}
#else
	//__debugbreak();
	int ifetch = 0;
	pthread_mutex_lock(&__mx);
	ifetch = *p;
	*p = ifetch + n;
	pthread_mutex_unlock(&__mx);
	return ifetch;
#endif
}

declspace_naked int __sync_add_and_fetch(int *p, int n) {
#ifndef _M_X64
	__asm {
		push	ebp
		mov		ebp,esp
		mov     ecx,[n]
		mov     edx,[p]
		mov		eax,ecx
		lock	xadd [edx],eax
		add		eax,ecx
		pop		ebp
		ret
	}
#else
	//__debugbreak();
	int ifetch = 0;
	pthread_mutex_lock(&__mx);
	ifetch = *p = (*p) + n;
	pthread_mutex_unlock(&__mx);
	return ifetch;
#endif
}

declspace_naked int __sync_sub_and_fetch(int *p, int n) {
#ifndef _M_X64
	__asm {
		push	ebp
		mov		ebp,esp
		mov		eax,[n]
		mov		edx,[p]
		neg		eax
		mov		ecx,eax
		mov		eax,ecx
		lock	xadd [edx],eax
		add		eax,ecx
		pop		ebp
		ret
	}
#else
	int ifetch = 0;
	pthread_mutex_lock(&__mx);
	ifetch = *p = (*p) - n;
	pthread_mutex_unlock(&__mx);
	return ifetch;
#endif
}

declspace_naked int __sync_lock_test_and_set(int *p, int n) {
#ifndef _M_X64
	__asm {
		push	ebp
		mov		ebp,esp
		mov		edx,[n]
		mov		eax,[p]
		xchg	[eax],edx
		mov		eax,edx
		pop		ebp
		ret
	}
#else
	int iRet = 0;
	pthread_mutex_lock(&__mx);
	iRet = *p;
	*p = n;
	pthread_mutex_unlock(&__mx);
	return iRet;
#endif
}

declspace_naked void __sync_lock_release(int *p) {
#ifndef _M_X64
	__asm {
		push	ebp
		mov		ebp,esp
		mov		eax,[p]
		mov		edx,0
		mov		[eax],edx
		nop
		pop		ebp
		ret
	}
#else
	//__debugbreak();
	pthread_mutex_lock(&__mx);
	*p = 0;
	pthread_mutex_unlock(&__mx);
#endif
}

declspace_naked void __sync_synchronize() {
#ifndef _M_X64
	__asm {
		push	ebp
		mov		ebp,esp
		lock	or [esp],0
		pop		ebp
		ret
	}
#else
	pthread_mutex_lock(&__mx);
	pthread_mutex_unlock(&__mx);
#endif
}

declspace_naked char __sync_bool_compare_and_swap(int *p, int value, int compare) {
#ifndef _M_X64
	__asm {
		push	ebp
		mov		ebp,esp
		mov		ecx,[compare]
		mov		eax,[value]
		mov		edx,[p]
		lock	cmpxchg [edx],ecx
		sete	al
		movzx	eax,al
		pop		ebp
		ret
	}
#else
	char cRet = 0;
	pthread_mutex_lock(&__mx);
	if (*p == value) {
		*p = compare;
		cRet = 1;
	}
	pthread_mutex_unlock(&__mx);
	return cRet;
#endif
}

declspace_naked int __sync_and_and_fetch(int *p, int n) {
#ifndef _M_X64
	__asm {
		push	ebp
		mov		ebp,esp
		push	esi
		push	ebx
		mov		esi,[n]
		mov		edx,[p]
		mov		eax,[edx]
retry:
		mov		ecx,eax
		and		ecx,esi
		mov		ebx,ecx
		lock	cmpxchg [edx],ecx
		sete	cl
		test	cl,cl
		je		retry
		mov		eax,ebx
		pop		ebx
		pop		esi
		pop		ebp
		ret
	}
#else
	int iRet = 0;
	pthread_mutex_lock(&__mx);
	iRet = *p = (*p) & n;
	pthread_mutex_unlock(&__mx);
	return iRet;
#endif
}
