
#ifndef HYPERCALL_V4v_H__
#define HYPERCALL_V4v_H__

#include <asm/xen/hypercall.h>


#ifdef CONFIG_X86_32
#define __HYPERCALL_ARG6REG     "ebp"
#else
#define __HYPERCALL_ARG6REG	"r9"
#endif

#undef __HYPERCALL_DECLS
#define __HYPERCALL_DECLS						\
	register unsigned long __res  asm(__HYPERCALL_RETREG);		\
	register unsigned long __arg1 asm(__HYPERCALL_ARG1REG) = __arg1; \
	register unsigned long __arg2 asm(__HYPERCALL_ARG2REG) = __arg2; \
	register unsigned long __arg3 asm(__HYPERCALL_ARG3REG) = __arg3; \
	register unsigned long __arg4 asm(__HYPERCALL_ARG4REG) = __arg4; \
	register unsigned long __arg5 asm(__HYPERCALL_ARG5REG) = __arg5; \
	register unsigned long __arg6 asm(__HYPERCALL_ARG6REG) = __arg6; \
	register void *__sp asm(_ASM_SP);

#undef __HYPERCALL_CLOBBER5

#define __HYPERCALL_CLOBBER6	"memory"
#define __HYPERCALL_CLOBBER5	__HYPERCALL_CLOBBER6, __HYPERCALL_ARG6REG

#define __HYPERCALL_6ARG(a1,a2,a3,a4,a5,a6)				\
	__HYPERCALL_5ARG(a1,a2,a3,a4,a5) __arg6 = (unsigned long) (a6);

#ifdef CONFIG_X86_32
#define __HYPERCALL_6PARAM	__HYPERCALL_5PARAM
#define _hypercall6(type, name, a1, a2, a3, a4, a5, a6)			\
({									\
	__HYPERCALL_DECLS;						\
	__HYPERCALL_6ARG(a1, a2, a3, a4, a5, a6);			\
	asm volatile (							\
			"push %%ebp; mov %%eax, %%ebp;"			\
			__HYPERCALL ";"					\
			"pop %%ebp"					\
		      : __HYPERCALL_6PARAM				\
		      : __HYPERCALL_ENTRY(name), "0" ((long) (a6))      \
		      : __HYPERCALL_CLOBBER6);				\
	(type)__res;							\
})
#else
#define __HYPERCALL_6PARAM      __HYPERCALL_5PARAM, "+r" (__arg6)
#define _hypercall6(type, name, a1, a2, a3, a4, a5, a6)			\
({									\
	__HYPERCALL_DECLS;						\
	__HYPERCALL_6ARG(a1, a2, a3, a4, a5, a6);			\
	asm volatile (__HYPERCALL ";"					\
		      : __HYPERCALL_6PARAM				\
		      : __HYPERCALL_ENTRY(name)				\
		      : __HYPERCALL_CLOBBER6);				\
	(type)__res;							\
})
#endif

#endif /* !HYPERCALL_V4v_H__ */
