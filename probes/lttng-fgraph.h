/*
 * lttng-fgraph.h
 *
 *  Created on: Apr 26, 2016
 *      Author: francis
 */

#ifndef PROBES_LTTNG_FGRAPH_H_
#define PROBES_LTTNG_FGRAPH_H_

#include <linux/preempt.h>

// Copy of recursion protection code

/* Only current can touch trace_recursion */

/*
 * For function tracing recursion:
 *  The order of these bits are important.
 *
 *  When function tracing occurs, the following steps are made:
 *   If arch does not support a ftrace feature:
 *    call internal function (uses INTERNAL bits) which calls...
 *   If callback is registered to the "global" list, the list
 *    function is called and recursion checks the GLOBAL bits.
 *    then this function calls...
 *   The function callback, which can use the FTRACE bits to
 *    check for recursion.
 *
 * Now if the arch does not suppport a feature, and it calls
 * the global list function which calls the ftrace callback
 * all three of these steps will do a recursion protection.
 * There's no reason to do one if the previous caller already
 * did. The recursion that we are protecting against will
 * go through the same steps again.
 *
 * To prevent the multiple recursion checks, if a recursion
 * bit is set that is higher than the MAX bit of the current
 * check, then we know that the check was made by the previous
 * caller, and we can skip the current check.
 */
enum {
	TRACE_BUFFER_BIT,
	TRACE_BUFFER_NMI_BIT,
	TRACE_BUFFER_IRQ_BIT,
	TRACE_BUFFER_SIRQ_BIT,

	/* Start of function recursion bits */
	TRACE_FTRACE_BIT,
	TRACE_FTRACE_NMI_BIT,
	TRACE_FTRACE_IRQ_BIT,
	TRACE_FTRACE_SIRQ_BIT,

	/* INTERNAL_BITs must be greater than FTRACE_BITs */
	TRACE_INTERNAL_BIT,
	TRACE_INTERNAL_NMI_BIT,
	TRACE_INTERNAL_IRQ_BIT,
	TRACE_INTERNAL_SIRQ_BIT,

	TRACE_BRANCH_BIT,
/*
 * Abuse of the trace_recursion.
 * As we need a way to maintain state if we are tracing the function
 * graph in irq because we want to trace a particular function that
 * was called in irq context but we have irq tracing off. Since this
 * can only be modified by current, we can reuse trace_recursion.
 */
	TRACE_IRQ_BIT,
};

#define trace_recursion_set(bit)	do { (current)->trace_recursion |= (1<<(bit)); } while (0)
#define trace_recursion_clear(bit)	do { (current)->trace_recursion &= ~(1<<(bit)); } while (0)
#define trace_recursion_test(bit)	((current)->trace_recursion & (1<<(bit)))

#define TRACE_CONTEXT_BITS	4

#define TRACE_FTRACE_START	TRACE_FTRACE_BIT
#define TRACE_FTRACE_MAX	((1 << (TRACE_FTRACE_START + TRACE_CONTEXT_BITS)) - 1)

#define TRACE_LIST_START	TRACE_INTERNAL_BIT
#define TRACE_LIST_MAX		((1 << (TRACE_LIST_START + TRACE_CONTEXT_BITS)) - 1)

#define TRACE_CONTEXT_MASK	TRACE_LIST_MAX

static __always_inline int trace_get_context_bit(void)
{
	int bit;

	if (in_interrupt()) {
		if (in_nmi())
			bit = 0;

		else if (in_irq())
			bit = 1;
		else
			bit = 2;
	} else
		bit = 3;

	return bit;
}

static __always_inline int trace_test_and_set_recursion(int start, int max)
{
	unsigned int val = current->trace_recursion;
	int bit;

	/* A previous recursion check was made */
	if ((val & TRACE_CONTEXT_MASK) > max)
		return 0;

	bit = trace_get_context_bit() + start;
	if (unlikely(val & (1 << bit)))
		return -1;

	val |= 1 << bit;
	current->trace_recursion = val;
	barrier();

	return bit;
}

static __always_inline void trace_clear_recursion(int bit)
{
	unsigned int val = current->trace_recursion;

	if (!bit)
		return;

	bit = 1 << bit;
	val &= ~bit;

	barrier();
	current->trace_recursion = val;
}

#endif /* PROBES_LTTNG_FGRAPH_H_ */
