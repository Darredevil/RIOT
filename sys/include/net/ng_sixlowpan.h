/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_ng_sixlowpan    6LoWPAN
 * @ingroup     net
 * @brief       6LoWPAN implementation
 * @{
 *
 * @file
 * @brief   Definitions for 6LoWPAN
 *
 * @author  Martine Lenders <mlenders@inf.fu-berlin.de>
 */
#ifndef NG_SIXLOWPAN_H_
#define NG_SIXLOWPAN_H_

#include <stdbool.h>

#include "kernel_types.h"

#include "net/ng_sixlowpan/frag.h"
#include "net/ng_sixlowpan/iphc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Default stack size to use for the 6LoWPAN thread.
 */
#ifndef NG_SIXLOWPAN_STACK_SIZE
#define NG_SIXLOWPAN_STACK_SIZE  (THREAD_STACKSIZE_DEFAULT)
#endif

/**
 * @brief   Default priority for the 6LoWPAN thread.
 */
#ifndef NG_SIXLOWPAN_PRIO
#define NG_SIXLOWPAN_PRIO   (THREAD_PRIORITY_MAIN - 4)
#endif

/**
 * @brief   Default message queue size to use for the 6LoWPAN thread.
 */
#ifndef NG_SIXLOWPAN_MSG_QUEUE_SIZE
#define NG_SIXLOWPAN_MSG_QUEUE_SIZE (8U)
#endif

/**
 * @brief   Dispatch for uncompressed 6LoWPAN frame.
 */
#define NG_SIXLOWPAN_UNCOMPRESSED   (0x41)

/**
 * @brief   Checks if dispatch indicates that frame is not a 6LoWPAN (NALP) frame.
 *
 * @param[in] disp  The first byte of a frame.
 *
 * @return  true, if frame is a NALP.
 * @return  false, if frame is not a NALP.
 */
static inline bool ng_sixlowpan_nalp(uint8_t disp)
{
    return (disp & 0x3f);
}

/**
 * @brief   Initialization of the 6LoWPAN thread.
 *
 * @details If 6LoWPAN was already initialized, it will just return the PID of
 *          the 6LoWPAN thread.
 *
 * @return  The PID to the 6LoWPAN thread, on success.
 * @return  -EINVAL, if @ref NG_SIXLOWPAN_PRIO was greater than or equal to
 *          @ref SCHED_PRIO_LEVELS
 * @return  -EOVERFLOW, if there are too many threads running already in general
 */
kernel_pid_t ng_sixlowpan_init(void);

/**
 * @brief   Prints 6LoWPAN dispatch to stdout.
 *
 * @param[in] data  A 6LoWPAN frame.
 * @param[in] size  Size of @p data.
 */
void ng_sixlowpan_print(uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* NG_SIXLOWPAN_H_ */
/** @} */
