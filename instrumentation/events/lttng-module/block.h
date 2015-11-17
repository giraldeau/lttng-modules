#undef TRACE_SYSTEM
#define TRACE_SYSTEM block

#if !defined(_TRACE_BLOCK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BLOCK_H

#include <linux/blktrace_api.h>
#include <linux/blkdev.h>
#include <linux/tracepoint.h>
#include <linux/trace_seq.h>
#include <linux/version.h>

#define RWBS_LEN	8

#ifndef _TRACE_BLOCK_DEF_
#define _TRACE_BLOCK_DEF_

#define __blk_dump_cmd(cmd, len)	"<unknown>"

enum {
	RWBS_FLAG_WRITE		= (1 << 0),
	RWBS_FLAG_DISCARD	= (1 << 1),
	RWBS_FLAG_READ		= (1 << 2),
	RWBS_FLAG_RAHEAD	= (1 << 3),
	RWBS_FLAG_BARRIER	= (1 << 4),
	RWBS_FLAG_SYNC		= (1 << 5),
	RWBS_FLAG_META		= (1 << 6),
	RWBS_FLAG_SECURE	= (1 << 7),
	RWBS_FLAG_FLUSH		= (1 << 8),
	RWBS_FLAG_FUA		= (1 << 9),
};

#endif /* _TRACE_BLOCK_DEF_ */

#define __print_rwbs_flags(rwbs)		\
	__print_flags(rwbs, "",			\
		{ RWBS_FLAG_FLUSH, "F" },	\
		{ RWBS_FLAG_WRITE, "W" },	\
		{ RWBS_FLAG_DISCARD, "D" },	\
		{ RWBS_FLAG_READ, "R" },	\
		{ RWBS_FLAG_FUA, "F" },		\
		{ RWBS_FLAG_RAHEAD, "A" },	\
		{ RWBS_FLAG_BARRIER, "B" },	\
		{ RWBS_FLAG_SYNC, "S" },	\
		{ RWBS_FLAG_META, "M" },	\
		{ RWBS_FLAG_SECURE, "E" })

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0))

#define blk_fill_rwbs(rwbs, rw, bytes)					      \
		tp_assign(rwbs, ((rw) & WRITE ? RWBS_FLAG_WRITE :	      \
			( (rw) & REQ_DISCARD ? RWBS_FLAG_DISCARD :	      \
			( (bytes) ? RWBS_FLAG_READ :			      \
			( 0 ))))					      \
			| ((rw) & REQ_RAHEAD ? RWBS_FLAG_RAHEAD : 0)	      \
			| ((rw) & REQ_SYNC ? RWBS_FLAG_SYNC : 0)	      \
			| ((rw) & REQ_META ? RWBS_FLAG_META : 0)	      \
			| ((rw) & REQ_SECURE ? RWBS_FLAG_SECURE : 0)	      \
			| ((rw) & REQ_FLUSH ? RWBS_FLAG_FLUSH : 0)	      \
			| ((rw) & REQ_FUA ? RWBS_FLAG_FUA : 0))

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37))

#define blk_fill_rwbs(rwbs, rw, bytes)					      \
		tp_assign(rwbs, ((rw) & WRITE ? RWBS_FLAG_WRITE :	      \
			( (rw) & REQ_DISCARD ? RWBS_FLAG_DISCARD :	      \
			( (bytes) ? RWBS_FLAG_READ :			      \
			( 0 ))))					      \
			| ((rw) & REQ_RAHEAD ? RWBS_FLAG_RAHEAD : 0)	      \
			| ((rw) & REQ_SYNC ? RWBS_FLAG_SYNC : 0)	      \
			| ((rw) & REQ_META ? RWBS_FLAG_META : 0)	      \
			| ((rw) & REQ_SECURE ? RWBS_FLAG_SECURE : 0))

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36))

#define blk_fill_rwbs(rwbs, rw, bytes)					      \
		tp_assign(rwbs, ((rw) & WRITE ? RWBS_FLAG_WRITE :	      \
			( (rw) & REQ_DISCARD ? RWBS_FLAG_DISCARD :	      \
			( (bytes) ? RWBS_FLAG_READ :			      \
			( 0 ))))					      \
			| ((rw) & REQ_RAHEAD ? RWBS_FLAG_RAHEAD : 0)	      \
			| ((rw) & REQ_HARDBARRIER ? RWBS_FLAG_BARRIER : 0)    \
			| ((rw) & REQ_SYNC ? RWBS_FLAG_SYNC : 0)	      \
			| ((rw) & REQ_META ? RWBS_FLAG_META : 0)	      \
			| ((rw) & REQ_SECURE ? RWBS_FLAG_SECURE : 0))

#else

#define blk_fill_rwbs(rwbs, rw, bytes)					      \
		tp_assign(rwbs, ((rw) & WRITE ? RWBS_FLAG_WRITE :	      \
			( (rw) & (1 << BIO_RW_DISCARD) ? RWBS_FLAG_DISCARD :  \
			( (bytes) ? RWBS_FLAG_READ :			      \
			( 0 ))))					      \
			| ((rw) & (1 << BIO_RW_AHEAD) ? RWBS_FLAG_RAHEAD : 0) \
			| ((rw) & (1 << BIO_RW_SYNCIO) ? RWBS_FLAG_SYNC : 0)  \
			| ((rw) & (1 << BIO_RW_META) ? RWBS_FLAG_META : 0)    \
			| ((rw) & (1 << BIO_RW_BARRIER) ? RWBS_FLAG_BARRIER : 0))

#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
DECLARE_EVENT_CLASS(block_buffer,

	TP_PROTO(struct buffer_head *bh),

	TP_ARGS(bh),

	TP_STRUCT__entry (
		__field(  dev_t,	dev			)
		__field(  sector_t,	sector			)
		__field(  size_t,	size			)
	),

	TP_fast_assign(
		tp_assign(dev, bh->b_bdev->bd_dev)
		tp_assign(sector, bh->b_blocknr)
		tp_assign(size, bh->b_size)
	),

	TP_printk("%d,%d sector=%llu size=%zu",
		MAJOR(__entry->dev), MINOR(__entry->dev),
		(unsigned long long)__entry->sector, __entry->size
	)
)

/**
 * block_touch_buffer - mark a buffer accessed
 * @bh: buffer_head being touched
 *
 * Called from touch_buffer().
 */
DEFINE_EVENT(block_buffer, block_touch_buffer,

	TP_PROTO(struct buffer_head *bh),

	TP_ARGS(bh)
)

/**
 * block_dirty_buffer - mark a buffer dirty
 * @bh: buffer_head being dirtied
 *
 * Called from mark_buffer_dirty().
 */
DEFINE_EVENT(block_buffer, block_dirty_buffer,

	TP_PROTO(struct buffer_head *bh),

	TP_ARGS(bh)
)
#endif

DECLARE_EVENT_CLASS(block_rq_with_error,

	TP_PROTO(struct request_queue *q, struct request *rq),

	TP_ARGS(q, rq),

	TP_STRUCT__entry(
		__field(  dev_t,	dev			)
		__field(  sector_t,	sector			)
		__field(  unsigned int,	nr_sector		)
		__field(  int,		errors			)
		__field(  unsigned int,	rwbs			)
		__dynamic_array_hex( unsigned char,	cmd,
			(rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
				rq->cmd_len : 0)
	),

	TP_fast_assign(
		tp_assign(dev, rq->rq_disk ? disk_devt(rq->rq_disk) : 0)
		tp_assign(sector, (rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
					0 : blk_rq_pos(rq))
		tp_assign(nr_sector, (rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
					0 : blk_rq_sectors(rq))
		tp_assign(errors, rq->errors)
		blk_fill_rwbs(rwbs, rq->cmd_flags, blk_rq_bytes(rq))
		tp_memcpy_dyn(cmd, (rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
					rq->cmd : NULL)
	),

	TP_printk("%d,%d %s (%s) %llu + %u [%d]",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  __blk_dump_cmd(__get_dynamic_array(cmd),
				 __get_dynamic_array_len(cmd)),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->errors)
)

/**
 * block_rq_abort - abort block operation request
 * @q: queue containing the block operation request
 * @rq: block IO operation request
 *
 * Called immediately after pending block IO operation request @rq in
 * queue @q is aborted. The fields in the operation request @rq
 * can be examined to determine which device and sectors the pending
 * operation would access.
 */
DEFINE_EVENT(block_rq_with_error, block_rq_abort,

	TP_PROTO(struct request_queue *q, struct request *rq),

	TP_ARGS(q, rq)
)

/**
 * block_rq_requeue - place block IO request back on a queue
 * @q: queue holding operation
 * @rq: block IO operation request
 *
 * The block operation request @rq is being placed back into queue
 * @q.  For some reason the request was not completed and needs to be
 * put back in the queue.
 */
DEFINE_EVENT(block_rq_with_error, block_rq_requeue,

	TP_PROTO(struct request_queue *q, struct request *rq),

	TP_ARGS(q, rq)
)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,5)	\
	|| LTTNG_KERNEL_RANGE(3,12,21, 3,14,0)		\
	|| LTTNG_KERNEL_RANGE(3,10,41, 3,11,0)		\
	|| LTTNG_KERNEL_RANGE(3,4,91, 3,5,0)		\
	|| LTTNG_KERNEL_RANGE(3,2,58, 3,3,0))

/**
 * block_rq_complete - block IO operation completed by device driver
 * @q: queue containing the block operation request
 * @rq: block operations request
 * @nr_bytes: number of completed bytes
 *
 * The block_rq_complete tracepoint event indicates that some portion
 * of operation request has been completed by the device driver.  If
 * the @rq->bio is %NULL, then there is absolutely no additional work to
 * do for the request. If @rq->bio is non-NULL then there is
 * additional work required to complete the request.
 */
TRACE_EVENT(block_rq_complete,

	TP_PROTO(struct request_queue *q, struct request *rq,
		 unsigned int nr_bytes),

	TP_ARGS(q, rq, nr_bytes),

	TP_STRUCT__entry(
		__field(  dev_t,	dev			)
		__field(  sector_t,	sector			)
		__field(  unsigned int,	nr_sector		)
		__field(  int,		errors			)
		__field(  unsigned int,	rwbs			)
		__dynamic_array_hex( unsigned char,	cmd,
			(rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
				rq->cmd_len : 0)
	),

	TP_fast_assign(
		tp_assign(dev, rq->rq_disk ? disk_devt(rq->rq_disk) : 0)
		tp_assign(sector, blk_rq_pos(rq))
		tp_assign(nr_sector, nr_bytes >> 9)
		tp_assign(errors, rq->errors)
		blk_fill_rwbs(rwbs, rq->cmd_flags, nr_bytes)
		tp_memcpy_dyn(cmd, (rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
					rq->cmd : NULL)
	),

	TP_printk("%d,%d %s (%s) %llu + %u [%d]",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->rwbs, __get_str(cmd),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->errors)
)

#else /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)) */

/**
 * block_rq_complete - block IO operation completed by device driver
 * @q: queue containing the block operation request
 * @rq: block operations request
 *
 * The block_rq_complete tracepoint event indicates that some portion
 * of operation request has been completed by the device driver.  If
 * the @rq->bio is %NULL, then there is absolutely no additional work to
 * do for the request. If @rq->bio is non-NULL then there is
 * additional work required to complete the request.
 */
DEFINE_EVENT(block_rq_with_error, block_rq_complete,

	TP_PROTO(struct request_queue *q, struct request *rq),

	TP_ARGS(q, rq)
)

#endif /* #else #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)) */

DECLARE_EVENT_CLASS(block_rq,

	TP_PROTO(struct request_queue *q, struct request *rq),

	TP_ARGS(q, rq),

	TP_STRUCT__entry(
		__field(  dev_t,	dev			)
		__field(  sector_t,	sector			)
		__field(  unsigned int,	nr_sector		)
		__field(  unsigned int,	bytes			)
		__field(  unsigned int,	rwbs			)
		__array_text(  char,         comm,   TASK_COMM_LEN   )
		__dynamic_array_hex( unsigned char,	cmd,
			(rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
				rq->cmd_len : 0)
	),

	TP_fast_assign(
		tp_assign(dev, rq->rq_disk ? disk_devt(rq->rq_disk) : 0)
		tp_assign(sector, (rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
					0 : blk_rq_pos(rq))
		tp_assign(nr_sector, (rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
					0 : blk_rq_sectors(rq))
		tp_assign(bytes, (rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
					blk_rq_bytes(rq) : 0)
		blk_fill_rwbs(rwbs, rq->cmd_flags, blk_rq_bytes(rq))
		tp_memcpy_dyn(cmd, (rq->cmd_type == REQ_TYPE_BLOCK_PC) ?
					rq->cmd : NULL)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
	),

	TP_printk("%d,%d %s %u (%s) %llu + %u [%s]",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  __entry->bytes,
		  __blk_dump_cmd(__get_dynamic_array(cmd),
				 __get_dynamic_array_len(cmd)),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->comm)
)

/**
 * block_rq_insert - insert block operation request into queue
 * @q: target queue
 * @rq: block IO operation request
 *
 * Called immediately before block operation request @rq is inserted
 * into queue @q.  The fields in the operation request @rq struct can
 * be examined to determine which device and sectors the pending
 * operation would access.
 */
DEFINE_EVENT(block_rq, block_rq_insert,

	TP_PROTO(struct request_queue *q, struct request *rq),

	TP_ARGS(q, rq)
)

/**
 * block_rq_issue - issue pending block IO request operation to device driver
 * @q: queue holding operation
 * @rq: block IO operation operation request
 *
 * Called when block operation request @rq from queue @q is sent to a
 * device driver for processing.
 */
DEFINE_EVENT(block_rq, block_rq_issue,

	TP_PROTO(struct request_queue *q, struct request *rq),

	TP_ARGS(q, rq)
)

/**
 * block_bio_bounce - used bounce buffer when processing block operation
 * @q: queue holding the block operation
 * @bio: block operation
 *
 * A bounce buffer was used to handle the block operation @bio in @q.
 * This occurs when hardware limitations prevent a direct transfer of
 * data between the @bio data memory area and the IO device.  Use of a
 * bounce buffer requires extra copying of data and decreases
 * performance.
 */
TRACE_EVENT(block_bio_bounce,

	TP_PROTO(struct request_queue *q, struct bio *bio),

	TP_ARGS(q, bio),

	TP_STRUCT__entry(
		__field( dev_t,		dev			)
		__field( sector_t,	sector			)
		__field( unsigned int,	nr_sector		)
		__field( unsigned int,	rwbs			)
		__array_text( char,		comm,	TASK_COMM_LEN	)
	),

	TP_fast_assign(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		tp_assign(dev, bio->bi_bdev ?
					  bio->bi_bdev->bd_dev : 0)
		tp_assign(sector, bio->bi_iter.bi_sector)
		tp_assign(nr_sector, bio_sectors(bio))
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_iter.bi_size)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#else /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
		tp_assign(dev, bio->bi_bdev ?
					  bio->bi_bdev->bd_dev : 0)
		tp_assign(sector, bio->bi_sector)
		tp_assign(nr_sector, bio->bi_size >> 9)
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_size)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#endif /* #else #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
	),

	TP_printk("%d,%d %s %llu + %u [%s]",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->comm)
)

/**
 * block_bio_complete - completed all work on the block operation
 * @q: queue holding the block operation
 * @bio: block operation completed
 * @error: io error value
 *
 * This tracepoint indicates there is no further work to do on this
 * block IO operation @bio.
 */
TRACE_EVENT(block_bio_complete,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
	TP_PROTO(struct request_queue *q, struct bio *bio, int error),

	TP_ARGS(q, bio, error),
#else
	TP_PROTO(struct request_queue *q, struct bio *bio),

	TP_ARGS(q, bio),
#endif

	TP_STRUCT__entry(
		__field( dev_t,		dev		)
		__field( sector_t,	sector		)
		__field( unsigned,	nr_sector	)
		__field( int,		error		)
		__field( unsigned int,	rwbs		)
	),

	TP_fast_assign(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_iter.bi_sector)
		tp_assign(nr_sector, bio_sectors(bio))
		tp_assign(error, error)
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_iter.bi_size)
#else /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_sector)
		tp_assign(nr_sector, bio->bi_size >> 9)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
		tp_assign(error, error)
#else
		tp_assign(error, 0)
#endif
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_size)
#endif /* #else #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
	),

	TP_printk("%d,%d %s %llu + %u [%d]",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->error)
)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
DECLARE_EVENT_CLASS(block_bio_merge,

	TP_PROTO(struct request_queue *q, struct request *rq, struct bio *bio),

	TP_ARGS(q, rq, bio),

	TP_STRUCT__entry(
		__field( dev_t,		dev			)
		__field( sector_t,	sector			)
		__field( unsigned int,	nr_sector		)
		__field( unsigned int,	rwbs			)
		__array_text( char,		comm,	TASK_COMM_LEN	)
	),

	TP_fast_assign(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_iter.bi_sector)
		tp_assign(nr_sector, bio_sectors(bio))
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_iter.bi_size)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#else /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_sector)
		tp_assign(nr_sector, bio->bi_size >> 9)
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_size)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#endif /* #else #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
	),

	TP_printk("%d,%d %s %llu + %u [%s]",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->comm)
)

/**
 * block_bio_backmerge - merging block operation to the end of an existing operation
 * @q: queue holding operation
 * @bio: new block operation to merge
 *
 * Merging block request @bio to the end of an existing block request
 * in queue @q.
 */
DEFINE_EVENT(block_bio_merge, block_bio_backmerge,

	TP_PROTO(struct request_queue *q, struct request *rq, struct bio *bio),

	TP_ARGS(q, rq, bio)
)

/**
 * block_bio_frontmerge - merging block operation to the beginning of an existing operation
 * @q: queue holding operation
 * @bio: new block operation to merge
 *
 * Merging block IO operation @bio to the beginning of an existing block
 * operation in queue @q.
 */
DEFINE_EVENT(block_bio_merge, block_bio_frontmerge,

	TP_PROTO(struct request_queue *q, struct request *rq, struct bio *bio),

	TP_ARGS(q, rq, bio)
)

/**
 * block_bio_queue - putting new block IO operation in queue
 * @q: queue holding operation
 * @bio: new block operation
 *
 * About to place the block IO operation @bio into queue @q.
 */
TRACE_EVENT(block_bio_queue,

	TP_PROTO(struct request_queue *q, struct bio *bio),

	TP_ARGS(q, bio),

	TP_STRUCT__entry(
		__field( dev_t,		dev			)
		__field( sector_t,	sector			)
		__field( unsigned int,	nr_sector		)
		__field( unsigned int,	rwbs			)
		__array_text( char,		comm,	TASK_COMM_LEN	)
	),

	TP_fast_assign(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_iter.bi_sector)
		tp_assign(nr_sector, bio_sectors(bio))
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_iter.bi_size)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#else /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_sector)
		tp_assign(nr_sector, bio->bi_size >> 9)
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_size)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#endif /* #else #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
	),

	TP_printk("%d,%d %s %llu + %u [%s]",
		  MAJOR(__entry->dev), MINOR(__entry->dev), __entry->rwbs,
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->comm)
)
#else
DECLARE_EVENT_CLASS(block_bio,

	TP_PROTO(struct request_queue *q, struct bio *bio),

	TP_ARGS(q, bio),

	TP_STRUCT__entry(
		__field( dev_t,		dev			)
		__field( sector_t,	sector			)
		__field( unsigned int,	nr_sector		)
		__field( unsigned int,	rwbs			)
		__array_text( char,		comm,	TASK_COMM_LEN	)
	),

	TP_fast_assign(
		tp_assign(dev, bio->bi_bdev ? bio->bi_bdev->bd_dev : 0)
		tp_assign(sector, bio->bi_sector)
		tp_assign(nr_sector, bio->bi_size >> 9)
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_size)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
	),

	TP_printk("%d,%d %s %llu + %u [%s]",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->comm)
)

/**
 * block_bio_backmerge - merging block operation to the end of an existing operation
 * @q: queue holding operation
 * @bio: new block operation to merge
 *
 * Merging block request @bio to the end of an existing block request
 * in queue @q.
 */
DEFINE_EVENT(block_bio, block_bio_backmerge,

	TP_PROTO(struct request_queue *q, struct bio *bio),

	TP_ARGS(q, bio)
)

/**
 * block_bio_frontmerge - merging block operation to the beginning of an existing operation
 * @q: queue holding operation
 * @bio: new block operation to merge
 *
 * Merging block IO operation @bio to the beginning of an existing block
 * operation in queue @q.
 */
DEFINE_EVENT(block_bio, block_bio_frontmerge,

	TP_PROTO(struct request_queue *q, struct bio *bio),

	TP_ARGS(q, bio)
)

/**
 * block_bio_queue - putting new block IO operation in queue
 * @q: queue holding operation
 * @bio: new block operation
 *
 * About to place the block IO operation @bio into queue @q.
 */
DEFINE_EVENT(block_bio, block_bio_queue,

	TP_PROTO(struct request_queue *q, struct bio *bio),

	TP_ARGS(q, bio)
)
#endif

DECLARE_EVENT_CLASS(block_get_rq,

	TP_PROTO(struct request_queue *q, struct bio *bio, int rw),

	TP_ARGS(q, bio, rw),

	TP_STRUCT__entry(
		__field( dev_t,		dev			)
		__field( sector_t,	sector			)
		__field( unsigned int,	nr_sector		)
		__field( unsigned int,	rwbs			)
		__array_text( char,		comm,	TASK_COMM_LEN	)
        ),

	TP_fast_assign(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		tp_assign(dev, bio ? bio->bi_bdev->bd_dev : 0)
		tp_assign(sector, bio ? bio->bi_iter.bi_sector : 0)
		tp_assign(nr_sector, bio ? bio_sectors(bio) : 0)
		blk_fill_rwbs(rwbs, bio ? bio->bi_rw : 0,
			      bio ? bio_sectors(bio) : 0)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#else /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
		tp_assign(dev, bio ? bio->bi_bdev->bd_dev : 0)
		tp_assign(sector, bio ? bio->bi_sector : 0)
		tp_assign(nr_sector, bio ? bio->bi_size >> 9 : 0)
		blk_fill_rwbs(rwbs, bio ? bio->bi_rw : 0,
			      bio ? bio->bi_size >> 9 : 0)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#endif /* #else #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
        ),

	TP_printk("%d,%d %s %llu + %u [%s]",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector, __entry->comm)
)

/**
 * block_getrq - get a free request entry in queue for block IO operations
 * @q: queue for operations
 * @bio: pending block IO operation
 * @rw: low bit indicates a read (%0) or a write (%1)
 *
 * A request struct for queue @q has been allocated to handle the
 * block IO operation @bio.
 */
DEFINE_EVENT(block_get_rq, block_getrq,

	TP_PROTO(struct request_queue *q, struct bio *bio, int rw),

	TP_ARGS(q, bio, rw)
)

/**
 * block_sleeprq - waiting to get a free request entry in queue for block IO operation
 * @q: queue for operation
 * @bio: pending block IO operation
 * @rw: low bit indicates a read (%0) or a write (%1)
 *
 * In the case where a request struct cannot be provided for queue @q
 * the process needs to wait for an request struct to become
 * available.  This tracepoint event is generated each time the
 * process goes to sleep waiting for request struct become available.
 */
DEFINE_EVENT(block_get_rq, block_sleeprq,

	TP_PROTO(struct request_queue *q, struct bio *bio, int rw),

	TP_ARGS(q, bio, rw)
)

/**
 * block_plug - keep operations requests in request queue
 * @q: request queue to plug
 *
 * Plug the request queue @q.  Do not allow block operation requests
 * to be sent to the device driver. Instead, accumulate requests in
 * the queue to improve throughput performance of the block device.
 */
TRACE_EVENT(block_plug,

	TP_PROTO(struct request_queue *q),

	TP_ARGS(q),

	TP_STRUCT__entry(
		__array_text( char,		comm,	TASK_COMM_LEN	)
	),

	TP_fast_assign(
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
	),

	TP_printk("[%s]", __entry->comm)
)

DECLARE_EVENT_CLASS(block_unplug,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
	TP_PROTO(struct request_queue *q, unsigned int depth, bool explicit),

	TP_ARGS(q, depth, explicit),
#else
	TP_PROTO(struct request_queue *q),

	TP_ARGS(q),
#endif

	TP_STRUCT__entry(
		__field( int,		nr_rq			)
		__array_text( char,		comm,	TASK_COMM_LEN	)
	),

	TP_fast_assign(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
		tp_assign(nr_rq, depth)
#else
		tp_assign(nr_rq, q->rq.count[READ] + q->rq.count[WRITE])
#endif
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
	),

	TP_printk("[%s] %d", __entry->comm, __entry->nr_rq)
)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))
/**
 * block_unplug_timer - timed release of operations requests in queue to device driver
 * @q: request queue to unplug
 *
 * Unplug the request queue @q because a timer expired and allow block
 * operation requests to be sent to the device driver.
 */
DEFINE_EVENT(block_unplug, block_unplug_timer,

	TP_PROTO(struct request_queue *q),

	TP_ARGS(q)
)
#endif

/**
 * block_unplug - release of operations requests in request queue
 * @q: request queue to unplug
 * @depth: number of requests just added to the queue
 * @explicit: whether this was an explicit unplug, or one from schedule()
 *
 * Unplug request queue @q because device driver is scheduled to work
 * on elements in the request queue.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
DEFINE_EVENT(block_unplug, block_unplug,
#else
DEFINE_EVENT(block_unplug, block_unplug_io,
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
	TP_PROTO(struct request_queue *q, unsigned int depth, bool explicit),

	TP_ARGS(q, depth, explicit)
#else
	TP_PROTO(struct request_queue *q),

	TP_ARGS(q)
#endif
)

/**
 * block_split - split a single bio struct into two bio structs
 * @q: queue containing the bio
 * @bio: block operation being split
 * @new_sector: The starting sector for the new bio
 *
 * The bio request @bio in request queue @q needs to be split into two
 * bio requests. The newly created @bio request starts at
 * @new_sector. This split may be required due to hardware limitation
 * such as operation crossing device boundaries in a RAID system.
 */
TRACE_EVENT(block_split,

	TP_PROTO(struct request_queue *q, struct bio *bio,
		 unsigned int new_sector),

	TP_ARGS(q, bio, new_sector),

	TP_STRUCT__entry(
		__field( dev_t,		dev				)
		__field( sector_t,	sector				)
		__field( sector_t,	new_sector			)
		__field( unsigned int,	rwbs		)
		__array_text( char,		comm,		TASK_COMM_LEN	)
	),

	TP_fast_assign(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_iter.bi_sector)
		tp_assign(new_sector, new_sector)
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_iter.bi_size)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#else /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_sector)
		tp_assign(new_sector, new_sector)
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_size)
		tp_memcpy(comm, current->comm, TASK_COMM_LEN)
#endif /* #else #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
	),

	TP_printk("%d,%d %s %llu / %llu [%s]",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  (unsigned long long)__entry->sector,
		  (unsigned long long)__entry->new_sector,
		  __entry->comm)
)

/**
 * block_bio_remap - map request for a logical device to the raw device
 * @q: queue holding the operation
 * @bio: revised operation
 * @dev: device for the operation
 * @from: original sector for the operation
 *
 * An operation for a logical device has been mapped to the
 * raw block device.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
TRACE_EVENT(block_bio_remap,
#else
TRACE_EVENT(block_remap,
#endif

	TP_PROTO(struct request_queue *q, struct bio *bio, dev_t dev,
		 sector_t from),

	TP_ARGS(q, bio, dev, from),

	TP_STRUCT__entry(
		__field( dev_t,		dev		)
		__field( sector_t,	sector		)
		__field( unsigned int,	nr_sector	)
		__field( dev_t,		old_dev		)
		__field( sector_t,	old_sector	)
		__field( unsigned int,	rwbs		)
	),

	TP_fast_assign(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_iter.bi_sector)
		tp_assign(nr_sector, bio_sectors(bio))
		tp_assign(old_dev, dev)
		tp_assign(old_sector, from)
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_iter.bi_size)
#else /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
		tp_assign(dev, bio->bi_bdev->bd_dev)
		tp_assign(sector, bio->bi_sector)
		tp_assign(nr_sector, bio->bi_size >> 9)
		tp_assign(old_dev, dev)
		tp_assign(old_sector, from)
		blk_fill_rwbs(rwbs, bio->bi_rw, bio->bi_size)
#endif /* #else #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)) */
	),

	TP_printk("%d,%d %s %llu + %u <- (%d,%d) %llu",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector,
		  MAJOR(__entry->old_dev), MINOR(__entry->old_dev),
		  (unsigned long long)__entry->old_sector)
)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32))
/**
 * block_rq_remap - map request for a block operation request
 * @q: queue holding the operation
 * @rq: block IO operation request
 * @dev: device for the operation
 * @from: original sector for the operation
 *
 * The block operation request @rq in @q has been remapped.  The block
 * operation request @rq holds the current information and @from hold
 * the original sector.
 */
TRACE_EVENT(block_rq_remap,

	TP_PROTO(struct request_queue *q, struct request *rq, dev_t dev,
		 sector_t from),

	TP_ARGS(q, rq, dev, from),

	TP_STRUCT__entry(
		__field( dev_t,		dev		)
		__field( sector_t,	sector		)
		__field( unsigned int,	nr_sector	)
		__field( dev_t,		old_dev		)
		__field( sector_t,	old_sector	)
		__field( unsigned int,	rwbs		)
	),

	TP_fast_assign(
		tp_assign(dev, disk_devt(rq->rq_disk))
		tp_assign(sector, blk_rq_pos(rq))
		tp_assign(nr_sector, blk_rq_sectors(rq))
		tp_assign(old_dev, dev)
		tp_assign(old_sector, from)
		blk_fill_rwbs(rwbs, rq->cmd_flags, blk_rq_bytes(rq))
	),

	TP_printk("%d,%d %s %llu + %u <- (%d,%d) %llu",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_rwbs_flags(__entry->rwbs),
		  (unsigned long long)__entry->sector,
		  __entry->nr_sector,
		  MAJOR(__entry->old_dev), MINOR(__entry->old_dev),
		  (unsigned long long)__entry->old_sector)
)
#endif

#undef __print_rwbs_flags
#undef blk_fill_rwbs

#endif /* _TRACE_BLOCK_H */

/* This part must be outside protection */
#include "../../../probes/define_trace.h"

