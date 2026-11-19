// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2026 The gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#define GADGET_PATH_MAX 4096
#define GADGET_S_IFMT 00170000
#define GADGET_S_IFREG 0100000
#define GADGET_VM_RWX 0x7
#define GADGET_VM_MAYSHARE 0x80

struct gadget_mapped_file {
	gadget_mntns_id mntns_id;
	gadget_pid pid;
	gadget_tid tid;
	__u64 process_start_ns;
	__u64 inode;
	__u64 start;
	__u64 end;
	__u64 offset_pages;
	__u32 dev_major;
	__u32 dev_minor;
	__u32 flags;
	__s32 path_error;
	bool deleted;
	char comm[TASK_COMM_LEN];
	char fname[GADGET_PATH_MAX];
};

/* Large memset calls cannot be lowered to BPF instructions by all builders. */
static const struct gadget_mapped_file gadget_empty_mapped_file = {};

/* One record per CPU keeps paths off the 512-byte BPF stack without a
 * capacity-limited deduplication map that could silently lose files.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gadget_mapped_file);
} gadget_mapped_file_heap SEC(".maps");

GADGET_ITER(mappings, gadget_mapped_file, gadget_snapshot_mapped_file);

SEC("iter/task_vma")
int gadget_snapshot_mapped_file(struct bpf_iter__task_vma *ctx)
{
	struct task_struct *task = ctx->task;
	struct vm_area_struct *vma = ctx->vma;

	if (!vma || !task)
		return 0;

	/* Keep the CO-RE direct load: bpf_d_path requires a verifier-trusted
	 * file pointer, which a bpf_probe_read_kernel-based read would lose.
	 */
	struct file *vm_file = vma->vm_file;
	if (!vm_file)
		return 0;
	struct inode *inode = BPF_CORE_READ(vm_file, f_inode);
	if ((BPF_CORE_READ(inode, i_mode) & GADGET_S_IFMT) != GADGET_S_IFREG)
		return 0;

	/* The iterator's task is not necessarily current. Thread-group leaders
	 * represent the shared address space once, not once per thread.
	 */
	__u32 pid = BPF_CORE_READ(task, tgid);
	__u32 tid = BPF_CORE_READ(task, pid);
	if (pid != tid)
		return 0;

	__u32 zero = 0;
	struct gadget_mapped_file *event =
		bpf_map_lookup_elem(&gadget_mapped_file_heap, &zero);
	if (!event) {
		bpf_printk("gadget: mapped-file scratch lookup failed");
		return 0;
	}
	if (bpf_probe_read_kernel(event, sizeof(*event),
				  &gadget_empty_mapped_file)) {
		bpf_printk("gadget: clearing mapped-file record failed");
		return 0;
	}
	event->pid = pid;
	event->tid = tid;
	event->process_start_ns = BPF_CORE_READ(task, start_time);
	__u32 uid = BPF_CORE_READ(task, cred, uid.val);
	__u32 gid = BPF_CORE_READ(task, cred, gid.val);
	event->mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (BPF_CORE_READ_STR_INTO(&event->comm, task, comm) < 0) {
		bpf_printk("gadget: reading mapped-file process name failed");
		return 0;
	}
	if (gadget_should_discard_data(event->mntns_id, pid, tid, event->comm,
				       uid, gid))
		return 0;

	event->inode = BPF_CORE_READ(inode, i_ino);
	__u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
	event->dev_major = dev >> 20;
	event->dev_minor = dev & ((1U << 20) - 1);
	event->deleted = BPF_CORE_READ(inode, i_nlink) == 0;
	event->start = BPF_CORE_READ(vma, vm_start);
	event->end = BPF_CORE_READ(vma, vm_end);
	event->offset_pages = BPF_CORE_READ(vma, vm_pgoff);
	__u64 flags = BPF_CORE_READ(vma, vm_flags);
	event->flags = flags & GADGET_VM_RWX;
	if (flags & GADGET_VM_MAYSHARE)
		event->flags |= 8;

	long ret = bpf_d_path(&vm_file->f_path, event->fname,
			      sizeof(event->fname));
	if (ret < 0) {
		event->path_error = ret;
		if (bpf_probe_read_kernel(event->fname, sizeof(event->fname),
					  gadget_empty_mapped_file.fname)) {
			bpf_printk("gadget: clearing mapped-file path failed");
			return 0;
		}
	}

	if (bpf_seq_write(ctx->meta->seq, event, sizeof(*event)))
		bpf_printk("gadget: writing mapped-file snapshot failed");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
