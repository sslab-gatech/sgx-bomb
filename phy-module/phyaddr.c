#include <asm/io.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>


#include <linux/sched.h>                /* test_thread_flag(), ...      */
#include <linux/kdebug.h>               /* oops_begin/end, ...          */
#include <linux/bootmem.h>              /* max_low_pfn                  */
#include <linux/kprobes.h>              /* NOKPROBE_SYMBOL, ...         */
#include <linux/mmiotrace.h>            /* kmmio_handler, ...           */
#include <linux/perf_event.h>           /* perf_sw_event                */
#include <linux/hugetlb.h>              /* hstate_index_to_shift        */
#include <linux/prefetch.h>             /* prefetchw                    */
#include <linux/context_tracking.h>     /* exception_enter(), ...       */
#include <linux/uaccess.h>              /* faulthandler_disabled()      */

#include <asm/cpufeature.h>             /* boot_cpu_has, ...            */
#include <asm/traps.h>                  /* dotraplinkage, ...           */
#include <asm/pgalloc.h>                /* pgd_*(), ...                 */
#include <asm/fixmap.h>                 /* VSYSCALL_ADDR                */
#include <asm/vsyscall.h>               /* emulate_vsyscall             */
#include <asm/vm86.h>                   /* struct vm86                  */
#include <asm/mmu_context.h>            /* vma_pkey()                   */

#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
#include <linux/delayacct.h>
#include <linux/init.h>
//#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/kallsyms.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
#include <linux/dma-debug.h>
#include <linux/debugfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>


// When userspace writes a pointer to /proc/jump, jump to that address in
// kernel mode.
//
void* resolve_addr(uint64_t address) {
    struct vm_area_struct *vma;
    struct task_struct *tsk;
    struct mm_struct *mm, *mm1;

    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    uint64_t paddr;

    tsk = current;
    mm1 = tsk->mm;

    vma = find_vma(mm1, address);

    mm = vma->vm_mm;
    pgd = pgd_offset(mm, address);


    if(pgd == NULL) {
        printk("pgd %p\n", (void*)pgd);
        return NULL;
    }
    //printk("pgd %p\n", (void*)pgd->pgd);

    pud = pud_offset((p4d_t*) pgd, address);
    if(pud == NULL) {
        printk("pud %p\n", (void*)pud);
        return NULL;
    }
    //printk("pud %p\n", (void*)pud->pud);


    pmd = pmd_offset(pud, address);
    if(pmd == NULL) {
        printk("pmd %p\n", (void*)pmd);
        return NULL;
    }
    //printk("pmd %p\n", (void*)pmd->pmd);


    pte = pte_offset_kernel(pmd, address);
    if(pte == NULL) {
        printk("pte %p\n", (void*)pte);
        return NULL;
    }
    //printk("pte %p\n", (void*)pte->pte);
    paddr = 0;
    paddr |= ((pte->pte & 0x0000ffffffffffff)>>12);
    paddr <<= 12;
    paddr |= address&4095;
    //printk("paddr 0x%016llx\n", paddr);
    return (void *)paddr;
}
ssize_t phy_write(struct file *file, const char *buf,
               size_t len, loff_t *data) {
    uint64_t fun;
    char *bbuf;
    void *ptr;

    if (len < sizeof(fun))
        return -EINVAL;

    if (copy_from_user(&fun, buf, sizeof(fun)))
        return -EFAULT;
    //printk("phyaddr.ko: wrote address at %p\n", (uint64_t*)fun);
    bbuf = (char*)buf;
    //void *ptr = virt_to_phys((uint64_t*)fun);
    ptr = resolve_addr((uint64_t)fun);
    //printk("phyaddr.ko: phys  address at %p\n", ptr);
    copy_to_user(bbuf, &ptr, sizeof(void*));
    /*
    ptr = fun;
    */
    return len;
}

static const struct file_operations proc_file_fops = {
 .write = phy_write,
};

// Create a file /proc/jump, with writes handled by jump_write.
int init_phyaddr(void) {
    struct proc_dir_entry *ent = proc_create("phyaddr", 0666, NULL, &proc_file_fops);
    if (ent == NULL)
        return -ENOMEM;
    else {
        printk("phyaddr.ko: Loaded incredibly insecure kernel module\n");
        return 0;
    }
}

void exit_phyaddr(void) {
    remove_proc_entry("phyaddr", NULL);
}

module_init(init_phyaddr);
module_exit(exit_phyaddr);

MODULE_AUTHOR("Yeongjin Jang");
MODULE_DESCRIPTION("phyaddr");
MODULE_LICENSE("GPL");
