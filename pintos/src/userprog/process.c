/* 
 * This file is derived from source code for the Pintos
 * instructional operating system which is itself derived
 * from the Nachos instructional operating system. The 
 * Nachos copyright notice is reproduced in full below. 
 *
 * Copyright (C) 1992-1996 The Regents of the University of California.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose, without fee, and
 * without written agreement is hereby granted, provided that the
 * above copyright notice and the following two paragraphs appear
 * in all copies of this software.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
 * ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
 * AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
 * HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
 * BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * Modifications Copyright (C) 2017-2018 David C. Harrison.  
 * All rights reserved.
 */

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "devices/timer.h"

#include "threads/semaphore.h"

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip) (void), void **esp);

struct process_struct
{
    char * cmdline_cpy;
    struct semaphore sema;
}process_struct;


/*
 * Push the command and arguments found in CMDLINE onto the stack, world 
 * aligned with the stack pointer ESP. Should only be called after the ELF 
 * format binary has been loaded into the heap by load();
 */
static void
push_command(const char *cmdline UNUSED, void **esp)
{
    char *temp = palloc_get_page(0);
    strlcpy(temp, cmdline, PGSIZE);
    
    char *temp2 = palloc_get_page(0);
    strlcpy(temp2, cmdline, PGSIZE);
    

    char *save = NULL;
    char *tok = NULL;
    int argc = 0;

    for(tok = strtok_r(temp2, " ", &save); tok != NULL; tok = strtok_r(NULL, " ", &save))
    {
        argc++;
    }
    palloc_free_page(temp2);

    save = NULL;
    tok = NULL;
    char **arg_adr = palloc_get_page(0);
    int i = 0;

    //push args onto stack
    for(tok = strtok_r(temp, " ", &save); tok != NULL; tok = strtok_r(NULL, " ", &save))
    {
        *esp -= strlen(tok)+1;
        memcpy(*esp, tok, strlen(tok)+1);
        arg_adr[i++] = *esp;
    }
    palloc_free_page(temp);
    
    //align stack pointer
    *esp -= 4;
    *esp = (void*) ((unsigned int) (*esp) & 0xfffffffc);
    

    //null sentinel
    *esp -= 4;
    *((char**)*esp) = 0;

    //push addresses from end to beginning of array
    for(int i = argc-1; i>=0;i--)
    {
        *esp -= sizeof(char*);
        *((char**)*esp) = arg_adr[i];
    }

    //push address of argv[0]
    *esp -= 4;
    *((void**)*esp) = *esp+4;

    //push argc
    *esp -= 4;
    *((int*)*esp) = argc;
    
    //push fake RA
    *esp -= 4;
    *((void**)*esp) = 0;

    palloc_free_page(arg_adr);

    // Some of your CSE130 Lab 3 code will go here.
    //
    // You'll be doing address arithmetic here and that's one of only a handful 
    // of situations in which it is acceptable to have comments inside functions. 
    //
    // As you advance the stack pointer by adding fixed and variable offsets
    // to it, add a SINGLE LINE comment to each logical block, a comment that 
    // describes what you're doing, and why.
    //       
    // If nothing else, it'll remind you what you did when it doesn't work :)
}
    
/*  
 * Starts a new kernel thread running a user program loaded from CMDLINE. 
 * The new thread may be scheduled (and may even exit) before process_execute() 
 * returns.  Returns the new process's thread id, or TID_ERROR if the thread 
 * could not be created. 
 */ 
tid_t
process_execute(const char *cmdline)
{
    // Make a copy of CMDLINE to avoid a race condition between the caller and load() 
    struct process_struct p_strct;
    semaphore_init(&p_strct.sema, 0);
    p_strct.cmdline_cpy = palloc_get_page(0);
    
    if (p_strct.cmdline_cpy == NULL)
        return TID_ERROR;

    strlcpy(p_strct.cmdline_cpy, cmdline, PGSIZE);

    char *save = NULL;
    char *tok = NULL;
    tok = strtok_r(cmdline, " ", &save);

    struct process_status *ps;
    list_push_back(&thread_current()->children, &ps->child);


    // Create a Kernel Thread for the new process
    tid_t tid = thread_create(tok, PRI_DEFAULT, start_process, &p_strct);

    ps->pid = tid;
    ps->exit_code = 0;
    ps->waited = 0;
    semaphore_down(&p_strct.sema);


    if(tid != TID_ERROR)


    // CSE130 Lab 3 : The "parent" thread immediately returns after creating 
    // the child. To get ANY of the tests passing, you need to synchronise the 
    // activity of the parent and child threads.

    return tid;
}

/* 
 * A thread function to load a user process and start it running. 
 * CMDLINE is assumed to contain an executable file name with no arguments.
 * If arguments are passed in CMDLINE, the thread will exit imediately.
 */
static void
start_process(void *cmdline)
{
    printf("pr2\n");
    // Initialize interrupt frame and load executable. 
    struct intr_frame pif;
    memset(&pif, 0, sizeof pif);

    pif.gs = pif.fs = pif.es = pif.ds = pif.ss = SEL_UDSEG;
    pif.cs = SEL_UCSEG;
    pif.eflags = FLAG_IF | FLAG_MBS;

    struct process_struct * temp = cmdline;

    char *cmdline_copy = palloc_get_page(0);
    strlcpy(cmdline_copy, temp->cmdline_cpy, PGSIZE);

    char *save = NULL;
    char * tok = NULL;
    tok = strtok_r(cmdline_copy, " ", &save);


    bool success = load(cmdline_copy, &pif.eip, &pif.esp);

    palloc_free_page(cmdline_copy);
    if (success) {
        push_command(temp->cmdline_cpy, &pif.esp);
    }

    semaphore_up(&temp->sema);

    if (!success) {
        thread_exit();
    }


    

    // Start the user process by simulating a return from an
    // interrupt, implemented by intr_exit (in threads/intr-stubs.S).  
    // Because intr_exit takes all of its arguments on the stack in 
    // the form of a `struct intr_frame',  we just point the stack 
    // pointer (%esp) to our stack frame and jump to it.
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&pif) : "memory");
    NOT_REACHED();
}


/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in Lab 3.  
   For now, it does nothing. */
int
process_wait(tid_t child_tid UNUSED)
{
    struct list_elem *e;
    struct process_status *ps = NULL;
    for(e = list_begin(&thread_current()->children);
        e != list_end(&thread_current()->children);
        e = list_next(e))
    {
        ps = list_entry(e, struct process_status, child);
        if(ps->pid == child_tid)
            break;
    }
    if(e = list_end(&thread_current()->children) || ps->waited == 1)
        return -1;

        
    return ps->exit_code;
}

/* Free the current process's resources. */
void
process_exit(void)
{

    struct thread *cur = thread_current();
    uint32_t *pd;

    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate(void)
{
    struct thread *t = thread_current();

    /* Activate thread's page tables. */
    pagedir_activate(t->pagedir);

    /* Set thread's kernel stack for use in processing
       interrupts. */
    tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
    uint32_t read_bytes, uint32_t zero_bytes,
    bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
static bool
load(const char *file_name, void (**eip) (void), void **esp)
{
    struct thread *t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory, as well as SPTE. */
    t->pagedir = pagedir_create();

    if (t->pagedir == NULL)
        goto done;
    process_activate();

    /* Open executable file. */
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: '%s': open failed, no such file\n", file_name);
        goto done;
    }

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
        || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7)
        || ehdr.e_type != 2
        || ehdr.e_machine != 3
        || ehdr.e_version != 1
        || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
        || ehdr.e_phnum > 1024) {
        printf("load: '%s: error loading ELF executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment(&phdr, file)) {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint32_t file_page = phdr.p_offset & ~PGMASK;
                    uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint32_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
                           Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
                            - read_bytes);
                    } else {
                        /* Entirely zero.
                           Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void *) mem_page,
                        read_bytes, zero_bytes, writable))
                        goto done;
                } else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(esp))
        goto done;

    /* Start address. */
    *eip = (void (*) (void)) ehdr.e_entry;

    /* Deny writes to executables. */
    file_deny_write(file);
    //thread_current()->executing_file = file;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */

    // do not close file here, postpone until it terminates
    return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off) file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *) phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *) (phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

#ifndef VM
#define vm_frame_allocate(x, y) palloc_get_page(x)
#define vm_frame_free(x) palloc_free_page(x)
#endif

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
    uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifdef VM
        // Lazy load
        struct thread *curr = thread_current();
        ASSERT(pagedir_get_page(curr->pagedir, upage) == NULL); // no virtual page yet?

        if (!vm_supt_install_filesys(curr->supt, upage,
            file, ofs, page_read_bytes, page_zero_bytes, writable)) {
            return false;
        }
#else
        /* Get a page of memory. */
        uint8_t *kpage = vm_frame_allocate(PAL_USER, upage);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int) page_read_bytes) {
            vm_frame_free(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            vm_frame_free(kpage);
            return false;
        }
#endif

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
#ifdef VM
        ofs += PGSIZE;
#endif
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp)
{
    uint8_t *kpage;
    bool success = false;

    // upage address is the first segment of stack.
    kpage = vm_frame_allocate(PAL_USER | PAL_ZERO, PHYS_BASE - PGSIZE);
    if (kpage != NULL) {
        success = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
        if (success)
            *esp = PHYS_BASE;
        else
            vm_frame_free(kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    bool success = (pagedir_get_page(t->pagedir, upage) == NULL);
    success = success && pagedir_set_page(t->pagedir, upage, kpage, writable);
#ifdef VM
    success = success && vm_supt_install_frame(t->supt, upage, kpage);
    if (success) vm_frame_unpin(kpage);
#endif
    return success;
}
