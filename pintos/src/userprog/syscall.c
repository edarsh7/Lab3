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

#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>

#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/umem.h"

static void syscall_handler(struct intr_frame *);

static void write_handler(struct intr_frame *);
static void create_handler(struct intr_frame *);
static void open_handler(struct intr_frame *);
static void exit_handler(struct intr_frame *);
static void read_handler(struct intr_frame *);


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int syscall;
  ASSERT( sizeof(syscall) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  umem_read(f->esp, &syscall, sizeof(syscall));

  // Store the stack pointer esp, which is needed in the page fault handler.
  // Do NOT remove this line
  thread_current()->current_esp = f->esp;

  switch (syscall) {
  case SYS_HALT: 
    shutdown_power_off();
    break;

  case SYS_EXIT: 
    exit_handler(f);
    break;
      
  case SYS_WRITE: 
    write_handler(f);
    break;

  case SYS_CREATE:
    create_handler(f);
    break;

  case SYS_OPEN:
    open_handler(f);
    break;

  case SYS_READ:
    read_handler(f);
    break;


  default:
    printf("[ERROR] system call %d is unimplemented!\n", syscall);
    thread_exit();
    break;
  }
}

/****************** System Call Implementations ********************/

void sys_exit(int status) 
{
  printf("%s: exit(%d)\n", thread_current()->name, status);

  thread_exit();
}

static void exit_handler(struct intr_frame *f) 
{
  int exitcode;
  umem_read(f->esp + 4, &exitcode, sizeof(exitcode));

  struct process_status *ps = thread_current()->p_stat;
  if(ps != NULL)
    ps->exit_code = 1;

  sys_exit(exitcode);
}

/*
 * BUFFER+0 and BUFFER+size should be valid user adresses
 */
static uint32_t sys_write(int fd, const void *buffer, unsigned size)
{
  umem_check((const uint8_t*) buffer);
  umem_check((const uint8_t*) buffer + size - 1);

  int ret = -1;

  if (fd == 1) { // write to stdout
    putbuf(buffer, size);
    ret = size;
  }

  return (uint32_t) ret;
}

static void write_handler(struct intr_frame *f)
{
    int fd;
    const void *buffer;
    unsigned size;

    umem_read(f->esp + 4, &fd, sizeof(fd));
    umem_read(f->esp + 8, &buffer, sizeof(buffer));
    umem_read(f->esp + 12, &size, sizeof(size));

    f->eax = sys_write(fd, buffer, size);
}

static int sys_create(char* fname, int isize)
{
  bool ret;
  ret = filesys_create(fname, isize, ret);
  return ret;
}

static void create_handler(struct intr_frame *f)
{
    const char * fname;
    int isize;
    umem_read(f->esp + 4, &fname, sizeof(fname));
    umem_read(f->esp + 8, &isize, sizeof(isize));
    bool x = sys_create(fname, isize);
    f->eax = x;
}

static int sys_open(const char* fname)
{
  umem_check((const uint8_t*) fname);
  struct file * opened = filesys_open(fname);

  if(!opened)
  {
    return -1;
  }

  struct file_entry * cur = palloc_get_page(0);
  cur->file = opened;
  if(list_empty(&thread_current()->files))
  {
    cur->id = 2;
  }
  else
  {
    cur->id = list_size(&thread_current()->files)+1;
  }
  list_push_back(&thread_current()->files, &cur->elem);
  return cur->id;
}


static void open_handler(struct intr_frame *f)
{
    const char * fname;
    umem_read(f->esp + 4, &fname, sizeof(fname));

    int x = sys_open(fname);
    f->eax =  x;
}

static int sys_read(int fd, const void *buffer, unsigned size)
{
  umem_check((const uint8_t*) buffer);
  umem_check((const uint8_t*) buffer + size - 1);

  int ret;

  if (fd == 1) { // write to stdout
    putbuf(buffer, size);
    ret = size;
  }
  else
  {
    struct file_entry * temp = NULL;
    struct list_elem * e;
    if(!list_empty(&thread_current()->files))
    {
        for(e = list_begin(&thread_current()->files);
            e != list_end(&thread_current()->files);
            e = list_next(e))
        {
          temp = list_entry(e, struct file_entry, entry);
          if(temp->id == fd)
          {
            ret = file_read(temp->file, buffer, size)
            break;
          }
        }
    }

  }

  return ret;
}


static void read_handler(struct intr_frame *f)
{
    int fd;
    const void *buf;
    unsigned size;

    umem_read(f->esp + 4, &fd, sizeof(fd));
    umem_read(f->esp + 8, &buf, sizeof(buf));
    umem_read(f->esp + 12, &size, sizeof(size));

    int x = sys_read(fd, buf, size);
    f->eax =  x;
}

