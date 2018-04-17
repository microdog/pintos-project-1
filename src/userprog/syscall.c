#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
void check_user_vaddr (const void *vaddr, bool writable);
void * user_to_kernel_addr (const void *uaddr);
void get_syscall_args (struct intr_frame *f, int *argv, int n);
void check_user_string (const char *str);
void check_user_buffer (const void *buffer, const unsigned size,
                        bool writable);

void
syscall_init (void) 
{
  lock_init (&fs_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int argv[4];
  check_user_vaddr (f->esp, false);
  int *ptr = (int *) user_to_kernel_addr (f->esp);
  switch (*ptr)
    {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      get_syscall_args (f, argv, 1);
      exit(argv[0]);
      break;
    case SYS_EXEC:
      get_syscall_args (f, argv, 1);
      check_user_string ((const char *) argv[0]);
      f->eax = exec ((const char *) user_to_kernel_addr ((const void *) argv[0]));
      break;
    case SYS_WAIT:
      get_syscall_args (f, argv, 1);
      f->eax = wait ((pid_t) argv[0]);
      break;
    case SYS_CREATE:
      get_syscall_args (f, argv, 2);
      check_user_string ((const char *) argv[0]);
      f->eax = create ((const char *) argv[0], (unsigned) argv[1]);
      break;
    case SYS_REMOVE:
      get_syscall_args (f, argv, 1);
      check_user_string ((const char *) argv[0]);
      f->eax = remove ((const char *) argv[0]);
      break;
    case SYS_OPEN:
      get_syscall_args (f, argv, 1);
      check_user_string ((const char *) argv[0]);
      f->eax = open ((const char *) argv[0]);
      break;
    case SYS_FILESIZE:
      get_syscall_args (f, argv, 1);
      f->eax = filesize ((int) argv[0]);
      break;
    case SYS_READ:
      get_syscall_args (f, argv, 3);
      check_user_buffer ((const void *) argv[1], (unsigned) argv[2], true);
      f->eax = read ((int) argv[0], user_to_kernel_addr ((const void *) argv[1]),
                     (unsigned) argv[2]);
      break;
    case SYS_WRITE:
      get_syscall_args (f, argv, 3);
      check_user_buffer ((void *) argv[1], (unsigned) argv[2], false);
      f->eax = write ((int) argv[0], user_to_kernel_addr ((const void *) argv[1]),
                      (unsigned) argv[2]);
      break;
    case SYS_SEEK:
      get_syscall_args (f, argv, 2);
      seek ((int) argv[0], (unsigned) argv[1]);
      break;
    case SYS_TELL:
      get_syscall_args (f, argv, 1);
      f->eax = tell ((int) argv[0]);
      break;
    case SYS_CLOSE:
      get_syscall_args (f, argv, 1);
      close ((int) argv[0]);
      break;
    }
}

void halt (void)
{
  shutdown_power_off ();
}

void exit (int status)
{
  struct thread *cur = thread_current ();
  if (thread_alive (cur->parent) && cur->cp)
    cur->cp->status = status;
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

pid_t exec (const char *file)
{
  pid_t pid = process_execute (file);
  struct child_process *cp = get_child_process (pid);
  if (!cp)
    return -1;
  if (cp->load_status == CHILD_NOT_LOADED)
    sema_down (&cp->load_sema);
  if (cp->load_status == CHILD_LOAD_FAILED)
    {
      detach_child_process (cp);
      return -1;
    }
  return pid;
}

int wait (pid_t pid)
{
  return process_wait (pid);
}

bool create (const char *file, unsigned initial_size)
{
  bool success;
  lock_acquire (&fs_lock);
  success = filesys_create (file, initial_size);
  lock_release (&fs_lock);
  return success;
}

bool remove (const char *file)
{
  bool success;
  lock_acquire (&fs_lock);
  success = filesys_remove (file);
  lock_release (&fs_lock);
  return success;
}

int open (const char *file)
{
  lock_acquire (&fs_lock);
  struct file *f = filesys_open (file);
  if (!f)
    {
      lock_release (&fs_lock);
      return -1;
    }
  int fd = process_attach_file (f);
  lock_release (&fs_lock);
  return fd;
}

int filesize (int fd)
{
  lock_acquire (&fs_lock);
  struct file *f = process_get_file (fd);
  if (!f)
    {
      lock_release (&fs_lock);
      return -1;
    }
  int size = file_length (f);
  lock_release (&fs_lock);
  return size;
}

int read (int fd, void *buffer, unsigned length)
{
  if (fd == STDIN_FILENO)
    {
      unsigned i;
      uint8_t *buf = (uint8_t *) buffer;
      for (i = 0; i < length; i++)
        {
          buf[i] = input_getc();
        }
      return length;
    }
  lock_acquire(&fs_lock);
  struct file *f = process_get_file (fd);
  if (!f)
    {
      lock_release (&fs_lock);
      return -1;
    }
  int bytes = file_read (f, buffer, length);
  lock_release (&fs_lock);
  return bytes;
}

int write (int fd, const void *buffer, unsigned length)
{
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, length);
      return length;
    }
  lock_acquire (&fs_lock);
  struct file *f = process_get_file (fd);
  if (!f)
    {
      lock_release (&fs_lock);
      return -1;
    }
  int bytes = file_write (f, buffer, length);
  lock_release (&fs_lock);
  return bytes;

}

void seek (int fd, unsigned position)
{
  lock_acquire (&fs_lock);
  struct file *f = process_get_file (fd);
  if (!f)
    {
      lock_release (&fs_lock);
      return;
    }
  file_seek (f, position);
  lock_release (&fs_lock);
}

unsigned tell (int fd)
{
  lock_acquire (&fs_lock);
  struct file *f = process_get_file (fd);
  if (!f)
    {
      lock_release (&fs_lock);
      return -1;
    }
  off_t offset = file_tell (f);
  lock_release (&fs_lock);
  return offset;
}

void close (int fd)
{
  lock_acquire (&fs_lock);
  process_detach_file (fd);
  lock_release (&fs_lock);
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Check if a user vaddr is valid. */
void check_user_vaddr (const void *vaddr, bool writable)
{
  int b;

  if (!is_user_vaddr (vaddr))
    exit (-1);

  if (!writable && -1 == get_user (vaddr))
    exit (-1);
  
  if (writable &&
      (-1 == (b = get_user (vaddr)) || !put_user ((uint8_t *) vaddr, (uint8_t) b)))
    exit (-1);
}

void * user_to_kernel_addr (const void *uaddr)
{
  void *ptr = pagedir_get_page (thread_current ()->pagedir, uaddr);
  if (!ptr)
    exit (-1);
  return ptr;
}

void get_syscall_args (struct intr_frame *f, int *argv, int n)
{
  int i;
  int *ptr;
  for (i = 0; i < n; i++)
    {
      ptr = (int *) f->esp + i + 1;
      check_user_vaddr ((const void *) ptr, false);
      argv[i] = *ptr;
    }
}

void check_user_string (const char *str)
{
  char *ptr = (char *) str;
  /* Go through the string. */
  check_user_vaddr ((void *) ptr, false);
  while (*(char *) user_to_kernel_addr ((void *) ptr) != '\0')
    check_user_vaddr ((void *) ++ptr, false);
}

void check_user_buffer (const void *buffer, const unsigned size,
                        bool writable)
{
  unsigned i;
  void *ptr = (void *) buffer;
  for (i = 0; i < size; ++i)
    check_user_vaddr (ptr++, writable);
}
