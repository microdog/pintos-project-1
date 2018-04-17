#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>
#include <user/syscall.h>
#include "threads/thread.h"
#include "threads/synch.h"

enum child_status
  {
    CHILD_NOT_LOADED,
    CHILD_LOADED,
    CHILD_LOAD_FAILED
  };

struct child_process
  {
    pid_t pid;
    int status;
    enum child_status load_status;
    bool exited;
    bool waiting;
    struct semaphore load_sema;
    struct semaphore wait_sema;
    struct list_elem elem;
  };

struct child_process * attach_child_process (pid_t pid);
struct child_process * get_child_process (pid_t pid);
void detach_child_process (struct child_process *cp);

struct process_file
  {
    struct file *file;
    int fd;
    struct list_elem elem;
  };

int process_attach_file (struct file *f);
struct file * process_get_file (int fd);
void process_detach_file (int fd);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
