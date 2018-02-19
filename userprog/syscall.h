#include<stdio.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void exit(int);
struct child_identifier * verify_valid_child_tid(tid_t);
int read(int, void *, unsigned);
bool create(const char *, unsigned);
int open(const char *);
int filesize(int);
int write(int, const void *, unsigned);
struct file* find_file(int);
int wait(int);
void close (int);
struct file_desc* find_file_desc(int);
bool remove (const char *file);
void seek (int fd, unsigned position);
unsigned tell (int fd);
#endif /* userprog/syscall.h */
