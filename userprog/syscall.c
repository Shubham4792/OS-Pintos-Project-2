#include "userprog/syscall.h"
#include <stdio.h>
#include <stdio.h>
#include "devices/input.h"
#include <console.h>
#include "userprog/process.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "string.h"

static void syscall_handler(struct intr_frame *);
static uint32_t *esp;
static struct semaphore sema;

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
   // sema_init(&sema, 1);
}

static void
syscall_handler(struct intr_frame *f) {
    esp = f->esp;
    uint32_t *x = f->esp;
    if (x == NULL) {
        exit(-1);
    }
    if (!is_user_vaddr(x) || !is_user_vaddr(x + 1) || !is_user_vaddr(x + 2) || !is_user_vaddr(x + 3)) {
        exit(-1);
    }
    if (pagedir_get_page(active_pd(), x) == NULL || pagedir_get_page(active_pd(), x + 1) == NULL || pagedir_get_page(active_pd(), x + 2) == NULL || pagedir_get_page(active_pd(), x + 3) == NULL) {
        exit(-1);
    }
    int sys = *esp;
    if (sys == SYS_HALT) {
        shutdown_power_off();
    } else if (sys == SYS_EXIT) {
        exit(*(esp + 1));
    } else if (sys == SYS_EXEC) {
        f->eax = exec(*(esp + 1));
    } else if (sys == SYS_WAIT) {
        f->eax = wait(*(esp + 1));
    } else if (sys == SYS_CREATE) {
        f->eax = create(*(esp + 1), *(esp + 2));
    } else if (sys == SYS_REMOVE) {
        f->eax = remove(*(esp + 1));
    } else if (sys == SYS_OPEN) {
        f->eax = open(*(esp + 1));
    } else if (sys == SYS_FILESIZE) {
        f->eax = filesize(*(esp + 1));
    } else if (sys == SYS_READ) {
        f->eax = read(*(esp + 1), *(esp + 2), *(esp + 3));
    } else if (sys == SYS_WRITE) {
        f->eax = write(*(esp + 1), *(esp + 2), *(esp + 3));
    } else if (sys == SYS_SEEK) {
        seek(*(esp + 1), *(esp + 2));
    } else if (sys == SYS_TELL) {
        tell(*(esp + 1));
    } else if (sys == SYS_CLOSE) {
        close(*(esp + 1));
    } else {
        thread_exit();
    }
}

bool remove(const char *file) {
    if (!is_user_vaddr(file) || pagedir_get_page(active_pd(), file) == NULL) {
        exit(-1);
    }
    return filesys_remove(file);
}

void seek(int fd, unsigned position) {
    file_seek(find_file(fd), position);
}

unsigned tell(int fd) {
    return file_tell(find_file(fd));
}

tid_t exec(const char* cmd_line) {
    if (!is_user_vaddr(cmd_line) || pagedir_get_page(active_pd(), cmd_line) == NULL) {
        exit(-1);
    }
    tid_t t = process_execute(cmd_line);
    sema_down(&find_thread_from_tid(t)->exec_sema);
    if (find_thread_from_tid(t)->load_failed == -1) {
        return -1;
    }
    return t;
}

/*If parent has called wait, finish own work, unblock parent 
 * blocked on this thread's semaphore, then thread_exit*/
void exit(int status) {
    struct thread *parent_thread = find_thread_from_tid(thread_current()->parentid);
    if (parent_thread != NULL) {
        thread_current()->status_val = status;
        if (thread_current()->read_only_file != NULL) {
            file_allow_write(thread_current()->read_only_file);
        }
         printf("%s: exit(%d)\n", thread_current()->name, status);
        struct child_identifier *cid = verify_valid_child_tid(parent_thread,thread_current()->tid);
        cid->status_val = status;
        cid->exit_done = true;
        sema_up(&cid->try_sema);
        sema_up(&thread_current()->wait_sema);
    }
    thread_exit();
}

/*Loop over list of child ids stored in parent struct thread. If tid matches, return true*/
struct child_identifier * verify_valid_child_tid(struct thread *t, tid_t child_tid) {
    struct list_elem *e;
    for (e = list_begin(&t->child_id_list); e != list_end(&t->child_id_list); e = list_next(e)) {
        struct child_identifier *c = list_entry(e, struct child_identifier, child_elem);
        tid_t tmp = c->tid;
        if (child_tid == tmp) {
            return c;
        }
    }
    return NULL;
}

/*Wait on child thread's semaphore which it will sema_up upon exiting. Avoid waiting if
 * waiting done already*/
int wait(tid_t child_tid) {
    struct child_identifier *cid = verify_valid_child_tid(thread_current(),child_tid);
    if (cid != NULL) {
        struct thread *t = find_thread_from_tid(child_tid);
        if (t == NULL) {
           while (!cid->exit_done) {
               if(cid->tid == -1){
                   exit(-1);
               }
               sema_down(&cid->try_sema);
            }
            return cid->status_val;
        }
        if (t->wait_done_already) {
            return -1;
        }
        t->wait_done_already = true;
        sema_down(&t->wait_sema);
        return t->status_val;
    } else {
        exit(-1);
    }
}

/* Find file with matching fd*/
int write(int fd, const void *buffer, unsigned size) {
    if (!is_user_vaddr(buffer) || pagedir_get_page(active_pd(), buffer) == NULL) {
        exit(-1);
    }
    struct file *open_file = find_file(fd);
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    } else if (open_file != NULL && buffer != NULL) {
        return file_write(open_file, buffer, size);
    } else {
        return 0;
    }
}

/*Loop over file descriptor list in current thread.
 *If fd matches file descriptor unique number, 
 *return reference to file, else return NULL.
 */
struct file* find_file(int fd) {
    struct list_elem *e;
    for (e = list_begin(&thread_current()->file_desc_list); e != list_end(&thread_current()->file_desc_list); e = list_next(e)) {
        struct file_desc *file_desc = list_entry(e, struct file_desc, file_desc_elem);
        if (file_desc->file_num == fd) {
            return file_desc->file;
        }
    }
    return NULL;
}

bool is_file_open(const char* file_name) {
    struct list_elem *e;
    for (e = list_begin(&thread_current()->file_desc_list); e != list_end(&thread_current()->file_desc_list); e = list_next(e)) {
        struct file_desc *file_desc = list_entry(e, struct file_desc, file_desc_elem);
        if (file_desc->file == file_name) {
            return file_desc->file;
        }
    }
    return NULL;
}

/*Loop over file descriptor list in current thread.
 *If fd matches file descriptor unique number, else return NULL.
 */
struct file_desc* find_file_desc(int fd) {
    struct list_elem *e;
    for (e = list_begin(&thread_current()->file_desc_list); e != list_end(&thread_current()->file_desc_list); e = list_next(e)) {
        struct file_desc *file_desc = list_entry(e, struct file_desc, file_desc_elem);
        if (file_desc->file_num == fd) {
            return file_desc;
        }
    }
    return NULL;
}

/*Check if thread has an open file with fd mentioned.
 *If its keyboard read, count characters while putting into buffer,
 *else return count returned by file_read.
 */
int read(int fd, void *buffer, unsigned size) {
    if (!is_user_vaddr(buffer) || pagedir_get_page(active_pd(), buffer) == NULL) {
        exit(-1);
    }
    int length = 0;
    if (size == 0) {
        return 0;
    }
    struct file *open_file = find_file(fd);

    if (fd == 0) {
        char c = 'a';
        while (c != 0) {
            c = input_getc();
            buffer = c;
            buffer++;
            length++;
        }
        return length;
    } else if (open_file != NULL) {
        return file_read(open_file, buffer, size);
    } else {
        return -1;
    }
}

/*Simply create a new file using filesys_create*/
bool create(const char *file, unsigned initial_size) {
    if (!is_user_vaddr(file) || pagedir_get_page(active_pd(), file) == NULL) {
        exit(-1);
    }
    if (initial_size < 0 || strlen(file) == 0 || file == NULL) {
        exit(-1);
    }
    return filesys_create(file, initial_size);
}

/*Opens file using filesys_open, allocates memory for file_desc of the new file,
 *pushes the struct file_desc list_elem to the thread list of file descriptors
 *pushes a unique number to the file_num field of struct file_desc and returns it.
 */
int open(const char *file) {
    if (!is_user_vaddr(file) || pagedir_get_page(active_pd(), file) == NULL) {
        exit(-1);
    }
    if (strlen(file) <= 0 || file == NULL) {
        return -1;
    }
    struct file *f = filesys_open(file);
    if (f == NULL) {
        return -1;
    }
    struct file_desc *fd = malloc(sizeof (*fd));
    if (fd != NULL) {
        fd->file = f;
        fd->file_num = thread_current()->file_desc_count;
        list_push_back(&thread_current()->file_desc_list, &fd->file_desc_elem);
        thread_current()->file_desc_count++;
        return fd->file_num;
    } else {
        free(fd);
    }
    return -1;
}

/*Verify if thread has an open file with fd and returns the size of the open file*/
int filesize(int fd) {
    struct file *open_file = find_file(fd);
    if (open_file != NULL) {
        return file_length(open_file);
    }
    return -1;
}

/*Verify if thread has an open file with fd and 
 * remove it from the list of file descriptors of current thread*/
void close(int fd_num) {
    if (fd_num < 2) {
        exit(-1);
    }
    struct file_desc *open_file_desc = find_file_desc(fd_num);
    if (open_file_desc != NULL) {
        struct file *open_file = open_file_desc->file;
        file_close(open_file);
        list_remove(&open_file_desc->file_desc_elem);
    }
}

