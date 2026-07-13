#pragma once

#include "basic_defs.h"

// PATH_MAX
#ifdef linux
#include <linux/limits.h>
#elif defined(__APPLE__)
#include <sys/syslimits.h>
#else
#include <limits.h>
#endif


struct file_descriptor;


bool file_valid(const struct file_descriptor *fd);

int file_create(const char *filename);
int file_mkdir(const char *pathname);
int file_sync(const struct file_descriptor *desc);
int64 file_getsize(const struct file_descriptor *desc);
int file_truncate(const struct file_descriptor *desc, uint64 offset);
bool file_exists(const char *name);
int file_close(struct file_descriptor *desc);
int file_pread(const struct file_descriptor *desc,
               uint64 offset, void *buf, size_t len, size_t *num);
int file_pwrite(const struct file_descriptor *desc,
                uint64 offset, const void *buf, size_t len, size_t *num);
int file_open(const char *name,
              bool readOnly,
              bool unbuf,
              struct file_descriptor **desc);
void file_freedirlist(char **names);
int file_listdirectory(const char *directory,
                       char ***namesOut);
char *file_getcwd(void);
char *file_fullpath(const char *path);
char *file_getname(const char *path);

int file_getline(struct file_descriptor *desc, char **line);
int file_unlink(const char *filename);
int file_rmdir(const char *path);
int file_glob(const char *path, const char *pattern, char ***list);
int file_rotate(const char *filename, uint32 n);
int file_rename(const char *src, const char *dst);
int file_chmod(const char *filename, uint32 mode);

