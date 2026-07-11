#pragma once

#include "basic_defs.h"

struct config;

int  config_load(const char *fileName, struct config **conf);
int  config_write(struct config *conf, const char *filename);
int  config_save(struct config *conf);
void config_free(struct config *conf);
struct config* config_create(void);

char* config_getstring(struct config *config, const char *def,
                       const char *fmt, ...) PRINTF_GCC_DECL(3, 4);
int64 config_getint64(struct config *config, int64 def,
                      const char *fmt, ...) PRINTF_GCC_DECL(3, 4);
bool  config_getbool(struct config *config, bool def,
                     const char *fmt, ...) PRINTF_GCC_DECL(3, 4);

void config_setstring(struct config *config, const char *s,
                      const char *fmt, ...) PRINTF_GCC_DECL(3, 4);
void config_setbool(struct config *config, bool b,
                    const char *fmt, ...) PRINTF_GCC_DECL(3, 4);
void config_setint64(struct config *config, int64 val,
                     const char *fmt, ...) PRINTF_GCC_DECL(3, 4);
bool config_isset(struct config *config,
                  const char *fmt, ...) PRINTF_GCC_DECL(2, 3);

