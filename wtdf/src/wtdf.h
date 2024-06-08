#ifndef WTDF_H
#define WTDF_H

#include "../../vigilante/src/cfg.h"
#include "errors.h"

void init_td(struct trace_def *tda, size_t n);
void trace_syscall(unsigned long long int sc, struct trace_def *td);
int write_td(struct trace_def *td, size_t n, char *file);
void trace_regs(enum reg r, enum state e, struct trace_def *td);
void trace_deref(enum dereference *d, size_t n, enum reg r, enum state e, struct trace_def *td);
enum error verify(struct trace_def *tda, size_t n);

#endif
