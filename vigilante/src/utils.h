#ifndef UTILS_H
#define UTILS_H

#include "errors.h"
#include "cfg.h"

#define ERROR_PREFIX "vigilante (error): "
#define INFORMATIVE_PREFIX "vigilante (info): "
#define WARNING_PREFIX "vigilante (warn): "

#define diag(f, tracee, pre, ...)					\
  fprintf(f, pre "(%lld): ", (long long int) tracee);			\
  fprintf(f, __VA_ARGS__);

enum error get_pid(char *pid_s, pid_t *tracee);
enum error read_tdf(char *file, struct trace_def **td, size_t *tdn, pid_t tracee);

#endif
