#ifndef UTILS_H
#define UTILS_H

#include "errors.h"
#include "cfg.h"

enum error wait_syscall(pid_t tracee);
void werr(char *err, FILE *f, pid_t tracee);
void winfo(char *info, FILE *f, pid_t tracee);
void warn(char *warn, FILE *f, pid_t tracee);
enum error perform_trace(unsigned long long int sc, struct user_regs_struct user_regs, struct trace_def *td, size_t tdn, pid_t tracee);
enum error get_pid(char *pid_s, pid_t *tracee);
enum error read_tdf(char *file, struct trace_def **td, size_t *tdn, pid_t tracee);

#endif
