/*
    Vigilante logs syscalls
    Copyright (C) 2024  Somdipto Chakraborty

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>

#include "utils.h"
#include "errors.h"
#include "cfg.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    werr("usage:\n\
  PID config (optional)\n", stderr, 0);
    return ERR_NOARGS;
  }

  pid_t tracee;

  enum error r;

  if ((r = get_pid(argv[1], &tracee)) != ERR_SUCCESS) {
    return r;
  }

  char *tdf = argv[2];

  if (ptrace(PTRACE_ATTACH, tracee, NULL, NULL) == -1) {
    werr("ptrace(PTRACE_ATTACH, tracee, NULL, NULL) failed\n", stderr, tracee);
    return ERR_PTRACE_ATTACH;
  }

  if (waitpid(tracee, NULL, 0) == -1) {
    fprintf(stderr, "waitpid(tracee, NULL, 0) failed\n");
    return ERR_WAITPID;
  }
  
  if (ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACECLONE) == -1) {
    werr("ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACECLONE) failed\n", stderr, tracee);
    return ERR_PTRACE_SETOPTIONS_TRACESYSGOOD;
  }

  if (ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACESYSGOOD) == -1) {
    werr("ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACESYSGOOD) failed\n", stderr, tracee);
    return ERR_PTRACE_SETOPTIONS_TRACESYSGOOD;
  }

  struct trace_def *td;
  size_t tdn;

  if ((r = read_tdf(tdf, &td, &tdn, tracee)) != ERR_SUCCESS) {
    return r;
  }

  while (1) {
    r = wait_syscall(tracee);

    if (r == ERR_WAITPID || r == ERR_TERMINATED) {
      return r;
    }

    r = wait_syscall(tracee);

    if (r == ERR_WAITPID || r == ERR_TERMINATED) {
      return r;
    }

    struct user_regs_struct user_regs;
    if (ptrace(PTRACE_GETREGS, tracee, NULL, &user_regs) == -1) {
      werr("ptrace(PTRACE_GETREGS, tracee, NULL, &user_regs) failed\n", stderr, tracee);
      return ERR_PTRACE_GETREGS;
    }

    unsigned long long int sc = user_regs.orig_rax;

    r = perform_trace(sc, user_regs, td, tdn, tracee);
  }
  
  free(td);

  return r;
}
