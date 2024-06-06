#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>

#include "tracer.h"

static enum error wait_syscall(pid_t tracee) {
  while (1) {
    if (ptrace(PTRACE_SYSCALL, tracee, NULL, NULL) == -1) {
      diag(stderr, tracee, ERROR_PREFIX, "ptrace(PTRACE_SYSCALL, tracee, NULL, NULL) failed\n");
      return ERR_PTRACE_SYSCALL;
    }

    int wstatus;
    if (waitpid(tracee, &wstatus, 0) == -1) {
      diag(stderr, tracee, ERROR_PREFIX, "waitpid(tracee, &wstatus, 0) failed\n");
      return ERR_WAITPID;
    }

    if (WIFEXITED(wstatus)) {
      return ERR_TERMINATED;
    }
    else if(WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) & 0x80) {
      return ERR_STOPPED;
    }
  }
}

static enum error _trace(unsigned long long int sc, struct user_regs_struct user_regs, struct trace_def *td, size_t tdn, pid_t tracee) {
  /* Do not change the order of the stored values in rvs and rss */

  unsigned long long int rvs[] = {
    user_regs.r15,
    user_regs.r14,
    user_regs.r13,
    user_regs.r12,
    user_regs.rbp,
    user_regs.rbx,
    user_regs.r11,
    user_regs.r10,
    user_regs.r9,
    user_regs.r8,
    user_regs.rax,
    user_regs.rcx,
    user_regs.rdx,
    user_regs.rsi,
    user_regs.rdi,
    user_regs.rip,
    user_regs.cs,
    user_regs.eflags,
    user_regs.rsp,
    user_regs.ss,
    user_regs.fs_base,
    user_regs.gs_base,
    user_regs.ds,
    user_regs.es,
    user_regs.fs,
    user_regs.gs
  };

  char *rss[] = {
    "R15",
    "R14",
    "R13",
    "R12",
    "RBP",
    "RBX",
    "R11",
    "R10",
    "R9",
    "R8",
    "RAX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RIP",
    "CS",
    "EFLAGS",
    "RSP",
    "SS",
    "FS_BASE",
    "GS_BASE",
    "DS",
    "ES",
    "FX",
    "GS"
  };

  if (td == NULL) {
    diag(stderr, tracee, INFORMATIVE_PREFIX, "syscall: %llu\n", sc);
    return ERR_SUCCESS;
  }

  for (size_t tdi = 0; tdi < tdn; tdi++) {
    if (sc == td[tdi].syscall || td[tdi].syscall == SC_ALL) {
      diag(stderr, tracee, INFORMATIVE_PREFIX, "syscall: %llu\n", sc);

      for (enum reg ri = 0; ri < REG_N; ri++) {
	if (td[tdi].trace_regs[ri] == TRACE) {
	  diag(stderr, tracee, INFORMATIVE_PREFIX, "  %s: %llu\n", rss[ri], rvs[ri]);

	  unsigned long long int r = rvs[ri];
	  _Bool exhausted = 0;

	  if (td[tdi].deref[ri][0] == D_END) {
	    exhausted = 1;
	  }

	  for (size_t dl = 0; !exhausted && dl < DEREF_LEVEL; dl++) {
	    if (td[tdi].deref[ri][dl] == D_W) {
	      r = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

	      if (errno) {
		diag(stderr, tracee, INFORMATIVE_PREFIX, "ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n");
	      }
	    }
	    else if(td[tdi].deref[ri][dl] == D_DW) {
	      long tr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

	      if (errno) {
		diag(stderr, tracee, WARNING_PREFIX, "ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n");
		break;
	      }

	      long ttr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE), NULL);

	      if (errno) {
		diag(stderr, tracee, WARNING_PREFIX, "ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n");
		break;
	      }

#ifdef ENDIAN_LITTLE
	      memcpy(&((char *) &tr)[WORD_SIZE], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
	      memcpy(&tr, &ttr, WORD_SIZE);

#endif

	      r = tr;
	    }
	    else if (td[tdi].deref[ri][dl] == D_QW) {
	      long tr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

	      if (errno) {
		diag(stderr, tracee, WARNING_PREFIX, "ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n");
		break;
	      }

	      long ttr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE), NULL);

	      if (errno) {
		diag(stderr, tracee, WARNING_PREFIX, "ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n");
		break;
	      }

#ifdef ENDIAN_LITTLE
	      memcpy(&((char *) &tr)[WORD_SIZE], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
	      memcpy(&((char *) &tr)[WORD_SIZE * 2], &ttr, WORD_SIZE);

#endif

	      ttr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE * 2), NULL);

	      if (errno) {
		diag(stderr, tracee, WARNING_PREFIX, "ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n");
		break;
	      }

#ifdef ENDIAN_LITTLE
	      memcpy(&((char *) &tr)[WORD_SIZE * 2], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
	      memcpy(&((char *) &tr)[WORD_SIZE], &ttr, WORD_SIZE);

#endif

	      tr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE * 3), NULL);

	      if (errno) {
		diag(stderr, tracee, WARNING_PREFIX, "ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n");
		break;
	      }

#ifdef ENDIAN_LITTLE
	      memcpy(&((char *) &tr)[WORD_SIZE * 3], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
	      memcpy(&tr, &ttr, WORD_SIZE);

#endif

	      r = tr;
	    }
	    else if (td[tdi].deref[ri][dl] > _DNOUSE_STRINGS && td[tdi].deref[ri][dl] < _DNOUSE_STRINGE) {
	      diag(stderr, tracee, INFORMATIVE_PREFIX, "    string: ");

	      unsigned long long int maddr = r + rvs[td[tdi].deref[ri][dl] - (_DNOUSE_STRINGS + 1)];

	      while (r < maddr) {
		errno = 0;

		long s = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

		if (errno) {
		  diag(stderr, tracee, WARNING_PREFIX, "ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n");
		  break;
		}

#ifdef ENDIAN_LITTLE
		fputc(*(char *) &s, stderr);

#elif defined(ENDIAN_BIG)
		fputc(((char *) &s)[WORD_SIZE - 1], stderr);

#endif

		r++;
	      }

	      fputc('\n', stderr);
	    }
	    else if (td[tdi].deref[ri][dl] == D_NSTRING) {
	      diag(stderr, tracee, INFORMATIVE_PREFIX, "    string: ");

	      while (1) {
		errno = 0;

		long s = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

		if (errno) {
		  diag(stderr, tracee, WARNING_PREFIX, "ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n");
		  break;
		}

		if (*(char *) &s != '\0') {
		  fputc(*(char *) &s, stderr);
		}
		else {
		  break;
		}

		r++;
	      }

	      r++;

	      fputc('\n', stderr);
	    }
	    else if (td[tdi].deref[ri][dl] == D_END) {
	      diag(stderr, tracee, INFORMATIVE_PREFIX, "    deref: %llu\n", r);

	      exhausted = 1;
	    }
	    else {
	      diag(stderr, tracee, ERROR_PREFIX, "illegal derefence\n");

	      return ERR_ILLEGAL_DEREF;
	    }
	  }
	}
      }

      break;
    }
  }

  return ERR_SUCCESS;
}

enum error trace(pid_t tracee, char *tdf) {
  if (ptrace(PTRACE_ATTACH, tracee, NULL, NULL) == -1) {
    diag(stderr, tracee, ERROR_PREFIX, "ptrace(PTRACE_ATTACH, tracee, NULL, NULL) failed\n");
    return ERR_PTRACE_ATTACH;
  }

  if (waitpid(tracee, NULL, 0) == -1) {
    diag(stderr, tracee, ERROR_PREFIX, "waitpid(tracee, NULL, 0) failed\n");
    return ERR_WAITPID;
  }
  
  if (ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACECLONE) == -1) {
    diag(stderr, tracee, ERROR_PREFIX, "ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACECLONE) failed\n");
    return ERR_PTRACE_SETOPTIONS_TRACESYSGOOD;
  }

  if (ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACESYSGOOD) == -1) {
    diag(stderr, tracee, ERROR_PREFIX, "ptrace(PTRACE_SETOPTIONS, tracee, NULL, PTRACE_O_TRACESYSGOOD) failed\n");
    return ERR_PTRACE_SETOPTIONS_TRACESYSGOOD;
  }

  struct trace_def *td;
  size_t tdn;

  enum error r;

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
      diag(stderr, tracee, ERROR_PREFIX, "ptrace(PTRACE_GETREGS, tracee, NULL, &user_regs) failed\n");
      return ERR_PTRACE_GETREGS;
    }

    unsigned long long int sc = user_regs.orig_rax;

    r = _trace(sc, user_regs, td, tdn, tracee);
  }
  
  free(td);

  return r;
}
