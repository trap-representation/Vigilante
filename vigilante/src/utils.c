#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <string.h>

#include "utils.h"
#include "vconfig.h"

#define ERROR_PREFIX "vigilante (error): "
#define INFO_PREFIX "vigilante (info): "
#define WARN_PREFIX "vigilante (warn): "

#ifdef ENDIAN_LITTLE
#elif defined(ENDIAN_BIG)
#else
_Static_assert(0, "define the endianness of your implementation in vconfig.h");
#endif

void werr(char *err, FILE *f, pid_t tracee) {
  fprintf(f, ERROR_PREFIX "(%llu): %s", (unsigned long long int) tracee, err);
}

void winfo(char *info, FILE *f, pid_t tracee) {
  fprintf(f, INFO_PREFIX "(%llu): %s", (unsigned long long int) tracee, info);
}

void wwarn(char *warn, FILE *f, pid_t tracee) {
  fprintf(f, WARN_PREFIX "(%llu): %s", (unsigned long long int) tracee, warn);
}

enum error wait_syscall(pid_t tracee) {
  while (1) {
    if (ptrace(PTRACE_SYSCALL, tracee, NULL, NULL) == -1) {
      fprintf(stderr, "ptrace(PTRACE_SYSCALL, tracee, NULL, NULL) failed\n");
      return ERR_PTRACE_SYSCALL;
    }

    int wstatus;
    if (waitpid(tracee, &wstatus, 0) == -1) {
      fprintf(stderr, "waitpid(tracee, &wstatus, 0) failed\n");
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

enum error get_pid(char *pid_s, pid_t *tracee) {
  *tracee = 0;

  for (size_t pc = 0; pid_s[pc] != '\0'; pc++) {
    if (pid_s[pc] >= '0' && pid_s[pc] <= '9') {
      *tracee *= 10;
      *tracee += pid_s[pc] - '0';
    }
    else {
      werr("invalid PID\n", stderr, 0);
      return ERR_INVALID_PID;
    }
  }

  return ERR_SUCCESS;
}

enum error perform_trace(unsigned long long int sc, struct user_regs_struct user_regs, struct trace_def *td, size_t tdn, pid_t tracee) {
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
    fprintf(stderr, INFO_PREFIX "(%llu): syscall: %llu\n", (unsigned long long int) tracee, sc);
    return ERR_SUCCESS;
  }

  for (size_t tdi = 0; tdi < tdn; tdi++) {
    if (sc == td[tdi].syscall || td[tdi].syscall == SC_ALL) {
      fprintf(stderr, INFO_PREFIX "(%llu): syscall: %llu\n", (unsigned long long int) tracee, sc);

      for (enum reg ri = 0; ri < REG_N; ri++) {
	if (td[tdi].trace_regs[ri] == TRACE) {
	  fprintf(stderr, INFO_PREFIX "(%llu):  %s: %llu\n", (unsigned long long int) tracee, rss[ri], rvs[ri]);

	  unsigned long long int r = rvs[ri];
	  _Bool exhausted = 0;

	  if (td[tdi].deref[ri][0] == D_END) {
	    exhausted = 1;
	  }

	  for (size_t dl = 0; !exhausted && dl < DEREF_LEVEL; dl++) {
	    if (td[tdi].deref[ri][dl] == D_W) {
	      r = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

	      if (errno) {
		winfo("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
	      }
	    }
	    else if(td[tdi].deref[ri][dl] == D_DW) {
	      long tr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

	      if (errno) {
		wwarn("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		break;
	      }

	      long ttr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE), NULL);

	      if (errno) {
		wwarn("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
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
		wwarn("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		break;
	      }

	      long ttr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE), NULL);

	      if (errno) {
		wwarn("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		break;
	      }

#ifdef ENDIAN_LITTLE
	      memcpy(&((char *) &tr)[WORD_SIZE], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
	      memcpy(&((char *) &tr)[WORD_SIZE * 2], &ttr, WORD_SIZE);

#endif

	      ttr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE * 2), NULL);

	      if (errno) {
		wwarn("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		break;
	      }

#ifdef ENDIAN_LITTLE
	      memcpy(&((char *) &tr)[WORD_SIZE * 2], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
	      memcpy(&((char *) &tr)[WORD_SIZE], &ttr, WORD_SIZE);

#endif

	      tr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE * 3), NULL);

	      if (errno) {
		wwarn("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
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
	      winfo("   string: ", stderr, tracee);

	      unsigned long long int maddr = r + rvs[td[tdi].deref[ri][dl] - (_DNOUSE_STRINGS + 1)];

	      while (r < maddr) {
		errno = 0;

		long s = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

		if (errno) {
		  wwarn("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
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
	      winfo("   string: ", stderr, tracee);

	      while (1) {
		errno = 0;

		long s = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

		if (errno) {
		  wwarn("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
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
	      fprintf(stderr, INFO_PREFIX "(%llu):    deref: %llu\n", (unsigned long long int) tracee, r);

	      exhausted = 1;
	    }
	    else {
	      werr("illegal derefence\n", stderr, tracee);

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

enum error read_tdf(char *file, struct trace_def **td, size_t *tdn, pid_t tracee) {
  *td = NULL;
  *tdn = 0;

  if (file == NULL) {
    return ERR_SUCCESS;
  }

  FILE *tdf = fopen(file, "rb");

  if (tdf == NULL) {
    werr("fopen(file, \"rb\") failed\n", stderr, tracee);
    return ERR_OPEN_TDF;
  }

  if (fread(tdn, sizeof(*tdn), 1, tdf) < 1) {
    if (!ferror(tdf)) {
      werr("invalid TDF file format\n", stderr, tracee);
      fclose(tdf);
      return ERR_INVALID_FILEFORMAT;
    }
    else {
      werr("failed to read from TDF\n", stderr, tracee);
      fclose(tdf);
      return ERR_FAILED_TO_READ_TDF;
    }
  }

  if ((*td = malloc(sizeof(**td) * *tdn)) == NULL) {
    werr("malloc(sizeof(**td) * *tdn) failed\n", stderr, tracee);
    fclose(tdf);
    return ERR_MALLOC;
  }

  if (fread(*td, sizeof(**td), *tdn, tdf) < *tdn) {
    if (!ferror(tdf)) {
      werr("invalid TDF file format\n", stderr, tracee);
      free(*td);
      fclose(tdf);
      return ERR_INVALID_FILEFORMAT;
    }
    else {
      werr("failed to read from TDF\n", stderr, tracee);
      free(*td);
      fclose(tdf);
      return ERR_FAILED_TO_READ_TDF;
    }
  }

  fclose(tdf);

  return ERR_SUCCESS;
}
