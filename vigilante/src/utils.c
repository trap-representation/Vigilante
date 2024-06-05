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

#ifdef ENDIAN_LITTLE
#elif defined(ENDIAN_BIG)
#else
_Static_assert(0, "define the endianness of your implementation in vconfig.h");
#endif

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

void werr(char *err, FILE *f, pid_t tracee) {
  fprintf(f, ERROR_PREFIX "(%llu): %s", (unsigned long long int) tracee, err);
}

void winfo(char *info, FILE *f, pid_t tracee) {
  fprintf(f, INFO_PREFIX "(%llu): %s", (unsigned long long int) tracee, info);
}

enum error get_pid(char *pid_s, pid_t *tracee) {
  *tracee = 0;

  for (size_t i = 0; pid_s[i] != '\0'; i++) {
    if (pid_s[i] >= '0' && pid_s[i] <= '9') {
      *tracee *= 10;
      *tracee += pid_s[i] - '0';
    }
    else {
      werr("invalid PID\n", stderr, 0);
      return ERR_INVALID_PID;
    }
  }

  return ERR_SUCCESS;
}

enum error perform_trace(unsigned long long int sc, struct user_regs_struct user_regs, struct trace_def *td, size_t tdn, pid_t tracee) {
  if (td == NULL) {
    fprintf(stderr, INFO_PREFIX "(%llu): syscall: %llu\n", (unsigned long long int) tracee, sc);
    return ERR_SUCCESS;
  }

  for (size_t i = 0; i < tdn; i++) {
    if (sc == td[i].syscall) {
      fprintf(stderr, INFO_PREFIX "(%llu): syscall: %llu\n", (unsigned long long int) tracee, sc);
      for (enum reg j = 0; j < REG_N; j++) {
	char *rs;
	unsigned long long int rv;

	if (td[i].trace_reg[j] == TRACE) {
	  switch (j) {
          case REG_R15:
	    rs = "R15";
            rv = user_regs.r15;
	    break;

          case REG_R14:
	    rs = "R14";
            rv = user_regs.r14;
	    break;

          case REG_R13:
	    rs = "R13";
            rv = user_regs.r13;
	    break;

          case REG_R12:
	    rs = "R12";
            rv = user_regs.r12;
	    break;

          case REG_RBP:
	    rs = "RBP";
            rv = user_regs.rbp;
	    break;

          case REG_RBX:
	    rs = "RBX";
            rv = user_regs.rbx;
	    break;

          case REG_R11:
	    rs = "R11";
            rv = user_regs.r11;
	    break;

          case REG_R10:
	    rs = "R10";
            rv = user_regs.r10;
	    break;

          case REG_R9:
	    rs = "R9";
            rv = user_regs.r9;
	    break;

          case REG_R8:
	    rs = "R8";
            rv = user_regs.r8;
	    break;

          case REG_RAX:
	    rs = "RAX";
            rv = user_regs.rax;
	    break;

          case REG_RCX:
	    rs = "RCX";
            rv = user_regs.rcx;
	    break;

          case REG_RDX:
	    rs = "RDX";
            rv = user_regs.rdx;
	    break;

          case REG_RSI:
	    rs = "RSI";
            rv = user_regs.rsi;
	    break;

          case REG_RDI:
	    rs = "RDI";
            rv = user_regs.rdi;
	    break;

          case REG_RIP:
	    rs = "RIP";
            rv = user_regs.rip;
	    break;

          case REG_CS:
	    rs = "CS";
            rv = user_regs.cs;
	    break;

          case REG_EFLAGS:
	    rs = "EFLAGS";
            rv = user_regs.eflags;
	    break;

          case REG_RSP:
	    rs = "RSP";
            rv = user_regs.rsp;
	    break;

          case REG_SS:
	    rs = "SS";
            rv = user_regs.ss;
	    break;

          case REG_FS_BASE:
	    rs = "FS_BASE";
            rv = user_regs.fs_base;
	    break;

          case REG_GS_BASE:
	    rs = "GS_BASE";
            rv = user_regs.gs_base;
	    break;

          case REG_DS:
	    rs = "DS";
            rv = user_regs.ds;
	    break;

          case REG_ES:
	    rs = "ES";
            rv = user_regs.es;
	    break;

          case REG_FS:
	    rs = "FX";
            rv = user_regs.fs;
	    break;

          case REG_GS:
	    rs = "GS";
            rv = user_regs.gs;
	    break;
	  }

	  fprintf(stderr, INFO_PREFIX "(%llu):  %s: %llu\n", (unsigned long long int) tracee, rs, rv);

	  unsigned long long int r = rv;
	  _Bool exhausted = 0;

	  if (td[i].deref[j][0] == D_END) {
	    exhausted = 1;
	  }

	  for (size_t k = 0; !exhausted && k < DEREF_LEVEL; k++) {
	    switch (td[i].deref[j][k]) {
	    case D_W:
	      r = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

	      if (errno) {
		werr("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		return ERR_PTRACE_PEEKTEXT;
	      }

	      break;

	    case D_DW:
	      {
		long tr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

		if (errno) {
		  werr("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		  return ERR_PTRACE_PEEKTEXT;
		}

		long ttr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE), NULL);

		if (errno) {
		  werr("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		  return ERR_PTRACE_PEEKTEXT;
		}

#ifdef ENDIAN_LITTLE
		memcpy(&((char *) &tr)[WORD_SIZE], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
		memcpy(&tr, &ttr, WORD_SIZE);

#endif

		r = tr;
	      }

	      break;

	    case D_QW:
	      {
		long tr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

		if (errno) {
		  werr("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		  return ERR_PTRACE_PEEKTEXT;
		}

		long ttr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE), NULL);

		if (errno) {
		  werr("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		  return ERR_PTRACE_PEEKTEXT;
		}

#ifdef ENDIAN_LITTLE
		memcpy(&((char *) &tr)[WORD_SIZE], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
		memcpy(&((char *) &tr)[WORD_SIZE * 2], &ttr, WORD_SIZE);

#endif

		ttr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE * 2), NULL);

		if (errno) {
		  werr("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		  return ERR_PTRACE_PEEKTEXT;
		}

#ifdef ENDIAN_LITTLE
		memcpy(&((char *) &tr)[WORD_SIZE * 2], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
		memcpy(&((char *) &tr)[WORD_SIZE], &ttr, WORD_SIZE);

#endif

		tr = ptrace(PTRACE_PEEKTEXT, tracee, (void *) (r + WORD_SIZE * 3), NULL);

		if (errno) {
		  werr("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		  return ERR_PTRACE_PEEKTEXT;
		}

#ifdef ENDIAN_LITTLE
		memcpy(&((char *) &tr)[WORD_SIZE * 3], &ttr, WORD_SIZE);

#elif defined(ENDIAN_BIG)
		memcpy(&tr, &ttr, WORD_SIZE);

#endif

		r = tr;
	      }

	      break;

	    case D_STRING:
	      winfo("   string: ", stderr, tracee);

	      while (1) {
		errno = 0;

		long s = ptrace(PTRACE_PEEKTEXT, tracee, (void *) r, NULL);

		if (errno) {
		  werr("ptrace(PTRACE_PEEKTEXT, tracee, r, NULL) failed\n", stderr, tracee);
		  return ERR_PTRACE_PEEKTEXT;
		}

		if (*(char *) &s != '\0') {
		  fputc(*(char *) &s, stderr);
		}
		else {
		  break;
		}

		r++;
	      }

	      fputc('\n', stderr);

	      break;

	    case D_END:
	      fprintf(stderr, INFO_PREFIX "(%llu):    deref: %llu\n", (unsigned long long int) tracee, r);
	      exhausted = 1;
	      break;

	    default:
	      werr("illegal derefence\n", stderr, tracee);
	      return ERR_ILLEGAL_DEREF;
	    }
	  }
	}
      }
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
