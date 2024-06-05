#ifndef CFG_H
#define CFG_H

#include "vconfig.h"

#define REG_N 27
#define DEREF_LEVEL VCONF_DEREF_LEVEL

#define SC_ALL VCONF_SC_ALL

enum trace {
  NOTRACE,
  TRACE
};

/* Do not change the order of the enumeration constants in reg and dereference*/

enum reg {
  REG_R15,
  REG_R14,
  REG_R13,
  REG_R12,
  REG_RBP,
  REG_RBX,
  REG_R11,
  REG_R10,
  REG_R9,
  REG_R8,
  REG_RAX,
  REG_RCX,
  REG_RDX,
  REG_RSI,
  REG_RDI,
  REG_RIP,
  REG_CS,
  REG_EFLAGS,
  REG_RSP,
  REG_SS,
  REG_FS_BASE,
  REG_GS_BASE,
  REG_DS,
  REG_ES,
  REG_FS,
  REG_GS
};

enum dereference {
  D_W,
  D_DW,
  D_QW,
  D_NSTRING,
  _DNOUSE_STRINGS,
  D_STRING_R15,
  D_STRING_R14,
  D_STRING_R13,
  D_STRING_R12,
  D_STRING_RBP,
  D_STRING_RBX,
  D_STRING_R11,
  D_STRING_R10,
  D_STRING_R9,
  D_STRING_R8,
  D_STRING_RAX,
  D_STRING_RCX,
  D_STRING_RDX,
  D_STRING_RSI,
  D_STRING_RDI,
  D_STRING_RIP,
  D_STRING_CS,
  D_STRING_EFLAGS,
  D_STRING_RSP,
  D_STRING_SS,
  D_STRING_FS_BASE,
  D_STRING_GS_BASE,
  D_STRING_DS,
  D_STRING_ES,
  D_STRING_FS,
  D_STRING_GS,
  _DNOUSE_STRINGE,
  D_END
};

struct trace_def {
  unsigned long long int syscall;
  _Bool trace_regs[REG_N];
  enum dereference deref[REG_N][DEREF_LEVEL];
};

#endif
