#ifndef CFG_H
#define CFG_H

#define REG_N 27
#define DEREF_LEVEL 512

enum trace {
  NOTRACE,
  TRACE
};

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
  D_STRING,
  D_END
};

struct trace_def {
  unsigned long long int syscall;
  _Bool trace_reg[REG_N];
  enum dereference deref[REG_N][DEREF_LEVEL];
};

#endif
