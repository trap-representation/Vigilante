/*
    WTDF lets you easily make TDF files
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


#include <stdlib.h>
#include <stdio.h>

#include "wtdf.h"

void init_td(struct trace_def *tda, size_t n) {
  for (size_t tdi = 0; tdi < n; tdi++) {
    tda[tdi].syscall = 0;

    for (size_t ri = 0; ri < REG_N; ri++) {
      tda[tdi].trace_regs[ri] = NOTRACE;
      tda[tdi].deref[ri][0] = D_END;
    }
  }
}

void trace_syscall(unsigned long long int sc, struct trace_def *td) {
  td->syscall = sc;
}

void trace_regs(enum reg r, struct trace_def *td) {
  td->trace_regs[r] = TRACE;
}

void trace_deref(enum dereference *d, size_t n, enum reg r, struct trace_def *td) {
  for (size_t i = 0; i < n; i++) {
    td->deref[r][i] = d[i];
  }
}

int write_td(struct trace_def *td, size_t n, char *file) {
  FILE *f = fopen(file, "wb");

  if (f == NULL) {
    return ERR_FOPEN;
  }

  if (fwrite(&n, sizeof(n), 1, f) < 1) {
    fclose(f);
    return ERR_FWRITE;
  }

  if (fwrite(td, sizeof(*td), n, f) < n) {
    fclose(f);
    return ERR_FWRITE;
  }

  fclose(f);

  return ERR_SUCCESS;
}

enum error verify(struct trace_def *tda, size_t n) {
  for (size_t tdi = 0; tdi < n; tdi++) {
    for (size_t ri = 0; ri < REG_N; ri++) {
      if (tda[tdi].trace_regs[ri] == NOTRACE && tda[tdi].deref[ri][0] != D_END) {
	return ERR_DEREF_ON_NOTRACE;
      }

      if (tda[tdi].trace_regs[ri] == TRACE) {
	_Bool ends_correct = 0;

	for (size_t dl = 0; dl < DEREF_LEVEL; dl++) {
	  if (tda[tdi].deref[ri][dl] != D_W && tda[tdi].deref[ri][dl] != D_DW && tda[tdi].deref[ri][dl] != D_QW && tda[tdi].deref[ri][dl] != D_NSTRING && tda[tdi].deref[ri][dl] != D_STRING_R15 && tda[tdi].deref[ri][dl] != D_STRING_R14 && tda[tdi].deref[ri][dl] != D_STRING_R13 && tda[tdi].deref[ri][dl] != D_STRING_R12 && tda[tdi].deref[ri][dl] != D_STRING_RBP && tda[tdi].deref[ri][dl] != D_STRING_RBX && tda[tdi].deref[ri][dl] != D_STRING_R11 && tda[tdi].deref[ri][dl] != D_STRING_R10 && tda[tdi].deref[ri][dl] != D_STRING_R9 && tda[tdi].deref[ri][dl] != D_STRING_R8 && tda[tdi].deref[ri][dl] != D_STRING_RAX && tda[tdi].deref[ri][dl] != D_STRING_RCX && tda[tdi].deref[ri][dl] != D_STRING_RDX && tda[tdi].deref[ri][dl] != D_STRING_RSI && tda[tdi].deref[ri][dl] != D_STRING_RDI && tda[tdi].deref[ri][dl] != D_STRING_RIP && tda[tdi].deref[ri][dl] != D_STRING_CS && tda[tdi].deref[ri][dl] != D_STRING_EFLAGS && tda[tdi].deref[ri][dl] != D_STRING_RSP && tda[tdi].deref[ri][dl] != D_STRING_SS && tda[tdi].deref[ri][dl] != D_STRING_FS_BASE && tda[tdi].deref[ri][dl] != D_STRING_GS_BASE && tda[tdi].deref[ri][dl] != D_STRING_DS && tda[tdi].deref[ri][dl] != D_STRING_ES && tda[tdi].deref[ri][dl] != D_STRING_FS && tda[tdi].deref[ri][dl] != D_STRING_GS && tda[tdi].deref[ri][dl] != D_END) {
	    return ERR_INVALID_DEREF;
	  }

	  if (tda[tdi].deref[ri][dl] == D_END) {
	    ends_correct = 1;
	    break;
	  }
	}

	if (!ends_correct) {
	  return ERR_ILLEGAL_END_DEREF;
	}
      }
    }
  }

  return ERR_SUCCESS;
}
