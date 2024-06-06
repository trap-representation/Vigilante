#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include "utils.h"
#include "vconfig.h"

#ifdef ENDIAN_LITTLE
#elif defined(ENDIAN_BIG)
#else
_Static_assert(0, "define the endianness of your implementation in vconfig.h");
#endif

enum error get_pid(char *pid_s, pid_t *tracee) {
  *tracee = 0;

  for (size_t pc = 0; pid_s[pc] != '\0'; pc++) {
    if (pid_s[pc] >= '0' && pid_s[pc] <= '9') {
      *tracee *= 10;
      *tracee += pid_s[pc] - '0';
    }
    else {
      diag(stderr, 0, ERROR_PREFIX, "invalid PID\n");
      return ERR_INVALID_PID;
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
    diag(stderr, tracee, ERROR_PREFIX, "fopen(file, \"rb\") failed\n");
    return ERR_OPEN_TDF;
  }

  if (fread(tdn, sizeof(*tdn), 1, tdf) < 1) {
    if (!ferror(tdf)) {
      diag(stderr, tracee, ERROR_PREFIX, "invalid TDF file format\n");
      fclose(tdf);
      return ERR_INVALID_FILEFORMAT;
    }
    else {
      diag(stderr, tracee, ERROR_PREFIX, "failed to read from TDF\n");
      fclose(tdf);
      return ERR_FAILED_TO_READ_TDF;
    }
  }

  if ((*td = malloc(sizeof(**td) * *tdn)) == NULL) {
    diag(stderr, tracee, ERROR_PREFIX, "malloc(sizeof(**td) * *tdn) failed\n");
    fclose(tdf);
    return ERR_MALLOC;
  }

  if (fread(*td, sizeof(**td), *tdn, tdf) < *tdn) {
    if (!ferror(tdf)) {
      diag(stderr, tracee, ERROR_PREFIX, "invalid TDF file format\n");
      free(*td);
      fclose(tdf);
      return ERR_INVALID_FILEFORMAT;
    }
    else {
      diag(stderr, tracee, ERROR_PREFIX, "failed to read from TDF\n");
      free(*td);
      fclose(tdf);
      return ERR_FAILED_TO_READ_TDF;
    }
  }

  fclose(tdf);

  return ERR_SUCCESS;
}
