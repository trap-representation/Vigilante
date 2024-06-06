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
#include <sys/types.h>

#include "errors.h"
#include "tracer.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    diag(stderr, -1, ERROR_PREFIX, "usage:\n"
	 "PID config (optional)\n");
    return ERR_NOARGS;
  }

  pid_t tracee;

  enum error r;

  if ((r = get_pid(argv[1], &tracee)) != ERR_SUCCESS) {
    return r;
  }

  return trace(tracee, argv[2]);
}
