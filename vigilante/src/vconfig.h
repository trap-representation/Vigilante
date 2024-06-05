#ifndef VCONFIG_H
#define VCONFIG_H

/* Redefine WORD_SIZE (in bytes) depending on your implementation */
#define WORD_SIZE 2

/* Comment out one of ENDIAN_LITTLE and ENDIAN_BIG, depending on your implementation */
#define ENDIAN_LITTLE
/* #define ENDIAN_BIG */

/* Change this depending on how many level of dereference you want to have */
#define VCONF_DEREF_LEVEL 512

/* Change this to a value that does not equal to any syscall number on your system */
#define VCONF_SC_ALL 65536

#endif
