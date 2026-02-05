#ifndef __STDLIB_H__
#define __STDLIB_H__

#include <stddef.h>

void* calloc(size_t num, size_t size);
void free(void *ptr);

int rand(void);

#endif