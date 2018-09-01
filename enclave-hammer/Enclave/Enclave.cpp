/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <map>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#include "phy.h"

#define STRIDE (128)
#define N_TIMES (1073741824ull / 4)
#define NUM_TIME_READS (1000)
#define SHMEM_ADDR (0x41410000)

void usleep(int time) {
    ocall_usleep(time);
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

volatile size_t timer = 0;
volatile size_t stop = 1;
uint64_t start_timer() {
    volatile uint64_t *timer_ptr = (uint64_t*)SHMEM_ADDR;
    stop = 0;
    while(1) {
        if(stop) break;
        *timer_ptr = ++timer;
    }
    return 0ul;
}
uint64_t stop_timer() {
    stop = 1;
}

uint64_t get_time() {
    uint64_t *timer_ptr = (uint64_t*)SHMEM_ADDR;
    return *timer_ptr;
}

int chk_flip(uint64_t *ptr, size_t size) {
    int nflips = 0;
    for(uint64_t i=0ull; i<size/sizeof(uint64_t); ++i) {
        if(ptr[i] != values[i%VALSIZE]) {
            ++nflips;
            // this should never be called; instead, machine will stop
            printf("Flip at %p 0x%016llx vs 0x%016llx\n", &ptr[i], ptr[i], values[i%VALSIZE]);
        }
    }
    return nflips;
}

uint64_t *g_heap_base; 
uint64_t *g_heap_end;
uint64_t g_heap_size;

uint64_t real_hammer(uint64_t *a, uint64_t *b, uint64_t reads, size_t ms) {
    while(reads-- > 0) {
        asm volatile("mov (%0), %%r10;" :: "r"(a) : "memory");
        asm volatile("mov (%0), %%r11;" :: "r"(b) : "memory");
        asm volatile("clflushopt (%0);" :: "r"(a) : "memory");
        asm volatile("clflushopt (%0);" :: "r"(b) : "memory");
    }
    int result = chk_flip((uint64_t*)g_heap_base, ms);
    if(result != 0) {
        printf("Flip!!! %d %d\n", result);
    }
}

uint64_t measure_min_timing(uint64_t vaddr_first, uint64_t vaddr_second, uint64_t n_trial) {
    volatile size_t min_r = (-1ull);
    volatile size_t number_of_reads = n_trial;
    volatile size_t *f = (volatile size_t *) vaddr_first;
    volatile size_t *s = (volatile size_t *) vaddr_second;

    size_t tt = get_time();
    while (number_of_reads-- > 0) {
        asm volatile("clflushopt (%0)" : : "r" (f) : "memory");
        asm volatile("clflushopt (%0)" : : "r" (s) : "memory");
        asm volatile("mfence;");
        asm volatile("mov (%0), %%r10;" :: "r"(f) : "memory");
        asm volatile("mov (%0), %%r11;" :: "r"(s) : "memory");
        asm volatile("lfence;");
    }
    size_t ttt = get_time();
    return (ttt-tt);
}


volatile uint64_t sum = 0ull;

uint64_t populate_all_pages() {
    uint64_t **ptr = (uint64_t**)(SHMEM_ADDR);
    g_heap_base = ptr[0];
    g_heap_end  = ptr[1];
    g_heap_size = (uint64_t)ptr[2];
  
    set_mem(g_heap_base, g_heap_size);
    return (uint64_t)0ull;
}



uint64_t Hammer(int value, uint64_t a, uint64_t b, uint64_t times) {
    uint64_t **ptr = (uint64_t**)(SHMEM_ADDR);
    char *aa = (char*)a;
    char *bb = (char*)b;
    size_t size = g_heap_size;
    printf("TID %d Hammering %p %p\n", value, aa, bb);
    if(value % 4 == 0) {
      real_hammer((uint64_t*)a, (uint64_t*)b, times, size);
    }
    else if (value % 4 == 1) {
      real_hammer((uint64_t*)b, (uint64_t*)a, times, size);
    }
    else if (value % 4 == 2) {
      real_hammer((uint64_t*)a, (uint64_t*)b, times, size);
    }
     else if (value % 4 == 3) {
      real_hammer((uint64_t*)b, (uint64_t*)a, times, size);
    }
  
    return 0;
}


