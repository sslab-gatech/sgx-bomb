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

#define N_TIMES ((uint64_t)(1024ul*1024ul*1024ul))
#define ROWSIZE (0x40000)
#define SHMEM_ADDR (0x41410000)
#define STRIDE  (128)
#define MAX_N_THREAD (8)

#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>

//#include <pthread.h>
#include <sys/types.h>
#include <errno.h>

#include <thread>
#include <fstream>
#include <iostream>
#include <chrono>
#include <algorithm>
#include <vector>

typedef std::chrono::high_resolution_clock Clock;

using namespace std;

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

typedef uint64_t pointer;
int g_pagemap_fd = -1;

void initPagemap() {
    g_pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    assert(g_pagemap_fd >= 0);
}

size_t frameNumberFromPagemap(size_t value) {
    return value & ((1ULL << 54) - 1);
}

pointer getPhysicalAddr(pointer virtual_addr) {
    pointer value;
    off_t offset = (virtual_addr / 4096) * sizeof(value);
    int got = pread(g_pagemap_fd, &value, sizeof(value), offset);
    assert(got == 8);
    //printf("%p\n", value);

    // Check the "page present" flag.
    assert(value & (1ULL << 63));

    pointer frame_num = frameNumberFromPagemap(value);
    return (frame_num * 4096) | (virtual_addr & (4095));
}


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    //if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
    //    if (fp != NULL) fclose(fp);
    //    return 0;
    //}

    /* reopen the file with write capablity */
    /*
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    */
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

void ocall_usleep(int usec) {
    usleep(usec);
}

void get_maps() {

    uint64_t *ptr = (uint64_t*)mmap((void*)SHMEM_ADDR, 0x1000, \
            PROT_READ|PROT_WRITE|PROT_EXEC, \
            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

    if(ptr != (void*)-1) {
        printf("%p is mapped!\n", ptr);
    }
    else {
        printf("Fixed map failed %p\n", ptr);
        return;
    }


    FILE *fp = fopen("/proc/self/maps", "rb");
    char buf[512];
    char int1[512];
    char int2[512];
    do {
        if (fgets(buf, 512, fp) == NULL) {
            printf("Error in reading proc/self/maps\n");
            exit(1000);    
        }
        if(strstr(buf, "/dev/isgx") != NULL) {
            // 7efde8241000-7efdec241000 rw-s 00241000 00:06 2855 /dev/isgx
            char *end1 = strstr(buf, "-");
            *end1 = '\0';
            char *start2 = end1 + 1;
            char *end2 = strstr(start2, " ");
            *end2 = '\0';
            uint64_t base = strtoull(buf, NULL, 16);
            uint64_t end = strtoull(start2, NULL, 16);
            if( (end - base) >= 0x4000000) {
                ptr[0] = base;
                ptr[1] = end;
                char *a = (char*)(ptr[0]);
                char *b = (char*)(ptr[1]);
                ptr[2] = uint64_t (b-a);
            }
            //printf("Size 0x%016llx Heap address: %p - %p\n", ptr[2], ptr[0], ptr[1]);
        }
        else if(strstr(buf, "vsyscall")) {
            break;
        }
    } while(1);
    fclose(fp);
}

uint64_t get_physical_address(uint64_t i_ptr) {
    int fd = open("/proc/phyaddr", O_WRONLY);
    if(fd < 0) return 0ull;
    uint64_t i_var = i_ptr;
    if (write(fd, &i_var, sizeof(uint64_t)) != sizeof(uint64_t)) {
        printf("Error in writing address into the /proc/phyaddr");
        exit(1001);
    }
    close(fd);
    return i_var;
}

struct addr_t {
    uint64_t paddr;
    uint64_t vaddr;
};

uint64_t page_size;

struct sort_function {
      bool operator() (addr_t i, addr_t j) {
          return (i.paddr<j.paddr);
      }
};

vector<addr_t> v_addrs;

void go_get_phy_addr() {

    uint64_t **ptr = (uint64_t**)(SHMEM_ADDR);
    char *HEAP_BASE = (char*)ptr[0];
    char *HEAP_END = (char*)ptr[1];

    uint64_t HEAP_SIZE = (HEAP_END - HEAP_BASE);
    uint64_t PAGE_CNT = HEAP_SIZE / 0x1000;

    page_size = PAGE_CNT;

    v_addrs.reserve(PAGE_CNT);
    for(int i=0; i<PAGE_CNT; ++i) {
        char *cur_addr = HEAP_BASE + (i*0x1000);
        uint64_t phy_addr = get_physical_address((uint64_t)cur_addr);
        addr_t at;
        at.paddr = phy_addr;
        at.vaddr = (uint64_t)cur_addr;
        v_addrs.push_back(at);
    }
    sort(v_addrs.begin(), v_addrs.end(), sort_function());
}


void ecall_hammer(int tid, uint64_t a, uint64_t b) {
    uint64_t return_val = 0;
    Hammer(global_eid, &return_val, tid, a, b, N_TIMES);
}

void thread_start_timer() {
    uint64_t return_val = 0;
    start_timer(global_eid, &return_val);
}
void thread_stop_timer() {
    uint64_t return_val = 0;
    stop_timer(global_eid, &return_val);
}


uint64_t min_timing(uint64_t first, uint64_t second, uint64_t n_trial) {
    uint64_t return_val = 0;
    measure_min_timing(global_eid, &return_val, first, second, n_trial);
    return return_val;
}

uint64_t m_min_timing(uint64_t vaddr_first, uint64_t vaddr_second, uint64_t n_trial) {
    volatile size_t min_r = (-1ull);
    volatile size_t number_of_reads = n_trial;
    volatile size_t *f = (volatile size_t *) vaddr_first;
    volatile size_t *s = (volatile size_t *) vaddr_second;

    while (number_of_reads-- > 0) {
        asm volatile("clflushopt (%0)" : : "r" (f) : "memory");
        asm volatile("clflushopt (%0)" : : "r" (s) : "memory");
        asm volatile("mfence;");
        size_t tt = rdtsc_beg();
        asm volatile("lfence;");
        asm volatile("mov (%0), %%r10;" :: "r"(f) : "memory");
        asm volatile("mov (%0), %%r11;" :: "r"(s) : "memory");
        asm volatile("lfence;");
        size_t ttt = rdtsc_end();
        asm volatile("lfence;");
        if(min_r > ttt-tt) {
            min_r = ttt-tt;
        }
        usleep(20);
    }
    return min_r;
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    int n_threads = 4;
    if(argc > 1) {
        n_threads = strtol(argv[1], 0, 10);
        if(n_threads < 1) {
            n_threads = 1;
        }
    }

    printf("Number of threads %d\n", n_threads);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enclave initialize failed\n");
        return -1;
    }

    get_maps();

    uint64_t return_val = 0;

    // populate virtual pages in the enclave
    populate_all_pages(global_eid, &return_val);

    // get sorted physical address at v_addrs vector
    go_get_phy_addr();
    printf("Total paddrs %lu\n", v_addrs.size());

    srand(time(NULL));
    addr_t start_addr;
    addr_t row_1_addr, row_2_addr, row_3_addr;
    int count;

    thread timer_thread(thread_start_timer);
    sleep(2);

    while(1) {
        int start_idx = rand() % v_addrs.size();
        for(int i=start_idx; i<v_addrs.size(); ++i) {
            if((v_addrs[i].paddr &0xfffff) == 0) {
                start_idx = i;
                break;
            }
        }
        start_addr = v_addrs[start_idx];
        row_1_addr = start_addr;
        memset(&row_2_addr, 0 , sizeof(addr_t));
        memset(&row_3_addr, 0 , sizeof(addr_t));

        for(int i = start_idx+1, count = 0; i<v_addrs.size(); ++i) {
            addr_t cur_addr = v_addrs[i];
            uint64_t timing = min_timing(start_addr.vaddr, cur_addr.vaddr, 10000);
            if(timing > 1000000) {
                count += 1;
            }
            if(count == 1) {
                row_2_addr = cur_addr;
            }
            if(count == 3) {
                row_3_addr = cur_addr;
                break;
            }
        }
        if (row_2_addr.paddr!= 0x0 && row_3_addr.paddr != 0x0) break;
    }
    printf("1st Row 0x%016lx 2nd Row 0x%016lx 3rd Row 0x%016lx\n", \
            row_1_addr.paddr, row_2_addr.paddr, row_3_addr.paddr);

    count = 0;
    vector<uint64_t> s_addr;
    vector<uint64_t> sp_addr;
    vector<uint64_t> e_addr;
    vector<uint64_t> ep_addr;
    for(int i=0;; ++i) {
        uint64_t stride_vaddr_start = row_1_addr.vaddr + STRIDE * i;
        uint64_t stride_vaddr_end = row_3_addr.vaddr + STRIDE * i;
        uint64_t timing1 = min_timing(stride_vaddr_start, stride_vaddr_end, 1000);
        uint64_t timing2 = min_timing(row_1_addr.vaddr, stride_vaddr_end, 1000);
        uint64_t timing3 = min_timing(stride_vaddr_start, row_3_addr.vaddr, 1000);
        if(timing1 > 100000 && timing2 > 100000 && timing3 > 100000) {
            count += 1;
            s_addr.push_back(stride_vaddr_start);
            e_addr.push_back(stride_vaddr_end);
            sp_addr.push_back(row_1_addr.paddr + STRIDE * i);
            ep_addr.push_back(row_3_addr.paddr + STRIDE * i);
        }
        if(count == 8)
            break;
    }
    for(int i=0; i<8; ++i) {
        printf("0x%016lx 0x%016lx 0x%016lx 0x%016lx\n", \
                s_addr[i], e_addr[i], sp_addr[i], ep_addr[i]);
    }

    // kill timer
    thread_stop_timer();
    timer_thread.join();


    // hammer!
    thread hammer_thread[MAX_N_THREAD];

    auto tall = Clock::now();
    while(1) {
        auto t1 = Clock::now();
        for(int i=0; i<n_threads; ++i) {
            // fork
            hammer_thread[i] = thread(ecall_hammer, i, s_addr[i], e_addr[i]);
        }
        for(int i=0; i<n_threads; ++i) {
            // join
            hammer_thread[i].join();
        }
        auto t2 = Clock::now();
        size_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        size_t duration2 = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - tall).count();
        printf("%ldms\n", duration);
        double n_hammers = 64.0 * (double)(N_TIMES*n_threads) / (double)duration;
        printf("%ld hammers per 64ms\n", (uint64_t)n_hammers);
        printf("Elapsed Time: %lds\n", duration2 / 1000);

    }
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("SGX Destroyed\n");

    return 0;
}

