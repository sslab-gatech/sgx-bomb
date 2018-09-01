# The SGX-Bomb attack
*SGX-Bomb* launches the Rowhammer attack 
against enclave memory to trigger the processor lockdown. 
If arbitrary bit flips have occurred inside the
enclave because of the Rowhammer attack, any read attempts to
the enclave memory results in a failure of integrity check so that
the processor will be locked, and the system should be rebooted.

This repository contains proof-of-concept code snippets 
of the SGX-bomb attack, including
 1. A kernel module to retrieve physical addresses of the enclave pages
 2. An enclave program to launch SGX-bomb attack 

# Evaluation
We evaluated the effectiveness of the SGX-Bomb attack 
in a real environment with DDR4 DRAM;
it takes 283 s to hang the entire system 
with the default DRAM refresh rate, 64 ms.

*Kernel version*: 4.15.0-33-generic

*Intel SGX-SDK* : [SGX-2.2 <b0cc03a8184949cac76880449190d56dfb717cba>]
(https://github.com/intel/linux-sgx/commit/b0cc03a8184949cac76880449190d56dfb717cba)
 
## More details
* Paper (**SysTEX 2017**):
  https://taesoo.kim/pubs/2017/jang:sgx-bomb.pdf 
* Slides: https://taesoo.kim/pubs/2017/jang:sgx-bomb-slides.pdf

## Contributors
* [Yeongjin Jang]
* Jaehyuk Lee
* [Sangho Lee]
* [Taesoo Kim]


[Yeongjin Jang]: <http://people.oregonstate.edu/~jangye/>
[Sangho Lee]: <http://www.cc.gatech.edu/~slee3036>
[Taesoo Kim]: <https://taesoo.kim/>

