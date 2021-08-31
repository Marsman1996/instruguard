# InstruGuard
Code repository for "InstruGuard: Find and Fix Instrumentation Errors for Coverage-based Greybox Fuzzing" (in *ASE'21*).

InstruGuard detects instrumentation errors by static analysis on target binaries, and fixes them with a general solution based on binary rewriting.
Please refer to the [paper](./InstruGuard!%20Find%20and%20Fix%20Instrumentation%20Errors%20for%20Coverage-based%20Greybox%20Fuzzing.pdf) for more details.

## General Setup
- The error detection script is tested in IDA 7.0, not sure if other versions could run the script.  
- RetroWrite requires python3 and python3-venv, make sure they are installed on system.
- Run `./setup.sh` to setup RetroWrite and aflig.

## Find Instrumentation Errors
To detect instrumentation errors,
if you are using IDA with GUI, just click `File->Script file` and select the `./find/IDA_checkinstru.py`.  
Or you can use the command line (Here we take `nm` as an example):  
`$ PATH_TO_IDAPRO -A -S./find/IDA_checkinstru.py PATH_TO_TARGET`  

`IDA_checkinstru.py` will generate two files: 
1. `nm_instru.log`, a report for human to read.
2. `nm_instru.json`, a diction which includes the MIL, EIL, and normal instrumentation.

## Fix Instrumentation Errors
Since RetroWrite now only supports programs compiled as position independent code (PIC/PIE), you can compile the target programs with the `./fix/aflig/afl-clang-fast`, in which we add `-f` inside this `afl-clang-fast`. 
Or you can add the arguments yourself during the compilation.

To fix the program with instrumentation errors, you need to:  
1. Generate assembly code for the target programs: 
    ```
    $ source ./fix/retrowrite/retro/bin/activate
    $ ./fix/retrowrite/retrowrite nm nm.s
    ```
2. Modify the assembly code with the instrumentation information we collect (i.e. `nm_instru.json`): 
   ```
    $ python ./fix/fix_asm.py --asm_file nm.s --instru_info nm_instru.json -O nm+.s
   ```
3. Compile the modified assembly code: 
    ```
    $ ./fix/aflig/afl-ig nm+.s -o nm+ -ldl
    ```
    LDFLAGS could be found in the Makefile/configure/CMAKEFile of the target program.

## Example
In [example](example/) folder, we demonstrate an example and show how to use InstruGuard. Read [example/README.md](example/README.md) for more details.

## Evaluation
The source code of the dataset in our paper can be downloaded [here](https://drive.google.com/file/d/1hGEu5na2hh3pWh_I4bvMaWZxWvXxBeev/view?usp=sharing). We also put [the binaries compiled by afl-clang-fast of AFL](https://drive.google.com/file/d/1cn0_CoOIhs78SfZhiS6Un6ZnkR5zmshh/view?usp=sharing) and [the fixed binaries](https://drive.google.com/file/d/1vt6uekruXfVn9XazrCD4WIFCqnb6f4Gr/view?usp=sharing).

<!-- ## Cite -->