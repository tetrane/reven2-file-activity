# REVEN2 File Activity

This script looks for file activity in a REVEN trace.

"File activity" covers the following operation:
- Opening a file
- Write to a file
- Reading from a file
- Reading file attributes from a file.

Note that file closing is not covered by this script.

This script is designed to work for Windows 10 64-bit traces.

The script allows to filter results by a specific PID of a process of interest.
Please use the `--help` switch for more information on the parameters accepted by the script.


## Prerequisite

This script can only be run on Debian Buster.


## Installing

The script requires python 3.

The script depends on libclang 7 being installed on the machine that runs the script.
For Debian Stretch/Buster, you can install it this way:

```
$ sudo apt install libclang1-7
```

The script requires a reven-enabled virtual environment.
Make sure you are in such an environment, and then run:

```
$ python3 -m pip install -r requirements.txt
```


## Usage

You can then run the script with:

```
$ python3 -m reven2_file_activity <parameters>
```


### Example

```
$ python3 -m reven2_file_activity --host localhost --port 42777
#114138 - svchost.exe(404) - NtCreateFile:
- ObjectAttributes = 0xdf2e6ff9c0
    - file = \??\PhysicalDrive0
- FileHandle = 0xdf2e6ff948
- FileAttributes = 0
- EaLength = 0
- CreateOptions = 96
- CreateDisposition = 1
- ShareAccess = 3
- EaBuffer = 0x0
- AllocationSize = 0x0
- DesiredAccess = 1048704
- IoStatusBlock = 0xdf2e6ff960
=> Return at #136057: SUCCESS
    - handle value = 0x53c

#174727 - csrss.exe(420) - NtReadFile:
- ByteOffset = 0xfffff9612fc79798
- FileHandle = 0xffffffff800003f4
- Buffer = 0xffffe000bbec824c
- Length = 240
- ApcRoutine = 0xfffff9612fc0b6c0
- Event = 0x0
- IoStatusBlock = 0xffffe000bbec81a8
- Key = 0x0
- ApcContext = 0xffffe000bbec80b0
=> Return at #177213: SUCCESS

#201940 - csrss.exe(420) - NtReadFile:
- ByteOffset = 0xfffff9612fc79798
- FileHandle = 0xffffffff800003f4
- Buffer = 0xffffe000bbec824c
- Length = 240
- ApcRoutine = 0xfffff9612fc0b6c0
- Event = 0x0
- IoStatusBlock = 0xffffe000bbec81a8
- Key = 0x0
- ApcContext = 0xffffe000bbec80b0
=> Return at #203280: FAILURE
    - ntstatus = 259

#3486309 - vlc.exe(2620) - NtQueryAttributesFile:
- ObjectAttributes = 0x31c9f00
    - file = \??\C:\Users\reven\Documents
- FileInformation = 0x31c9f30
=> Return at #3532285: SUCCESS

...
```
