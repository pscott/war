# War: a polymorphic virus (for ELF64 files)

War is a polymorphic virus that infects ELF64 files (linux-native 64 bits executables).
It is written only in asm (intel flavor).

It:
- Infect `/tmp/test` and `/tmp/test2` directories
- Does not modify the behaviour of the infected file
- The infection simply adds a signature and adds its own code to the target (_auto-replication_)
- Does not run if a process `test` is running
- Displays `DEBUG...` if the process is traced (`gdb`, `strace`...)

# Usage

First start by creating the target folders:

`mkdir /tmp/test ; mkdir /tmp/test2`

Copy the elf files you wish to infect:

`cp /bin/ls /tmp/test; cp /bin/gcc /tmp/test2`

Now compile the virus and run it:
`make ; ./war`

Check that the files were correctly infected:
`strings /tmp/test/ls | grep 'pscott'`
`strings /tmp/test2/gcc | grep 'pscott'`

Since the virus auto-replicates, you can now infect those folders by running the infected files.

Copy a new binary:
`cp /bin/cat /tmp/test2`

Run an infected binary:
`/tmp/test/ls`

Check that the file was correctly infected:
`strings /tmp/test2/cat | grep 'pscott'`

Voila!

This virus is not harmful and was coded strictly for learning purposes.

# Resources
Inspired from:
- [Midrashim](https://github.com/guitmz/midrashim/blob/main/Linux.Midrashim.asm)
- [tmpout.sh](https://tmpout.sh/1/6.html)
- [Coconut's project](https://github.com/dbaffier/Death/)
