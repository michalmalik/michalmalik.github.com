---
layout: post
title: "ELF: dynamic struggles"
---

## Intro

Every ELF64 binary starts with this header:
{% highlight c %}
typedef struct elf64_hdr {
  unsigned char	e_ident[EI_NIDENT];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;
{% endhighlight %}

We are only going to concern ourselves with dynamically linked 
`Elf64_Ehdr.e_type` = `ET_EXEC` (executable files) or `ET_DYN` (dynamic shared objects,
basically shared libraries).

Note: If you don't know what dynamic linking means, I suggest to read [this article][dynamic-linking].
I will not mention ELF sections on purpose. They are not relevant in executables and shared
libraries. They don't have to be there
and should be treated like a nice bonus when they actually are. See [sstrip][sstrip].
This "technique" is used by [malware][roopre] fairly often and you don't need sstrip to do the job.

`e_phoff` specifies the start of a `program header table` (PHT) in the file. The PHT is made
of `Elf64_Phdr` entries (segments):

{% highlight c %}
typedef struct elf64_phdr {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;		/* Segment file offset */
  Elf64_Addr p_vaddr;		/* Segment virtual address */
  Elf64_Addr p_paddr;		/* Segment physical address */
  Elf64_Xword p_filesz;		/* Segment size in file */
  Elf64_Xword p_memsz;		/* Segment size in memory */
  Elf64_Xword p_align;		/* Segment alignment, file & memory */
} Elf64_Phdr;
{% endhighlight %}

`p_type` can have values such as `PT_LOAD`, `PT_DYNAMIC`, `PT_INTERP` etc.

When loading an ELF binary, the linux kernel looks for `PT_LOAD` segments
and [maps them into memory][kernel-map-segments] (among other things). When doing so, it
uses both `p_offset` (segment file offset) and `p_vaddr` (the address where to map
the segment into memory). ELF segments can overlap in the file. Usually, there are 2 `PT_LOAD`
segments - 1 for code (R-X) and 1 for data (RW-). There can also be just 1 or more than 2.
Whenever a virtual address needs to be converted to a file offset, it can be done like this:

{% highlight c %}
for(int i = 0; i < ehdr->e_phnum; i++) {
        if(seg[i].p_type != PT_LOAD)
                continue;

        if(va >= seg[i].p_vaddr && va < seg[i].p_vaddr + seg[i].p_memsz) {
                offset = seg[i].p_offset + (va - seg[i].p_vaddr);
        }
}
{% endhighlight %}

When you dynamically link an ELF, `PT_DYNAMIC` can be found in the program header table
of the resulting binary. It usually belongs to the second `PT_LOAD` segment, therefore it is loaded
into memory. `PT_INTERP` specifies the dynamic interpreter and the kernel is very [sensitive]
[interp] about it. 

`PT_DYNAMIC` is an array of dynamic entries:

{% highlight c %}
typedef struct {
  Elf64_Sxword d_tag;		/* entry tag value */
  union {
    Elf64_Xword d_val;
    Elf64_Addr d_ptr;
  } d_un;
} Elf64_Dyn;
{% endhighlight %}

`d_tag` is the [type][dynamic-type] of the dynamic entry. Dynamic entries contain vital information
for the dynamic linker. Information such as symbol relocations to figure out what API are you
trying to call (simplified) etc.

## Case: executable binaries

Let's compile a program and look at it with [radare2][radare-git] (always use the git version)!
I am using radare on OS X:

{% highlight bash %}
$ r2 -v
radare2 0.10.2-git 10555 @ darwin-little-x86-64 git.0.10.1-99-g747699f
commit: 747699f712d7cc0402b20c9313a16634e68d7764 build: 2016-03-11
{% endhighlight %}

{% highlight c %}
#include <fcntl.h>
#include <unistd.h>

int main()
{
        int fd = open("hello", O_CREAT | O_TRUNC | O_WRONLY);
        
        if(fd > 0) {
                write(fd, "world", 5);
                close(fd);
        }
        
        return 0;
}
{% endhighlight %}

I am using `gcc (Debian 4.9.2-10) 4.9.2` `ldd (Debian GLIBC 2.19-18+deb8u3) 2.19 `on `Debian 8.3 x64`.


Compile it (it should be dynamically linked unless given `-static`) and check its size:
{% highlight bash %}
$ gcc myprogram.c -o myprogram
$ wc --bytes myprogram
6992
{% endhighlight %}

Use sstrip and check its size:
{% highlight bash %}
$ sstrip myprogram
$ wc --bytes myprogram
2528
{% endhighlight %}

{% highlight radare %}
$ r2 -A myprogram

[0x004004a0]> iS
[Sections]
idx=00 vaddr=0x004003a0 paddr=0x000003a0 sz=120 vsz=120 perm=----- name=.rela.plt
idx=01 vaddr=0x00400388 paddr=0x00000388 sz=24 vsz=24 perm=----- name=.rel.plt
idx=02 vaddr=0x00600990 paddr=0x00000990 sz=120 vsz=120 perm=----- name=.got.plt
idx=03 vaddr=0x00400040 paddr=0x00000040 sz=448 vsz=448 perm=m-r-x name=PHDR
idx=04 vaddr=0x00400200 paddr=0x00000200 sz=28 vsz=28 perm=m-r-- name=INTERP
idx=05 vaddr=0x00400000 paddr=0x00000000 sz=1948 vsz=1948 perm=m-r-x name=LOAD0
idx=06 vaddr=0x006007a0 paddr=0x000007a0 sz=576 vsz=584 perm=m-rw- name=LOAD1
idx=07 vaddr=0x006007b8 paddr=0x000007b8 sz=464 vsz=464 perm=m-rw- name=DYNAMIC
idx=08 vaddr=0x0040021c paddr=0x0000021c sz=68 vsz=68 perm=m-r-- name=NOTE
idx=09 vaddr=0x00400670 paddr=0x00000670 sz=52 vsz=52 perm=m-r-- name=GNU_EH_FRAME
idx=10 vaddr=0x00000000 paddr=0x00000000 sz=0 vsz=0 perm=m-rw- name=GNU_STACK
idx=11 vaddr=0x00400000 paddr=0x00000000 sz=64 vsz=64 perm=m-rw- name=ehdr

12 sections

[0x004004a0]> ir
[Relocations]
vaddr=0x006009a8 paddr=0x000009a8 type=SET_64 write
vaddr=0x006009b0 paddr=0x000009b0 type=SET_64 close
vaddr=0x006009b8 paddr=0x000009b8 type=SET_64 __libc_start_main
vaddr=0x006009c0 paddr=0x000009c0 type=SET_64 __gmon_start__
vaddr=0x006009c8 paddr=0x000009c8 type=SET_64 open
vaddr=0x00600988 paddr=0x00000988 type=SET_64 __gmon_start__

6 relocations

0x004004a0]> pdf @ main
╒ (fcn) main 74
│           ; var int local_0h     @ rbp-0x0
│           ; var int local_4h     @ rbp-0x4
│           ; DATA XREF from 0x004004bd (main)
│           0x00400596      55             push rbp
│           0x00400597      4889e5         mov rbp, rsp
│           0x0040059a      4883ec10       sub rsp, 0x10
│           0x0040059e      be41020000     mov esi, 0x241
│           0x004005a3      bf64064000     mov edi, 0x400664
│           0x004005a8      b800000000     mov eax, 0
│           0x004005ad      e8defeffff     call sym.imp.open
│           0x004005b2      8945fc         mov dword [rbp - local_4h], eax
│           0x004005b5      837dfc00       cmp dword [rbp - local_4h], 0
│       ┌─< 0x004005b9      7e1e           jle 0x4005d9
│       │   0x004005bb      8b45fc         mov eax, dword [rbp - local_4h]
│       │   0x004005be      ba05000000     mov edx, 5
│       │   0x004005c3      be6a064000     mov esi, 0x40066a
│       │   0x004005c8      89c7           mov edi, eax
│       │   0x004005ca      e881feffff     call sym.imp.write
│       │   0x004005cf      8b45fc         mov eax, dword [rbp - local_4h]
│       │   0x004005d2      89c7           mov edi, eax
│       │   0x004005d4      e887feffff     call sym.imp.close
{% endhighlight %}

Alright. Radare can clearly see what APIs are we trying to call. In short - radare
used the information contained within the dynamic entries (relocations, dynamic symbol table,
dynamic string table etc.) to figure it out.

Let's try and use `readelf` utility.

{% highlight radare %}
$ readelf -r myprogram

There are no relocations in this file.
{% endhighlight %}

Oops. `readelf` by default relies on `section header table` (which we took away) - __first mistake__, but this *feature* has been
known for a while. You have to force it to use `PT_DYNAMIC`, not the section `.dynamic`,

{% highlight radare %}
$ readelf -D -r myprogram

'RELA' relocation section at offset 0x400388 contains 24 bytes:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000600988  000400000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0

'PLT' relocation section at offset 0x4003a0 contains 120 bytes:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
0000006009a8  000100000007 R_X86_64_JUMP_SLO 0000000000000000 write + 0
0000006009b0  000200000007 R_X86_64_JUMP_SLO 0000000000000000 close + 0
0000006009b8  000300000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main + 0
0000006009c0  000400000007 R_X86_64_JUMP_SLO 0000000000000000 __gmon_start__ + 0
0000006009c8  000500000007 R_X86_64_JUMP_SLO 0000000000000000 open + 0
{% endhighlight %}

__But how do they load the dynamic entries from the file?__

They use `PT_DYNAMIC`'s `p_offset` - the file offset.

Is this correct? Well..

Let's jump into [010 Editor][010editor], load our program and use [Tim Strazzere's ELF template][tim-elf] 
(the one on their website is fairly outdated) to change the `p_offset` field of `PT_DYNAMIC` to `0x0`.

![p_offset is 0]({{ site.url }}/assets/dynamic_zero.png)

Run it.

{% highlight radare %}
$ strace ./myprogram
open("hello", O_WRONLY|O_CREAT|O_TRUNC, 03777714751741270) = 3
write(3, "world", 5)                    = 5
close(3)                                = 0
{% endhighlight %}

That works. Let's check radare.

{% highlight radare %}
$ r2 -A myprogram

0x004004a0]> iS
[Sections]
idx=00 vaddr=0x00400040 paddr=0x00000040 sz=448 vsz=448 perm=m-r-x name=PHDR
idx=01 vaddr=0x00400200 paddr=0x00000200 sz=28 vsz=28 perm=m-r-- name=INTERP
idx=02 vaddr=0x00400000 paddr=0x00000000 sz=1948 vsz=1948 perm=m-r-x name=LOAD0
idx=03 vaddr=0x006007a0 paddr=0x000007a0 sz=576 vsz=584 perm=m-rw- name=LOAD1
idx=04 vaddr=0x006007b8 paddr=0x00000000 sz=464 vsz=464 perm=m-rw- name=DYNAMIC
idx=05 vaddr=0x0040021c paddr=0x0000021c sz=68 vsz=68 perm=m-r-- name=NOTE
idx=06 vaddr=0x00400670 paddr=0x00000670 sz=52 vsz=52 perm=m-r-- name=GNU_EH_FRAME
idx=07 vaddr=0x00000000 paddr=0x00000000 sz=0 vsz=0 perm=m-rw- name=GNU_STACK
idx=08 vaddr=0x00400000 paddr=0x00000000 sz=64 vsz=64 perm=m-rw- name=ehdr

9 sections

[0x004004a0]> ir
[Relocations]

0 relocations

[0x004004a0]> pdf @ main
╒ (fcn) main 74
│           ; var int local_0h     @ rbp-0x0
│           ; var int local_4h     @ rbp-0x4
│           ; DATA XREF from 0x004004bd (main)
│           0x00400596      55             push rbp
│           0x00400597      4889e5         mov rbp, rsp
│           0x0040059a      4883ec10       sub rsp, 0x10
│           0x0040059e      be41020000     mov esi, 0x241
│           0x004005a3      bf64064000     mov edi, 0x400664
│           0x004005a8      b800000000     mov eax, 0
│           0x004005ad      e8defeffff     call fcn.00400490
│           0x004005b2      8945fc         mov dword [rbp - local_4h], eax
│           0x004005b5      837dfc00       cmp dword [rbp - local_4h], 0
│       ┌─< 0x004005b9      7e1e           jle 0x4005d9
│       │   0x004005bb      8b45fc         mov eax, dword [rbp - local_4h]
│       │   0x004005be      ba05000000     mov edx, 5
│       │   0x004005c3      be6a064000     mov esi, 0x40066a
│       │   0x004005c8      89c7           mov edi, eax
│       │   0x004005ca      e881feffff     call fcn.00400450
│       │   0x004005cf      8b45fc         mov eax, dword [rbp - local_4h]
│       │   0x004005d2      89c7           mov edi, eax
│       │   0x004005d4      e887feffff     call fcn.00400460
{% endhighlight %}

`PT_DYNAMIC` `p_offset` is `0x0`, radare shows no relocations. 

To demonstrate with `readelf`:

{% highlight radare %}
$ readelf -D -r myprogram

'RELA' relocation section at offset 0x0 contains 17179869188 bytes:
readelf: Warning: Virtual address 0x0 not located in any PT_LOAD segment.
readelf: Error: Reading 0x400000004 bytes extends past end of file for 64-bit relocation data
{% endhighlight %}

[Radare2][radare-bug] uses `p_offset`.
[LLVM][llvm-elf] uses `p_offset`.

The linux kernel does not really care about the dynamic segment, but looking for `PT_DYNAMIC` identifier on [LXR][lxr] you can find [this][kernel-dynamic] for example.
FreeBSD is doing it [too][freebsd-dynamic]. [Glibc][glibc-dynamic] and IDA as well.

The general consensus seems to be that calculating the offset of the `dynamic table` should be done
through its virtual address just like you would when converting a virtual address to an offset:

{% highlight radare %}
offset = 0x7A0 + (0x6007B8 - 0x6007A0) = 0x7B8
{% endhighlight %}

__Is this it?__

Yes. Well, except maybe adding another `dynamic table` with a personal touch at the end of the file..

![Change dynamic]({{ site.url }}/assets/change_dynamic.png)
![Change JMPREL]({{ site.url }}/assets/010_jmprel_r2.png)

{% highlight radare %}
$ readelf -D --dynamic myprogram

Dynamic section at offset 0x9e0 contains 24 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x400418
 0x000000000000000d (FINI)               0x400654
 0x0000000000000019 (INIT_ARRAY)         0x6007a0
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x6007a8
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x400260
 0x0000000000000005 (STRTAB)             0x400310
 0x0000000000000006 (SYMTAB)             0x400280
 0x000000000000000a (STRSZ)              73 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x600990
 0x0000000000000002 (PLTRELSZ)           120 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 ==> 0x0000000000000017 (JMPREL)             0xffffffff
 0x0000000000000007 (RELA)               0x400388
 0x0000000000000008 (RELASZ)             24 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffffe (VERNEED)            0x400368
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x40035a
 0x0000000000000000 (NULL)               0x0
{% endhighlight %}

{% highlight radare %}
$ readelf -D -r myprogram

'RELA' relocation section at offset 0x400388 contains 24 bytes:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000600988  000400000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0

'PLT' relocation section at offset 0xffffffff contains 120 bytes:
readelf: Warning: Virtual address 0xffffffff not located in any PT_LOAD segment.
readelf: Error: Reading 0x78 bytes extends past end of file for 64-bit relocation data
{% endhighlight %}

{% highlight radare %}
$ strace ./myprogram
open("hello", O_WRONLY|O_CREAT|O_TRUNC, 03777722565300410) = 3
write(3, "world", 5)                    = 5
close(3)                                = 0
{% endhighlight %}

## Shared libraries

Sample shared library, let's call it `libtest.c`:
{% highlight c %}
#include <stdio.h>

void __attribute__((constructor)) foo()
{
        puts("bar");
}
{% endhighlight %}

{% highlight bash %}
$ gcc -fPIC -shared libtest.c -o libtest.so
$ sstrip libtest.so
{% endhighlight %}

Try to run it with our previous `myprogram`:
{% highlight bash %}
$ strace -E LD_PRELOAD=./libtest.so ./myprogram
write(1, "bar\n", 4bar
)                    = 4
open("hello", O_WRONLY|O_CREAT|O_TRUNC, 03777601547305710) = 3
write(3, "world", 5)                    = 5
close(3)                                = 0
{% endhighlight %}

Check disassembly of `foo` symbol in radare:
{% highlight radare %}
[0x000005b0]> pdf @ sym.foo
╒ (fcn) sym.foo 18
│           0x000006b0      55             push rbp
│           0x000006b1      4889e5         mov rbp, rsp
│           0x000006b4      488d3d120000.  lea rdi, [rip + 0x12]       ; 0x6cd
│           0x000006bb      e8c0feffff     call sym.imp.puts
│           0x000006c0      5d             pop rbp
╘           0x000006c1      c3             ret
{% endhighlight %}

Change `PT_DYNAMIC` `p_offset` to `0x0`:

![Change shared dynamic offset]({{ site.url }}/assets/change_shared_dynamic.png)

Run again..
{% highlight bash %}
$ strace -E LD_PRELOAD=./libtest.so ./myprogram
write(1, "bar\n", 4bar
)                    = 4
open("hello", O_WRONLY|O_CREAT|O_TRUNC, 03777751564430010) = 3
write(3, "world", 5)                    = 5
close(3)                                = 0
{% endhighlight %}

Now take a look again with radare:

{% highlight radare %}
[0x000005b0]> iS
[Sections]
idx=00 vaddr=0x00000000 paddr=0x00000000 sz=1876 vsz=1876 perm=m-r-x name=LOAD0
idx=01 vaddr=0x00200758 paddr=0x00000758 sz=576 vsz=584 perm=m-rw- name=LOAD1
idx=02 vaddr=0x00200778 paddr=0x00000000 sz=448 vsz=448 perm=m-rw- name=DYNAMIC
idx=03 vaddr=0x00000190 paddr=0x00000190 sz=36 vsz=36 perm=m-r-- name=NOTE
idx=04 vaddr=0x000006d4 paddr=0x000006d4 sz=28 vsz=28 perm=m-r-- name=GNU_EH_FRAME
idx=05 vaddr=0x00000000 paddr=0x00000000 sz=0 vsz=0 perm=m-rw- name=GNU_STACK
idx=06 vaddr=0x00000000 paddr=0x00000000 sz=64 vsz=64 perm=m-rw- name=ehdr

7 sections

[0x000005b0]> is
[Symbols]

0 symbols

[0x000005b0]> ir
[Relocations]

0 relocations

[0x000005b0]> pd 6 @ 0x6b0
            0x000006b0      55             push rbp
            0x000006b1      4889e5         mov rbp, rsp
            0x000006b4      488d3d120000.  lea rdi, [rip + 0x12]       ; 0x6cd
            0x000006bb      e8c0feffff     call fcn.00000580
            0x000006c0      5d             pop rbp
            0x000006c1      c3             ret
{% endhighlight %}

You can probably tell where I am going with this.

## Implications

I think it's a nice trick to fool some popular tools and newbie reversers. :-) Also somewhat
helpful if you are parsing ELF in your tool.

There are more things that can be done, but this post is way longer than I expected. Maybe next time.

Note: if I remember correctly, there was a CTF that used 2 dynamic string tables. One was
referenced from the dynamic table where `PT_DYNAMIC` pointed to and the other from the `.dynamic` section.
This caused some tools to show wrong APIs. If someone finds a link, let me know and I will update the post.

Thanks for reading!

__UPDATE:__

Radare2 [addressed][radare-fix] this issue!

{% highlight radare %}
$ r2 -v
radare2 0.10.2-git 10577 @ darwin-little-x86-64 git.0.10.1-121-g1c443ca
commit: 1c443caccfcfbad0b25dd2c28acb6d3d70d8dd10 build: 2016-03-13
{% endhighlight %}

![p_offset is 0]({{ site.url }}/assets/dynamic_zero.png)

{% highlight radare %}
$ r2 -A myprogram

[0x004004a0]> iS
[Sections]
idx=00 vaddr=0x004003a0 paddr=0x000003a0 sz=120 vsz=120 perm=----- name=.rela.plt
idx=01 vaddr=0x00400388 paddr=0x00000388 sz=24 vsz=24 perm=----- name=.rel.plt
idx=02 vaddr=0x00600990 paddr=0x00000990 sz=120 vsz=120 perm=----- name=.got.plt
idx=03 vaddr=0x00400040 paddr=0x00000040 sz=448 vsz=448 perm=m-r-x name=PHDR
idx=04 vaddr=0x00400200 paddr=0x00000200 sz=28 vsz=28 perm=m-r-- name=INTERP
idx=05 vaddr=0x00400000 paddr=0x00000000 sz=1948 vsz=1948 perm=m-r-x name=LOAD0
idx=06 vaddr=0x006007a0 paddr=0x000007a0 sz=576 vsz=584 perm=m-rw- name=LOAD1
idx=07 vaddr=0x006007b8 paddr=0x00000000 sz=464 vsz=464 perm=m-rw- name=DYNAMIC
idx=08 vaddr=0x0040021c paddr=0x0000021c sz=68 vsz=68 perm=m-r-- name=NOTE
idx=09 vaddr=0x00400670 paddr=0x00000670 sz=52 vsz=52 perm=m-r-- name=GNU_EH_FRAME
idx=10 vaddr=0x00000000 paddr=0x00000000 sz=0 vsz=0 perm=m-rw- name=GNU_STACK
idx=11 vaddr=0x00400000 paddr=0x00000000 sz=64 vsz=64 perm=m-rw- name=ehdr

12 sections

[0x004004a0]> ir
[Relocations]
vaddr=0x006009a8 paddr=0x000009a8 type=SET_64 write
vaddr=0x006009b0 paddr=0x000009b0 type=SET_64 close
vaddr=0x006009b8 paddr=0x000009b8 type=SET_64 __libc_start_main
vaddr=0x006009c0 paddr=0x000009c0 type=SET_64 __gmon_start__
vaddr=0x006009c8 paddr=0x000009c8 type=SET_64 open
vaddr=0x00600988 paddr=0x00000988 type=SET_64 __gmon_start__

6 relocations

[0x004004a0]> pdf @ main
╒ (fcn) main 74
│           ; var int local_0h     @ rbp-0x0
│           ; var int local_4h     @ rbp-0x4
│           ; DATA XREF from 0x004004bd (main)
│           0x00400596      55             push rbp
│           0x00400597      4889e5         mov rbp, rsp
│           0x0040059a      4883ec10       sub rsp, 0x10
│           0x0040059e      be41020000     mov esi, 0x241
│           0x004005a3      bf64064000     mov edi, 0x400664
│           0x004005a8      b800000000     mov eax, 0
│           0x004005ad      e8defeffff     call sym.imp.open
│           0x004005b2      8945fc         mov dword [rbp - local_4h], eax
│           0x004005b5      837dfc00       cmp dword [rbp - local_4h], 0
│       ┌─< 0x004005b9      7e1e           jle 0x4005d9
│       │   0x004005bb      8b45fc         mov eax, dword [rbp - local_4h]
│       │   0x004005be      ba05000000     mov edx, 5
│       │   0x004005c3      be6a064000     mov esi, 0x40066a
│       │   0x004005c8      89c7           mov edi, eax
│       │   0x004005ca      e881feffff     call sym.imp.write
│       │   0x004005cf      8b45fc         mov eax, dword [rbp - local_4h]
│       │   0x004005d2      89c7           mov edi, eax
│       │   0x004005d4      e887feffff     call sym.imp.close
│       │   ; JMP XREF from 0x004005b9 (main)
│       └─> 0x004005d9      b800000000     mov eax, 0
│           0x004005de      c9             leave
╘           0x004005df      c3             ret
{% endhighlight %}

[radare-fix]: https://github.com/radare/radare2/issues/4302
[radare-git]: https://github.com/radare/radare2
[roopre]: https://www.virusbulletin.com/virusbulletin/2014/07/mayhem-hidden-threat-nix-web-servers
[glibc-dynamic]: https://code.woboq.org/userspace/glibc/elf/rtld.c.html#1025
[freebsd-dynamic]: https://github.com/freebsd/freebsd/blob/master/sys/boot/common/load_elf.c#L595
[kernel-dynamic]: http://lxr.free-electrons.com/source/fs/binfmt_elf_fdpic.c#L855
[parse-vdso]: http://lxr.free-electrons.com/source/Documentation/vDSO/parse_vdso.c#L123
[lxr]: http://lxr.free-electrons.com/
[llvm-elf]: http://llvm.org/docs/doxygen/html/Object_2ELF_8h_source.html
[radare-bug]: https://github.com/radare/radare2/blob/master/libr/bin/format/elf/elf.c#L305
[tim-elf]: https://github.com/strazzere/010Editor-stuff/blob/master/Templates/ELFTemplate.bt
[010editor]: http://www.sweetscape.com/download/010editor/
[interp]: http://lxr.free-electrons.com/source/fs/binfmt_elf.c#L721
[dynamic-type]: http://lxr.free-electrons.com/source/include/uapi/linux/elf.h#L72
[sstrip]: http://www.muppetlabs.com/~breadbox/software/elfkickers.html
[kernel-load-elf]: http://lxr.free-electrons.com/source/fs/binfmt_elf.c#L665
[kernel-map-segments]: http://lxr.free-electrons.com/source/fs/binfmt_elf.c#L861
[dynamic-linking]: http://sploitfun.blogspot.sk/2013/06/dynamic-linking-internals.html