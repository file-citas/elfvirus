elfvirus
========

Self replicating code, which injects itself into the NOTE program header.
It uses magic to locate libc functions inside the infected executalbe.


Build
-----

```
make
```

Usage
-----

The libc used to get the function offsets is hardcoded in the elfvirus.c sourcefile.
So if you run into Problems, it's probably because the target uses a different libc 
than the one the virus gets its offsets from ( which is /lib/i386-linux-gnu/i686/cmov/libc.so.6).

To find out which libc your target uses type:
```
ldd <target binary>
```

If those match, the following should work:

```
cd testdir
make
../elfvirus
mv test infected
make clean && make
./infected
```


Dependencies
------------

* gcc-multilib
* libc6-dev:i386
* libelf


TODO
----

* get target libc path
* support 64bit binaries
