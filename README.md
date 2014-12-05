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
