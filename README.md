# Python Log4RCE

An all-in-one pure Python3 PoC for [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228).

## Configure

Replace the global variables at the top of the script to your configuration. 

## Run

All you need is to run with any `python3` install:

```
python3 ./log4rce.py
```

## Java

If you want to run your own Java script, you can recompile it and insert it in the `PAYLOAD`. We can use `./java/Exploit.java` as example.

```bash
javac ./java/Exploit.java
python3 -c 'print(open("./java/Exploit.class", "rb").read())'
```

Copy the output of the previous in the `JAVA_CLASSES` dict. It can be select through the `OS` global variable.
