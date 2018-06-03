# rikka

[![Build Status](https://travis-ci.org/Hanaasagi/rikka.svg?branch=master)](https://travis-ci.org/Hanaasagi/rikka)
![](https://img.shields.io/badge/Python-3.6-0086CC.svg)
![](https://img.shields.io/badge/version-beta-EB6EA5.svg)

Let you visit localhost behind NAT or Firewall

*It need Python 3.6 and above*

### Usage

run master in you server which have public ip address (for example `134.233.56.79`)

```Bash
$ rkserver -t 0.0.0.0:25362 -b 0.0.0.0:8080
```

run slave in localhost

```Bash
$ rklocal -t 134.233.56.79:25362 -d localhost:80
```

Then, visit `134.233.56.79:8080`, you will see the same page as `localhost:80`

Of course, it's just forwarding TCP traffic transparently. You can use any application layer protocol at will.

### Why rikka

rikka a word from Japanese that means "snow".

![](https://i.imgur.com/tskQvea.png)

### License
MIT
