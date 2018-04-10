# transition

![](https://img.shields.io/badge/Python-3.6-0086CC.svg)

let you visit localhost behind NAT or Firewall

*It need Python 3.6 and above*

### Usage

run master in you server which have public ip address (For example `134.233.56.79`)

```
$ python master.py -t 0.0.0.0:25362 -b 0.0.0.0:8080
```

run slave in localhost

```
$ python slave.py -t 134.233.56.79:25362 -d localhost:80
```

Then, visit `134.233.56.79:8080`, you will see the same page as `localhost:80`

Of course, it's just forwarding TCP traffic. You can use any application layer protocol at will.

### License
MIT
