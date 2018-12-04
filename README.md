# Overview

This repository contains the junit tests to demonstrate how XStream v1.4.9 respond to the security issues http://x-stream.github.io/CVE-2013-7285.html and http://x-stream.github.io/CVE-2017-7957.html.

# Summary on behaviour through v1.4.7 to v1.4.11.1

A way to deal with CVE_2013_7285 is provided through v1.4.7. But issue again is showed up while fixing CVE-2017-7957 in v1.4.10.

So v1.4.11 is released to fix the broken issue. 

However, it broke the java runtime environments below JDK 8.0. So, v1.4.11.1 is released to address that.


# References

1. http://x-stream.github.io/
2. http://x-stream.github.io/changes.html
3. http://x-stream.github.io/CVE-2017-7957.html
4. http://x-stream.github.io/CVE-2013-7285.html
5. https://github.com/x-stream/xstream/issues/73 - An open issue seemed to exist for a long time with HibernateMapper
6. http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/ - blog that details the means to reproduce the violated cases 
7. https://github.com/x-stream/xstream/issues/133 -  Issue caused for v1.4.11.1 release

  