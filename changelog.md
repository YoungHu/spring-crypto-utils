---
layout: docs
title: ChangeLog
subtitle: The sources, they are a changin'
blurb_title: ChangeLog
blurb: <p>This is what happens between releases.</p>
navbar:
  active_item: docs
---

### release 1.3.6 - (2013-12-19)

* Spring Framework 4.0.0 ready
* JDK 1.6 is now the minimum required version
* <a href="https://github.com/mcaserta/spring-crypto-utils/pull/3">#3</a>
  new: better appliance of the Apache License v2
  (<a href="https://github.com/simonetripodi">Simone Tripodi</a>)


### release 1.3.0 - (2012-08-22)

* <a href="https://github.com/mcaserta/spring-crypto-utils/pull/2">#2</a>
  new: added provider attribute to almost all elements so that
  a custom provider can be configured 
  (think <a href="http://www.bouncycastle.org/java.html">BouncyCastle</a>)
  (<a href="https://github.com/bosakm">Martin Bosak</a>)
* new: the namespace for the whole project has been moved to springcryptoutils.com.
  
  <strong>Migration guide:</strong> a very simple search and 
  replace in your projects will do the trick:
  * in the xml files: <code>http://code.google.com/p/spring-crypto-utils/schema/crypt</code> 
    becomes <code>http://springcryptoutils.com/schema/crypt</code>
  * in the java files: <code>import com.google.code.springcryptoutils</code> becomes
    <code>import com.springcryptoutils</code>
  * <strong>NB:</strong> the maven coordinates are unchanged (they still have
    <code>com.google</code> in the groupId)


### release 1.2.0 - (2012-05-10)

* <a href="https://github.com/mcaserta/spring-crypto-utils/pull/1">#1</a>
  new: added certificate element
  (<a href="https://github.com/iamthechad">Chad Johnston</a>)


### release 1.1.1 - (2012-02-02)

* spring crypto utils is now in
  <a href="http://repo1.maven.org/maven2/com/google/code/spring-crypto-utils/spring-crypto-utils/">maven
  central</a>, so there's no extra repository to setup in the pom.

  If you had previously setup our custom repository, you can safely remove it from your poms now as
  all previous versions have also been uploaded to central. There are no source code changes in
  this release.


### release 1.1.0 - (2012-01-29)

* fix: non-existant alias name should throw an error
* new: added crypt:secretKey element
* new: added support for mac (message authentication codes)


### release 1.0.1 - (2012-01-25)

* new: added support for configuring a keystore using conventional java system properties
  <code>javax.net.ssl.keyStore</code> and <code>javax.net.ssl.keyStorePassword</code> through the
  <code>&lt;crypt:defaultKeystore/&gt;</code> configuration element


### release 1.0.0 - (2011-09-15)

* first public stable release