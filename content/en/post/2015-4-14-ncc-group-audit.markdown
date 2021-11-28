---
author: Josh Aas, ISRG Executive Director
date: 2015-04-14T00:00:00Z
excerpt: ISRG has engaged the NCC Group Crypto Services team to perform a security
  review of Let's Encrypt's certificate authority software, boulder, and the ACME
  protocol.
title: ISRG Engages NCC Group for Let's Encrypt Audit
slug: ncc-group-audit
---

ISRG has engaged the [NCC Group Crypto Services team](https://cryptoservices.github.io/) to perform a security review of Let's Encrypt's certificate authority software, [boulder](https://github.com/letsencrypt/boulder), and the [ACME protocol](https://tools.ietf.org/html/rfc8555). NCC Group's team was selected due to their strong reputation for cryptography expertise, which brought together Matasano Security, iSEC Partners, and Intrepidus Group.

The NCC Group audit will take place prior to the general availability of Let's Encrypt's service, and is intended to provide additional assurance that our systems are secure. The NCC Group audit does not replace the WebTrust audit, which will happen after general availability.

"I'm very much looking forward to the general availability of Let’s Encrypt - lowering the bar both technically and financially for people to deploy TLS will result in a more encrypted Internet that helps increase security and preserve people's privacy," said Tom Ritter, Practice Director, NCC Group.

Let's Encrypt's certificate authority software is called [boulder](https://github.com/letsencrypt/boulder). It's largely written in the go language and makes use of CloudFlare's [CFSSL](https://github.com/cloudflare/cfssl) tools, which are also written in go. Our boulder software contains modules including a web front-end and registration, validation, certificate, and storage authorities.

[ACME](https://github.com/letsencrypt/acme-spec/), short for Automated Certificate Management Environment, is the protocol that Let's Encrypt will use for automatic certificate issuance and management. We hope to standardize ACME in the [IETF](https://www.ietf.org/), starting with the formation of a working group later this year.
