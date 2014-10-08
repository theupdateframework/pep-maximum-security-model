Title: Surviving a Compromise of PyPI: The Maximum Security Model
Version: $Revision$
Last-Modified: $Date$
Author: Trishank Karthik Kuppusamy <trishank@nyu.edu>,
Donald Stufft <donald@stufft.io>, Justin Cappos <jcappos@nyu.edu>,
Vladimir Diaz <vladimir.v.diaz@gmail.com>

BDFL-Delegate: Nick Coghlan <ncoghlan@gmail.com>
Discussions-To: DistUtils mailing list <distutils-sig@python.org>
Status: Draft
Type: Standards Track
Content-Type: text/x-rst
Created: 8-Oct-2014


Abstract
========

This PEP proposes how the Python Package Index (PyPI [1]_) should be integrated
with The Update Framework [2]_ (TUF).  TUF was designed to be a flexible
security add-on to a software updater or package manager.  The framework
integrates best security practices such as separating role responsibilities,
adopting the many-man rule for signing packages, keeping signing keys offline,
and revocation of expired or compromised signing keys.  For example, attackers
would have to steal multiple signing keys stored independently to compromise
a role responsible for specifying a repository's available files.  Another role
responsible for indicating the latest snapshot of the repository may have to be
similarly compromised, and independent of the first compromised role.

The proposed integration will allow modern package managers such as pip [3]_ to
be more secure against various types of security attacks on PyPI and protect
users from such attacks.  Specifically, this PEP describes how PyPI processes
should be adapted to generate and incorporate TUF metadata (i.e., the minimum
security model).  The minimum security model supports verification of PyPI
distributions that are signed with keys stored on PyPI: distributions uploaded
by developers are signed by PyPI, require no action from developers (other
than uploading the distribution), and are immediately available for download.  The
minimum security model also minimizes PyPI administrative responsibilities by
automating much of the signing process.

This PEP does not prescribe how package managers such as pip should be adapted
to install or update projects from PyPI with TUF metadata.   Package managers
interested in adopting TUF on the client side may consult TUF's `library
documentation`__, which exists for this purpose.  Support for project
distributions that are signed by developers (maximum security model) is also
not discussed in this PEP, but is outlined in the appendix as a possible future
extension and covered in detail in PEP XXX [VD: Link to PEP once it is
completed].  The PEP XXX extension focuses on the maximum security model, which
requires more PyPI administrative work (none by clients), but it also proposes 
an easy-to-use key management solution for developers, how to interface with
a potential future build farm on PyPI infrastructure, and discusses the
feasibility of end-to-end signing.

__ https://github.com/theupdateframework/tuf/tree/develop/tuf/client#updaterpy


Rationale
=========





Threat Model
============

The threat model assumes the following:

* Offline keys are safe and securely stored.

* Attackers can compromise at least one of PyPI's trusted keys stored online,
  and may do so at once or over a period of time.

* Attackers can respond to client requests.

An attacker is considered successful if they can cause a client to install (or
leave installed) something other than the most up-to-date version of the
software the client is updating. If the attacker is preventing the installation
of updates, they want clients to not realize there is anything wrong.


Definitions
===========

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119__.

__ http://www.ietf.org/rfc/rfc2119.txt

This PEP focuses on the application of TUF on PyPI; however, the reader is
encouraged to read about TUF's design principles [2]_.  It is also RECOMMENDED
that the reader be familiar with the TUF specification [16]_.

Terms used in this PEP are defined as follows:

* Projects: Projects are software components that are made available for
  integration.  Projects include Python libraries, frameworks, scripts,
  plugins, applications, collections of data or other resources, and various
  combinations thereof.  Public Python projects are typically registered on the
  Python Package Index [17]_.

* Releases: Releases are uniquely identified snapshots of a project [17]_.

* Distributions: Distributions are the packaged files that are used to publish
  and distribute a release [17]_.

* Simple index: The HTML page that contains internal links to the
  distributions of a project [17]_.

* Metadata: Metadata are signed files that describe roles, other metadata, and
  target files.

* Repository: A repository is a source of named metadata and target files.
  Clients request metadata and target files stored on a repository.

* Consistent snapshot: A set of TUF metadata and PyPI targets that capture the
  complete state of all projects on PyPI as they were at some fixed point in
  time.

* The *snapshot* (*release*) role: In order to prevent confusion due
  to the different meanings of the term "release" as employed by PEP 426 [17]_
  and the TUF specification [16]_, the *release* role is renamed as the
  *snapshot* role.
  
* Developer: Either the owner or maintainer of a project who is allowed to
  update the TUF metadata as well as distribution metadata and files for the
  project.

* Online key: A private cryptographic key that MUST be stored on the PyPI
  server infrastructure.  This is usually to allow automated signing with the
  key.  However, an attacker who compromises the PyPI infrastructure will be
  able to read these keys.

* Offline key: A private cryptographic key that MUST be stored independent of
  the PyPI server infrastructure.  This prevents automated signing with the
  key.  An attacker who compromises the PyPI infrastructure will not be able to
  immediately read these keys.

* Threshold signature scheme: A role can increase its resilience to key
  compromises by specifying that at least t out of n keys are REQUIRED to sign
  its metadata.  A compromise of t-1 keys is insufficient to compromise the
  role itself.  Saying that a role requires (t, n) keys denotes the threshold
  signature property.


Minimum Security Model


There are two security models to consider when integrating TUF with PyPI.  The
one proposed in this PEP is the minimum security model, which supports
verification of PyPI distributions that are signed with private cryptographic
keys stored on PyPI.  Distributions uploaded by developers are signed by PyPI
and immediately available for download.  A possible future extension to this
PEP, discussed in Appendix B, proposes the maximum security model and allows a
developer to sign for his/her project.  Developer keys are not stored online:
therefore, projects are safe from PyPI compromises.

The minimum security model requires no action from a developer and protects
against malicious CDNs [19]_ and public mirrors.  To support continuous
delivery of uploaded packages, PyPI signs for projects with an online key.
This level of security prevents projects from being accidentally or
deliberately tampered with by a mirror or a CDN because the mirror or CDN will
not have any of the keys required to sign for projects.  However, it does not
protect projects from attackers who have compromised PyPI, since attackers can
manipulate TUF metadata using the keys stored online.   

This PEP proposes that the *bins* role (and its delegated roles) sign for all
PyPI projects with an online key.  The *targets* role, which only signs with an
offline key, MUST delegate all PyPI projects to the *bins* role.  This means
that when a package manager such as pip (i.e., using TUF) downloads a
distribution from a project on PyPI, it will consult the *bins* role about the
TUF metadata for the project.  If no bin roles delegated by *bins* specify the
project's distribution, then the project is considered to be non-existent on
PyPI.


Extension to the Minimum Security Model
=======================================

The maximum security model and end-to-end signing have been intentionally
excluded from this PEP.  Although both improve PyPI's ability to survive a
repository compromise and allow developers to sign their distributions, they
have been postponed for review as a potential future extension to PEP 458.  PEP
XXX [VD: Link to PEP once it is completed], which discusses the extension in
detail, is available for review to those developers interested in the
end-to-end signing option.  The maximum security model and end-to-end signing
are briefly covered in subsections that follow.

There are several reasons for not initially supporting the features discussed
in this section:

1. A build farm (distribution wheels on supported platforms are generated on
   PyPI infrastructure for each project) may possibly complicate matters.  PyPI
   wants to support a build farm in the future.  Unfortunately, if wheels are
   auto-generated externally, developer signatures for these wheels are
   unlikely.  However, there might still be a benefit to generating wheels from
   source distributions that *are* signed by developers (provided that reproducible
   wheels are possible).  Another possibility is to optionally delegate trust
   of these wheels to an online role.

2. An easy-to-use key management solution is needed for developers.
   `miniLock`__ is one likely candidate for management and generation of keys.
   Although developer signatures can be left as an option, this approach may be
   insufficient due to the great number of unsigned dependencies that can occur
   for a signed distribution requested by a client.  Requiring developers to
   manually sign distributions and manage keys is expected to render key
   signing an unused feature.

__ https://minilock.io/

3. A two-phase approach, where the minimum security model is implemented first
   followed by the maximum security model, can simplify matters and give PyPI
   administrators time to review the feasibility of end-to-end signing.


Maximum Security Model
----------------------

The maximum security model relies on developers signing their projects and
uploading signed metadata to PyPI.  If the PyPI infrastructure were to be
compromised, attackers would be unable to serve malicious versions of claimed
projects without access to the project's developer key.  Figure 3 depicts the
changes made to figure 2, namely that developer roles are now supported and
that three new delegated roles exist: *claimed*, *recently-claimed*, and
*unclaimed*.  The *bins* role has been renamed *unclaimed* and can contain any
projects that have not been added to *claimed*.  The strength of this model
(over the minimum security model) is in the offline keys provided by
developers.  Although the minimum security model supports continuous delivery,
all of the projects are signed by an online key.  An attacker can corrupt
packages in the minimum security model, but not in the maximum model without
also compromising a developer's key.

.. image:: figure1.png

Figure 3: An overview of the metadata layout in the maximum security model.
The maximum security model supports continuous delivery and survivable key
compromise.


End-to-End Signing
------------------

End-to-End signing allows both PyPI and developers to sign for the metadata
downloaded by clients.  PyPI is trusted to make uploaded projects available to
clients (they sign the metadata for this part of the process), and developers
can sign the distributions that they upload.

PEP XXX [VD: Link to PEP once it is completed] discusses the tools available to
developers who sign the distributions that they upload to PyPI.  To summarize
PEP XXX, developers generate cryptographic keys and sign metadata in some
automated fashion, where the metadata includes the information required to
verify the authenticity of the distribution.  The metadata is then uploaded to
PyPI by the client, where it will be available for download by package managers
such as pip (i.e., package managers that support TUF metadata).  The entire
process is transparent to clients (using a package manager that supports TUF)
who download distributions from PyPI.


Producing Consistent Snapshots
------------------------------

Given a project, PyPI is responsible for updating the *bins* metadata (roles
delegated by the *bins* role and signed with an online key).  Every project
MUST upload its release in a single transaction.  The uploaded set of files is
called the "project transaction".  How PyPI MAY validate the files in a project
transaction is discussed in a later section.  For now, the focus is on how PyPI
will respond to a project transaction.

Every metadata and target file MUST include in its filename the `hex digest`__
of its `SHA-256`__ hash.  For this PEP, it is RECOMMENDED that PyPI adopt a
simple convention of the form: digest.filename, where filename is the original
filename without a copy of the hash, and digest is the hex digest of the hash.

__ http://docs.python.org/2/library/hashlib.html#hashlib.hash.hexdigest
__ https://en.wikipedia.org/wiki/SHA-2

When a project uploads a new transaction, the project transaction process MUST
add all new targets and relevant delegated *bins* metadata.  (It is shown later
in this section why the *bins* role will delegate targets to a number of
delegated *bins* roles.)  Finally, the project transaction process MUST inform
the snapshot process about new delegated *bins* metadata.

Project transaction processes SHOULD be automated and MUST also be applied
atomically: either all metadata and targets -- or none of them -- are added.
The project transaction and snapshot processes SHOULD work concurrently.
Finally, project transaction processes SHOULD keep in memory the latest *bins*
metadata so that they will be correctly updated in new consistent snapshots.

All project transactions MAY be placed in a single queue and processed
serially.  Alternatively, the queue MAY be processed concurrently in order of
appearance, provided that the following rules are observed:

1. No pair of project transaction processes must concurrently work on the same
   project.

2. No pair of project transaction processes must concurrently work on
   *bins* projects that belong to the same delegated *bins* targets
   role.

These rules MUST be observed so that metadata is not read from or written to
inconsistently.


Snapshot Process
----------------

The snapshot process is fairly simple and SHOULD be automated.  The snapshot
process MUST keep in memory the latest working set of *root*, *targets*, and
delegated roles.  Every minute or so, the snapshot process will sign for this
latest working set.  (Recall that project transaction processes continuously
inform the snapshot process about the latest delegated metadata in a
concurrency-safe manner.  The snapshot process will actually sign for a copy of
the latest working set while the latest working set in memory will be updated
with information that is continuously communicated by the project transaction
processes.)  The snapshot process MUST generate and sign new *timestamp*
metadata that will vouch for the metadata (*root*, *targets*, and delegated
roles) generated in the previous step.  Finally, the snapshot process MUST make
available to clients the new *timestamp* and *snapshot* metadata representing
the latest snapshot.

A few implementation notes are now in order.  So far, we have seen only that
new metadata and targets are added, but not that old metadata and targets are
removed.  Practical constraints are such that eventually PyPI will run out of
disk space to produce a new consistent snapshot.  In that case, PyPI MAY then
use something like a "mark-and-sweep" algorithm to delete sufficiently old
consistent snapshots: in order to preserve the latest consistent snapshot, PyPI
would walk objects beginning from the root (*timestamp*) of the latest
consistent snapshot, mark all visited objects, and delete all unmarked objects.
The last few consistent snapshots may be preserved in a similar fashion.
Deleting a consistent snapshot will cause clients to see nothing except HTTP
404 responses to any request for a file within that consistent snapshot.
Clients SHOULD then retry (as before) their requests with the latest consistent
snapshot.

All clients, such as pip using the TUF protocol, MUST be modified to download
every metadata and target file (except for *timestamp* metadata) by including,
in the request for the file, the cryptographic hash of the file in the
filename.  Following the filename convention recommended earlier, a request for
the file at filename.ext will be transformed to the equivalent request for the
file at digest.filename.

Finally, PyPI SHOULD use a `transaction log`__ to record project transaction
processes and queues so that it will be easier to recover from errors after a
server failure.

__ https://en.wikipedia.org/wiki/Transaction_log


Key Compromise Analysis
=======================

This PEP has covered the minimum security model, the TUF roles that should be
added to support continuous delivery of distributions, and how to generate and
sign the metadata of each role.  The remaining sections discuss how PyPI
SHOULD audit repository metadata, and the methods PyPI can use to detect and
recover from a PyPI compromise.

Table 1 summarizes a few of the attacks possible when a threshold number of
private cryptographic keys (belonging to any of the PyPI roles) are
compromised.  The leftmost column lists the roles (or a combination of roles)
that have been compromised, and the columns to its right show whether the
compromised roles leaves clients susceptible to malicious updates, a freeze
attack, or metadata inconsistency attacks.


+-----------------+-------------------+----------------+--------------------------------+
| Role Compromise | Malicious Updates | Freeze Attack  | Metadata Inconsistency Attacks |
+=================+===================+================+================================+
|    timetamp     |       NO          |       YES      |       NO                       |
|                 | snapshot and      | limited by     | snapshot needs to cooperate    |
|                 | targets or any    | earliest root, |                                |
|                 | of the bins need  | targets, or    |                                |
|                 | to cooperate      | bin expiry     |                                |
|                 |                   | time           |                                |
+-----------------+-------------------+----------------+--------------------------------+
|    snapshot     |       NO          |       NO       |       NO                       |
|                 | timestamp and     | timestamp      | timestamp needs to cooperate   |
|                 | targets or any of | needs to       |                                |
|                 | the bins need to  | cooperate      |                                |
|                 | cooperate         |                |                                |
+-----------------+-------------------+----------------+--------------------------------+
|    timestamp    |       NO          |       YES      |       YES                      |
|    **AND**      | targets or any    | limited by     | limited by earliest root,      |
|    snapshot     | of the bins need  | earliest root, | targets, or bin metadata       |
|                 | to cooperate      | targets, or    | expiry time                    |
|                 |                   | bin metadata   |                                |
|                 |                   | expiry time    |                                |
+-----------------+-------------------+----------------+--------------------------------+
|    targets      |       NO          | NOT APPLICABLE |        NOT APPLICABLE          |
|    **OR**       | timestamp and     | need timestamp | need timestamp and snapshot    |
|    bin          | snapshot need to  | and snapshot   |                                |
|                 | cooperate         |                |                                |
+-----------------+-------------------+----------------+--------------------------------+
|   timestamp     |       YES         |       YES      |       YES                      |
|   **AND**       |                   | limited by     | limited by earliest root,      |
|   snapshot      |                   | earliest root, | targets, or bin metadata       |
|   **AND**       |                   | targets, or    | expiry time                    |
|   bin           |                   | bin metadata   |                                |
|                 |                   | expiry time    |                                |
+-----------------+-------------------+----------------+--------------------------------+
|     root        |       YES         |       YES      |       YES                      |
+-----------------+-------------------+----------------+--------------------------------+

Table 1: Attacks possible by compromising certain combinations of role keys.
In `September 2013`__, it was shown how the latest version (at the time) of pip
was susceptible to these attacks  and how TUF could protect users against them
[14]_.

__ https://mail.python.org/pipermail/distutils-sig/2013-September/022755.html

Note that compromising *targets* or any delegated role (except for project
targets metadata) does not immediately allow an attacker to serve malicious
updates.  The attacker must also compromise the *timestamp* and *snapshot*
roles (which are both online and therefore more likely to be compromised).
This means that in order to launch any attack, one must not only be able to
act as a man-in-the-middle but also compromise the *timestamp* key (or
compromise the *root* keys and sign a new *timestamp* key).  To launch any
attack other than a freeze attack, one must also compromise the *snapshot* key.

Finally, a compromise of the PyPI infrastructure MAY introduce malicious
updates to *bins* projects because the keys for these roles are online.  The
maximum security model discussed in the appendix addresses this issue.  PEP XXX
[VD: Link to PEP once it is completed] also covers the maximum security model
and goes into more detail on generating developer keys and signing uploaded
distributions.


In the Event of a Key Compromise
--------------------------------

A key compromise means that a threshold of keys (belonging to the metadata
roles on PyPI), as well as the PyPI infrastructure, have been compromised and
used to sign new metadata on PyPI.

If a threshold number of *timestamp*, *snapshot*, or *bins* keys have
been compromised, then PyPI MUST take the following steps:

1. Revoke the *timestamp*, *snapshot* and *targets* role keys from
   the *root* role.  This is done by replacing the compromised *timestamp*,
   *snapshot* and *targets* keys with newly issued keys.

2. Revoke the *bins* keys from the *targets* role by replacing their keys with
   newly issued keys.  Sign the new *targets* role metadata and discard the new
   keys (because, as explained earlier, this increases the security of
   *targets* metadata).

3. All targets of the *bins* roles SHOULD be compared with the last known
   good consistent snapshot where none of the *timestamp*, *snapshot*, or
   *bins* keys
   were known to have been compromised.  Added, updated or deleted targets in
   the compromised consistent snapshot that do not match the last known good
   consistent snapshot MAY be restored to their previous versions.  After
   ensuring the integrity of all *bins* targets, the *bins* metadata
   MUST be regenerated.

4. The *bins* metadata MUST have their version numbers incremented, expiry
   times suitably extended, and signatures renewed.

5. A new timestamped consistent snapshot MUST be issued.

Following these steps would preemptively protect all of these roles even though
only one of them may have been compromised.

If a threshold number of *root* keys have been compromised, then PyPI MUST take
the steps taken when the *targets* role has been compromised.  All of the
*root* keys must also be replaced.

It is also RECOMMENDED that PyPI sufficiently document compromises with
security bulletins.  These security bulletins will be most informative when
users of pip-with-TUF are unable to install or update a project because the
keys for the *timestamp*, *snapshot* or *root* roles are no longer valid.  They
could then visit the PyPI web site to consult security bulletins that would
help to explain why they are no longer able to install or update, and then take
action accordingly.  When a threshold number of *root* keys have not been
revoked due to a compromise, then new *root* metadata may be safely updated
because a threshold number of existing *root* keys will be used to sign for the
integrity of the new *root* metadata.  TUF clients will be able to verify the
integrity of the new *root* metadata with a threshold number of previously
known *root* keys.  This will be the common case.  Otherwise, in the worst
case, where a threshold number of *root* keys have been revoked due to a
compromise, an end-user may choose to update new *root* metadata with
`out-of-band`__ mechanisms.

__ https://en.wikipedia.org/wiki/Out-of-band#Authentication


Auditing Snapshots
------------------

If a malicious party compromises PyPI, they can sign arbitrary files with any
of the online keys.  The roles with offline keys (i.e., *root* and *targets*)
are still protected.  To safely recover from a repository compromise, snapshots
should be audited to ensure files are only restored to trusted versions.

When a repository compromise has been detected, the integrity of three types of
information must be validated:

1. If the online keys of the repository have been compromised, they can be
   revoked by having the *targets* role sign new metadata delegating to a new
   key.

2. If the role metadata on the repository has been changed, this would impact
   the metadata that is signed by online keys.  Any role information created
   since the last period should be discarded. As a result, developers of new
   projects will need to re-register their projects.

3. If the packages themselves may have been tampered with, they can be
   validated using the stored hash information for packages that existed at the
   time of the last period.

In order to safely restore snapshots in the event of a compromise, PyPI SHOULD
maintain a small number of its own mirrors to copy PyPI snapshots according to
some schedule.  The mirroring protocol can be used immediately for this
purpose.  The mirrors must be secured and isolated such that they are
responsible only for mirroring PyPI.  The mirrors can be checked against one
another to detect accidental or malicious failures.

Another approach is to generate the cryptographic hash of *snapshot*
periodically and tweet it.  Perhaps a user comes forward with the actual
metadata and the repository maintainers can verify the metadata's cryptographic
hash.  Alternatively, PyPI may periodically archive its own versions of
*snapshot* rather than rely on externally provided metadata.  In this case,
PyPI SHOULD take the cryptographic hash of every package on the repository and
store this data on an offline device. If any package hash has changed, this
indicates an attack.

As for attacks that serve different versions of metadata, or freeze a version
of a package at a specific version, they can be handled by TUF with techniques
like implicit key revocation and metadata mismatch detection [81].




References
==========

.. [1] https://pypi.python.org
.. [2] https://isis.poly.edu/~jcappos/papers/samuel_tuf_ccs_2010.pdf
.. [3] http://www.pip-installer.org
.. [4] https://wiki.python.org/moin/WikiAttack2013
.. [5] https://github.com/theupdateframework/pip/wiki/Attacks-on-software-repositories
.. [6] https://mail.python.org/pipermail/distutils-sig/2013-April/020596.html
.. [7] https://mail.python.org/pipermail/distutils-sig/2013-May/020701.html
.. [8] https://mail.python.org/pipermail/distutils-sig/2013-July/022008.html
.. [9] PEP 381, Mirroring infrastructure for PyPI, Ziadé, Löwis
       http://www.python.org/dev/peps/pep-0381/
.. [10] https://mail.python.org/pipermail/distutils-sig/2013-September/022773.html
.. [11] https://mail.python.org/pipermail/distutils-sig/2013-May/020848.html
.. [12] PEP 449, Removal of the PyPI Mirror Auto Discovery and Naming Scheme, Stufft
        http://www.python.org/dev/peps/pep-0449/
.. [13] https://isis.poly.edu/~jcappos/papers/cappos_mirror_ccs_08.pdf
.. [14] https://mail.python.org/pipermail/distutils-sig/2013-September/022755.html
.. [15] https://pypi.python.org/security
.. [16] https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt
.. [17] PEP 426, Metadata for Python Software Packages 2.0, Coghlan, Holth, Stufft
        http://www.python.org/dev/peps/pep-0426/
.. [18] https://en.wikipedia.org/wiki/Continuous_delivery
.. [19] https://mail.python.org/pipermail/distutils-sig/2013-August/022154.html
.. [20] https://en.wikipedia.org/wiki/RSA_%28algorithm%29
.. [21] https://en.wikipedia.org/wiki/Key-recovery_attack
.. [22] http://csrc.nist.gov/publications/nistpubs/800-57/SP800-57-Part1.pdf
.. [23] https://www.openssl.org/
.. [24] https://pypi.python.org/pypi/pycrypto
.. [25] http://ed25519.cr.yp.to/


Acknowledgements
================

This material is based upon work supported by the National Science Foundation
under Grant No. CNS-1345049 and CNS-0959138. Any opinions, findings, and
conclusions or recommendations expressed in this material are those of the
author(s) and do not necessarily reflect the views of the National Science
Foundation.

Nick Coghlan, Daniel Holth and the distutils-sig community in general for
helping us to think about how to usably and efficiently integrate TUF with
PyPI.

Roger Dingledine, Sebastian Hahn, Nick Mathewson,  Martin Peck and Justin
Samuel for helping us to design TUF from its predecessor Thandy of the Tor
project.

Konstantin Andrianov, Geremy Condra, Vladimir Diaz, Zane Fisher, Justin Samuel,
Tian Tian, Santiago Torres, John Ward, and Yuyu Zheng for helping us to develop
TUF.

Vladimir Diaz, Monzur Muhammad and Sai Teja Peddinti for helping us to review
this PEP.

Zane Fisher for helping us to review and transcribe this PEP.


Copyright
=========

This document has been placed in the public domain.
