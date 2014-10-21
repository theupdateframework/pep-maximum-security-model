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
Replaces:  458 


Abstract
========

Proposed is an extension to PEP 458 [1]_ that adds support for end-to-end
signing and the maximum security model.  End-to-end signing allows both PyPI
and developers to sign for the distributions that are downloaded by clients.
The minimum security model proposed by PEP 458 supports continuous delivery of
distributions (because they are signed by online keys), but it does not protect
distributions in the event that PyPI is compromised.  The maximum security
model aims to provide survivable key compromise and retain many of the benefits
of PEP 458 (e.g., immediate availability of distributions that are uploaded to
PyPI).

This PEP covers the changes made to PEP 458 and excludes the informational
parts of the first PEP (e.g., overview of The Update Framework).  It mainly
focuses on the maximum security model changes and includes modified sections of
the snapshot process, key compromise analysis, auditing snapshots, and the
steps that should be taken if there is a PyPI compromise.  The signing and key
management process that PyPI MAY follow is outlined, but not strictly defined
so as to allow the developer tools to decide how best to implement the release
process, and the management of keys and metadata.  That is, the expected
cryptographic key type and signature of the metadata that MUST be uploaded by
developers to support end-to-end verification of distributions is delineated.


Rationale
=========

PEP 458 proposes how PyPI should be integrated with The Update Framework.  It
explains how modern package managers like pip can be made more secure, and the
types of attacks that can be prevented if PyPI were modified on the server side
to include TUF metadata.  Package managers can reference the TUF metadata
available on PyPI to download distrubutions more securely.  PEP 458 goes on to
describe the metadata layout of the PyPI repository and the minimum security
model. 

The minimum security model supports continuous delivery of projects and uses
online cryptographic keys to sign the distributions uploaded by projects.  The
main strength of the minimum security model is the automated and simplified
release process: developers may upload distributions and then have PyPI sign
for their distributions.

In the minimum security model much of release process is handled in an
automated fashion by online roles, but this simplified approach requires that
cryptographic be stored on PyPI infrastructure.  Cryptographic signing keys
that are stored online are vulnerable to theft, and thus distributions that are
signed by these keys can be easily forged if attackers compromised the
server(s) that rely on these signing keys.  The maximum security model is an
extension to the minimum model that allows PyPI to survive a repository
compromise and permit developers to sign for the distributions that they make
available to PyPI users.

Although the maximum security model provides additional protections while still
supporting continuous delivery of distributions, it was postponed for several
reasons:

1.  A build farm (distribution wheels on supported platforms are generated on
    PyPI infrastructure for each project) may possibly complicate matters.
    PyPI wants to support a build farm in the future.  Unfortunately, if wheels
    are auto-generated externally, developer signatures for these wheels are
    unlikely.  However, there might still be a benefit to generating wheels
    from source distributions that *are* signed by developers (provided that
    reproducible wheels are possible).  Another possibility is to optionally
    delegate trust of these wheels to an online role.

2.  An easy-to-use key management solution is needed for developers.
    `miniLock`__ is one likely candidate for management and generation of keys.
    Although developer signatures can be left as an option, this approach may
    be insufficient due to the great number of unsigned dependencies that can
    occur for a signed distribution requested by a client.  Requiring
    developers to manually sign distributions and manage keys is expected to
    render key signing an unused feature.

    __ https://minilock.io/

3.  A two-phase approach, where the minimum security model is implemented first
    followed by the maximum security model, can simplify matters and give PyPI
    administrators time to review the feasibility of end-to-end signing.


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
that the reader be familiar with the TUF specification [3]_, and PEP 458 [1]_
(which this PEP is extending).

Terms used in this PEP are defined as follows:

* Projects: Projects are software components that are made available for
  integration.  Projects include Python libraries, frameworks, scripts,
  plugins, applications, collections of data or other resources, and various
  combinations thereof.  Public Python projects are typically registered on the
  Python Package Index [4]_.

* Releases: Releases are uniquely identified snapshots of a project [4]_.

* Distributions: Distributions are the packaged files that are used to publish
  and distribute a release [4]_.

* Simple index: The HTML page that contains internal links to the
  distributions of a project [4]_.

* Metadata: Metadata are signed files that describe roles, other metadata, and
  target files.

* Repository: A repository is a source of named metadata and target files.
  Clients request metadata and target files stored on a repository.

* Consistent snapshot: A set of TUF metadata and PyPI targets that capture the
  complete state of all projects on PyPI as they were at some fixed point in
  time.

* The *snapshot* (*release*) role: In order to prevent confusion due to the
  different meanings of the term "release" as employed by PEP 426 [1]_ and the
  TUF specification [3]_, the *release* role is renamed as the *snapshot* role.
  
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


Extension to PEP 458 (minimum security model)
=============================================

The maximum security model and end-to-end signing have been intentionally
excluded from PEP 458.  Although both improve PyPI's ability to survive a
repository compromise and allow developers to sign their distributions, they
have been postponed for review as a potential future extension to PEP 458.
This PEP is available for review to those developers interested in the
end-to-end signing option.  The maximum security model and end-to-end signing
are covered in the subsections that follow.

[VD: Discuss roles in both models and explain disadvanges/advantages?]

Minimum Security Model - outline of roles, signing process.

Maximum Security Model - benefits, additional roles, signing process.


Maximum Security Model
----------------------

The maximum security model relies on developers signing their projects and
uploading signed metadata to PyPI.  If the PyPI infrastructure were to be
compromised, attackers would be unable to serve malicious versions of claimed
projects without access to the project's developer key.  Figure 1 depicts the
changes made to the metadata layout of the minimum security model, namely
that developer roles are now supported and that three new delegated roles
exist: *claimed*, *recently-claimed*, and *unclaimed*.  The *bins* role has
been renamed *unclaimed* and can contain any projects that have not been added
to *claimed*.  The strength of this model (over the minimum security model) is
in the offline keys provided by developers.  Although the minimum security
model supports continuous delivery, all of the projects are signed by an online
key.  An attacker can corrupt packages in the minimum security model, but not
in the maximum model without also compromising a developer's key.

.. image:: figure1.png

Figure 1: An overview of the metadata layout in the maximum security model.
The maximum security model supports continuous delivery and survivable key
compromise.


End-to-End Signing
------------------

End-to-end signing allows both PyPI and developers to sign for the metadata
downloaded by clients.  PyPI is trusted to make uploaded projects available to
clients (they sign the metadata for this part of the process), and developers
can sign the distributions that they upload.

This PEP discusses the tools available to developers who sign the distributions
that they upload to PyPI.  To summarize, developers generate cryptographic keys
and sign metadata in some automated fashion, where the metadata includes the
information required to verify the authenticity of the distribution.  The
metadata is then uploaded to PyPI by the client, where it will be available for
download by package managers such as pip (i.e., package managers that support
TUF metadata).  The entire process is transparent to clients (using a package
manager that supports TUF) who download distributions from PyPI.


Automated Signing of Distributions
----------------------------------

- `Distutils`__

__ https://docs.python.org/2/distutils/index.html#distutils-index

[VD: May Distutils be modified?]
The upload procedure would need to be modified to sign and upload TUF metadata.


- Separate tool provided to the developers

A default PyPI-mediated key management & package signing solution that is
transparent and does not require a key escrow (sharing or moving encrypted
private keys.)  Additionally, a developer may also circumvent sharing encrypted
private keys between multiple machines.

Here is a brief outline of one approach that may be considered:

1.  Register project.
2.  Enter secondary password.
3.  Add new identity to user account from machine 2 (a password prompt.)
4.  Upload project.

Under the hood (the average user is not aware or needs to care):

The "create an identity with only a password" action generates an encrypted
private key file and uploads the ed25519 public key to PyPI.  An existing
identity (contains its public key in project metadata or on PyPI) signs (done
transparently) for new identities.  By default, project metadata has a
signature threshold of 1.  Other verified identities or maintainers may create
new releases and satisfy the threshold.

The framework is flexible, though.  A single project key may also be shared
between machines or maintainers, if manual key management is preferred (e.g.,
ssh-copy-id.)

TUF's `repository`__ and `developer`__ tools:

__ https://github.com/theupdateframework/tuf/blob/develop/tuf/README.md
__ https://github.com/theupdateframework/tuf/blob/develop/tuf/README-developer-tools.md


- Cryptographic key files 

The implementation SHOULD encrypt key files with AES-256-CTR-Mode and passwords
strengthened with PBKDF2-HMAC-SHA256 (100K iterations by default, but may be
overriden in 'tuf.conf.PBKDF2_ITERATIONS' by the user.) The framework, however,
can use any Cryptography library (support for PyCA cryptography may be added)
and the KDF tweaked to your taste.  Tried and tested approaches is the way to
go.


- Cryptographic signature scheme: `Ed25519`__

__ http://ed25519.cr.yp.to/

Ed25519 is a public-key signature system that uses small cryptographic
signatures and keys.  A pure-python implementation of the signature scheme is
available.  pip MUST not depend on external depencies that have to be compiled
(e.g., compiling C extensions to perform verification of signatures), so
verifying RSA signatures may be impractical due to speed.  `Verification of
Ed25519 signatures`__ is fast, even when performed in Python code.

__ https://github.com/pyca/ed25519


- Key management: `MiniLock`__

Essentially it derives a private key from a password so that users do not have
to manage cryptographic key files.  Users may view the cryptographic key as
secondary password: no matter how many computers they have. MiniLock works well
with a signature scheme like Ed25519, which only needs a very small key.

__ https://github.com/kaepora/miniLock#-minilock


- Third-party upload tool: Twine

Third-party tools like `Twine`__ may be modified (if they wish to support
distributions that include TUF metadata) to sign and upload developer projects
to PyPI.  Twine is a utility for interacting with PyPI that uses TLS to upload
distributions and prevent MITM attacks on user names and passwords.

__ https://github.com/pypa/twine


Producing Consistent Snapshots
------------------------------

Given a project, PyPI is responsible for updating, depending on the project,
either the claimed, recently-claimed or unclaimed metadata as well as
associated delegated targets metadata. Every project MUST upload its set of
metadata and targets in a single transaction.  The uploaded set of files is
called the "project transaction".  How PyPI MAY validate the files in a project
transaction is discussed in a later section.  For now, the focus is on how PyPI
will respond to a project transaction.

Every metadata and target file MUST include in its filename the `hex digest`__
of its `SHA-256`__ hash.  For this PEP, it is RECOMMENDED that PyPI adopt a
simple convention of the form: digest.filename, where filename is the original
filename without a copy of the hash, and digest is the hex digest of the hash.

__ http://docs.python.org/2/library/hashlib.html#hashlib.hash.hexdigest
__ https://en.wikipedia.org/wiki/SHA-2

When an unclaimed project uploads a new transaction, a project transaction
process MUST add all new targets and relevant delegated unclaimed metadata. (We
will see later in this section why the unclaimed role will delegate targets to
a number of delegated unclaimed roles.) Finally, the project transaction
process MUST inform the consistent snapshot process about new delegated
unclaimed metadata.

When a recently-claimed project uploads a new a transaction, a project
transaction process MUST add all new targets and delegated targets metadata for
the project. If the project is new, then the project transaction process MUST
also add new recently-claimed metadata with public keys and threshold number
(which MUST be part of the transaction) for the project. Finally, the project
transaction process MUST inform the consistent snapshot process about new
recently-claimed metadata as well as the current set of delegated targets
metadata for the project.

The process for a claimed project is slightly different. The difference is that
PyPI administrators will choose to move the project from the recently-claimed
role to the claimed role. A project transaction process MUST then add new
recently-claimed and claimed metadata to reflect this migration. As is the case
for a recently-claimed project, the project transaction process MUST always add
all new targets and delegated targets metadata for the claimed project.
Finally, the project transaction process MUST inform the consistent snapshot
process about new recently-claimed or claimed metadata as well as the current
set of delegated targets metadata for the project.

Project transaction processes SHOULD be automated, except when PyPI
administrators move a project from the recently-claimed role to the claimed
role. Project transaction processes MUST also be applied atomically: either all
metadata and targets -- or none of them -- are added. The project transaction
processes and consistent snapshot process SHOULD work concurrently. Finally,
project transaction processes SHOULD keep in memory the latest claimed,
recently-claimed and unclaimed metadata so that they will be correctly updated
in new consistent snapshots.

All project transactions MAY be placed in a single queue and processed
serially.  Alternatively, the queue MAY be processed concurrently in order of
appearance, provided that the following rules are observed:

1.  No pair of project transaction processes must concurrently work on the same
    project.

2.  No pair of project transaction processes must concurrently work on
    *unclaimed* projects that belong to the same delegated *unclaimed* role.

3.  No pair of project transaction processes must concurrently work on new
    recently-claimed projects.

4.  No pair of project transaction processes must concurrently work on new
    claimed projects.

5.  No project transaction process must work on a new claimed project while
    another project transaction process is working on a new recently-claimed
    project and vice versa.

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

This PEP has covered the maximum security model, the TUF roles that should be
added to support continuous delivery of distributions, how to generate and sign
the metadata of each role, support distributions that have been signed by
developers.  The remaining sections discuss how PyPI SHOULD audit repository
metadata, and the methods PyPI can use to detect and recover from a PyPI
compromise.

Table 1 summarizes a few of the attacks possible when a threshold number of
private cryptographic keys (belonging to any of the PyPI roles) are
compromised.  The leftmost column lists the roles (or a combination of roles)
that have been compromised, and the columns to its right show whether the
compromised roles leaves clients susceptible to malicious updates, a freeze
attack, or metadata inconsistency attacks.

+-------------------+-------------------+-----------------------+-----------------------+
| Role Compromise   | Malicious Updates | Freeze Attack         | Metadata Inconsistency|
|                   |                   |                       | Attacks               |
+===================+===================+=======================+=======================+
|    timetamp       |       NO          |       YES             |       NO              |
|                   | snapshot and      | limited by earliest   | snapshot needs to     |
|                   | targets or any    | root, targets, or bin | cooperate             |
|                   | of the delegated  | metadata expiry time  |                       |
|                   | roles need to     |                       |                       |
|                   | cooperate         |                       |                       |
+-------------------+-------------------+-----------------------+-----------------------+
|    snapshot       |       NO          |         NO            |       NO              |
|                   | timestamp and     | timestamp needs to    | timestamp needs to    |
|                   | targets or any of | coorperate            | cooperate             |
|                   | the delegated     |                       |                       |
|                   | roles need to     |                       |                       |
|                   | cooperate         |                       |                       |
+-------------------+-------------------+-----------------------+-----------------------+
|    timestamp      |       NO          |         YES           |       YES             |
|    **AND**        | targets or any    | limited by earliest   | limited by earliest   |
|    snapshot       | of the delegated  | root, targets, or bin | root, targets, or bin |
|                   | roles need to     | metadata expiry time  | metadata expiry time  |
|                   | cooperate         |                       |                       |
|                   |                   |                       |                       |
+-------------------+-------------------+-----------------------+-----------------------+
|    targets        |       NO          |     NOT APPLICABLE    |    NOT APPLICABLE     |
|    **OR**         | timestamp and     | need timestamp and    | need timestamp        |
|    claimed        | snapshot need to  | snapshot              | and snapshot          |
|    **OR**         | cooperate         |                       |                       |
| recently-claimed  |                   |                       |                       |
|    **OR**         |                   |                       |                       |
|    unclaimed      |                   |                       |                       |
|    **OR**         |                   |                       |                       |
|    project        |                   |                       |                       |
+-------------------+-------------------+-----------------------+-----------------------+
|   (timestamp      |       YES         |       YES             |       YES             |
|   **AND**         |                   | limited by earliest   | limited by earliest   |
|   snapshot)       |                   | root, targets, or bin | root, targets, or bin |
|   **AND**         |                   | metadata expiry time  | metadata expiry time  |
|   project         |                   |                       |                       |
|                   |                   |                       |                       |
+-------------------+-------------------+-----------------------+-----------------------+
|  (timestamp       |     YES           |        YES            |           YES         |
|  **AND**          | but only of       | limited by earliest   | limited by earliest   |
|  snapshot)        | projects not      | root, targets,        | root, targets,        |
|  **AND**          | delegated by      | claimed,              | claimed,              |
| (recently-claimed | claimed           | recently-claimed,     | recently-claimed,     |
| **OR**            |                   | project, or unclaimed | project, or unclaimed |
| unclaimed)        |                   | metadata expiry time  | metadata expiry time  |
+-------------------+-------------------+-----------------------+-----------------------+
| (timestamp        |                   |         YES           |           YES         | 
| **AND**           |                   | limited by earliest   | limited by earliest   |   
| snapshot)         |                   | root, targets,        | root, targets,        |
| **AND**           |       YES         | claimed,              | claimed,              |
| (targets **OR**   |                   | recently-claimed,     | recently-claimed,     |
| claimed)          |                   | project, or unclaimed | project, or unclaimed |
|                   |                   | metadata expiry time  | metadata expiry time  |
+-------------------+-------------------+-----------------------+-----------------------+
|     root          |       YES         |         YES           |           YES         |
+-------------------+-------------------+-----------------------+-----------------------+

Table 1: Attacks possible by compromising certain combinations of role keys.
In `September 2013`__, it was shown how the latest version (at the time) of pip
was susceptible to these attacks  and how TUF could protect users against them
[8]_.

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

If a threshold number of developer keys of a project have been compromised,
then the project MUST take the following steps:

1.  The project metadata and targets MUST be restored to the last known good
    consistent snapshot where the project was not known to be compromised. This
    can be done by the developers repackaging and resigning all targets with
    the new keys.

2.  The project's metadata MUST have its version numbers incremented, expiry
    times suitably extended and signatures renewed.

Whereas PyPI MUST take the following steps:

1.  Revoke the compromised developer keys from the delegation to the project by
    the recently-claimed or claimed role. This is done by replacing the
    compromised developer keys with newly issued developer keys.

2.  A new timestamped consistent snapshot MUST be issued.

If a threshold number of timestamp, snapshot, recently-claimed or
unclaimed keys have been compromised, then PyPI MUST take the following steps:

1.  Revoke the timestamp, snapshot and targets role keys from the
    root role. This is done by replacing the compromised timestamp,
    snapshot and targets keys with newly issued keys.

2.  Revoke the recently-claimed and unclaimed keys from the targets role by
    replacing their keys with newly issued keys. Sign the new targets role
    metadata and discard the new keys (because, as we explained earlier, this
    increases the security of targets metadata).

3.  Clear all targets or delegations in the recently-claimed role and delete
    all associated delegated targets metadata. Recently registered projects
    SHOULD register their developer keys again with PyPI.

4.  All targets of the recently-claimed and unclaimed roles SHOULD be compared
    with the last known good consistent snapshot where none of the timestamp,
    snapshot, recently-claimed or unclaimed keys were known to have been
    compromised. Added, updated or deleted targets in the compromised
    consistent snapshot that do not match the last known good consistent
    snapshot MAY be restored to their previous versions. After ensuring the
    integrity of all unclaimed targets, the unclaimed metadata MUST be
    regenerated.

5.  The recently-claimed and unclaimed metadata MUST have their version numbers
    incremented, expiry times suitably extended and signatures renewed.

6.  A new timestamped consistent snapshot MUST be issued.

This would preemptively protect all of these roles even though only one of them
may have been compromised.

If a threshold number of the targets or claimed keys have been compromised,
then there is little that an attacker could do without the timestamp and
snapshot keys. In this case, PyPI MUST simply revoke the compromised targets or
claimed keys by replacing them with new keys in the root and targets roles
respectively.

If a threshold number of the timestamp, snapshot and claimed keys have been
compromised, then PyPI MUST take the following steps in addition to the steps
taken when either the timestamp or snapshot keys are compromised:

1.  Revoke the claimed role keys from the targets role and replace them with
    newly issued keys.
    
2.  All project targets of the claimed roles SHOULD be compared with the last
    known good consistent snapshot where none of the timestamp, snapshot or
    claimed keys were known to have been compromised.  Added, updated or
    deleted targets in the compromised consistent snapshot that do not match
    the last known good consistent snapshot MAY be restored to their previous
    versions.  After ensuring the integrity of all claimed project targets, the
    claimed metadata MUST be regenerated.

3.  The claimed metadata MUST have their version numbers incremented, expiry
    times suitably extended and signatures renewed.


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
   time of the last period.  Also new distributions that are signed by
   developers in the claimed role may be safely retained.  However, any
   distributions signed by developers in the *recently-claimed* or *unclaimed*
   role should be discarded.

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
like implicit key revocation and metadata mismatch detection [1].


References
==========

.. [1] https://www.python.org/dev/peps/pep-0458/
.. [2] https://isis.poly.edu/~jcappos/papers/samuel_tuf_ccs_2010.pdf
.. [3] https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt
.. [4] PEP 426, Metadata for Python Software Packages 2.0, Coghlan, Holth,
        Stufft http://www.python.org/dev/peps/pep-0426/
.. [5] https://github.com/theupdateframework/pip/wiki/Attacks-on-software-repositories
.. [6] https://mail.python.org/pipermail/distutils-sig/2013-September/022773.html
.. [7] https://isis.poly.edu/~jcappos/papers/cappos_mirror_ccs_08.pdf
.. [8] https://mail.python.org/pipermail/distutils-sig/2013-September/022755.html
.. [9] https://pypi.python.org/security
.. [10] https://mail.python.org/pipermail/distutils-sig/2013-August/022154.html
.. [11] https://en.wikipedia.org/wiki/RSA_%28algorithm%29
.. [12] https://pypi.python.org/pypi/pycrypto
.. [13] http://ed25519.cr.yp.to/


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


Copyright
=========

This document has been placed in the public domain.
