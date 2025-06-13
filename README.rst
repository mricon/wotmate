WOTMATE
-------

This is an attempt to reimplement the defunct PGP pathfinder without
needing anything other than your own keyring. This is very much a work
in progress.

Prerequisite:
    ./make-sqlitedb.py

Currently, the following tools are available:

graph-paths.py
~~~~~~~~~~~~~~
Draws the shortest path between each key you have personally signed and
the target key. For simpler setups, it exactly mirrors the web of trust,
but the resulting graph is not necessarily one-to-one (because you can
assign ownertrust to a key you did not directly sign).

Example usage:

    ./graph-paths.py --fromkey torvalds jeyu

.. image:: https://raw.githubusercontent.com/mricon/wotmate/master/examples/torvalds-to-jeyu.png
   :alt: Example graph produced
   :width: 100%
   :align: center


graph-to-full.py
~~~~~~~~~~~~~~~~
Very similar, but finds shortest paths to each fully-trusted key in your
keyring. Handy for open-source projects where someone maintains a "web
of trust."

Example usage:

    ./graph-to-full.py jeyu

.. image:: https://raw.githubusercontent.com/mricon/wotmate/master/examples/full-to-jeyu.png
   :alt: Example graph produced
   :width: 100%
   :align: center


Getting support and contributing patches
----------------------------------------
Please send patches and support requests to tools@kernel.org.

Submissions must be made under the terms of the Linux Foundation
certificate of contribution and should include a Signed-off-by: line.
Please read the DCO file for full legal definition of what that implies.


