WOTMATE
-------

This is an attempt to reimplement the `PGP pathfinder`_ without needing
anything other than your own keyring. It still requires that you first
make a sqlite database (reimplementation of wotsap) before running the
actual graphers, but on the upside it doesn't require that a key is in
the "strong set" before you are able to graph paths to it.

.. _`PGP pathfinder`: https://pgp.cs.uu.nl

This is very much a work in progress. Currently, the following tools are
available:

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


graph-pgp-pathfinder.py
~~~~~~~~~~~~~~~~~~~~~~~
If you don't want to use a local source of PGP key info, you can query the
PGP Pathfinder service, hosted at https://pgp.cs.uu.nl/. Note, that both top
and bottom keys must be in the "strong set" as defined by Wotsap.

Example usage:

    ./graph-pgp-pathfinder.py 79BE3E4300411886 89A4A8DEECE1C170

.. image:: https://raw.githubusercontent.com/mricon/wotmate/master/examples/pgp-pathfinder.png
   :alt: Example graph produced
   :width: 100%
   :align: center
