zodb_auth
==========

Overview
--------

``zodb_auth`` is a package which allows :term:`Pyramid` to store and
authenticate users in the :term:`ZODB`.


Installation
------------

Install using setuptools, e.g. (within a virtualenv)::

  $ easy_install zodb_auth

Setup
-----

Once ``zodb_auth`` is installed, you must use the ``config.include``
mechanism to include it into your Pyramid project's configuration.  In your
Pyramid project's ``__init__.py``:

.. code-block:: python
   :linenos:

   config = Configurator(.....)
   config.include('zodb_auth')

From now on, whenever a new request is setup from an application using
``config`` it will have access to user objects in the zodb.

Usage
-----

TODO:

More Information
----------------

.. toctree::
   :maxdepth: 1

   api.rst
   glossary.rst


Reporting Bugs / Development Versions
-------------------------------------

Visit http://github.com/Pylons/zodb_auth to download development or
tagged versions.

Visit http://github.com/Pylons/zodb_auth/issues to report bugs.

Indices and tables
------------------

* :ref:`glossary`
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
