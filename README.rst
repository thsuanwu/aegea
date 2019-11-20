Aegea: Amazon Web Services Operator Interface
=============================================

*Aegea* is a command line interface (CLI) that provides a set of essential commands and terminal dashboards for
operators of Amazon Web Services (AWS) accounts. Aegea lets you build AMIs and Docker images using the
`cloud-init <http://cloudinit.readthedocs.io/>`_ config management package, manage config roles, launch and monitor instances
and services, and manage AWS resources including ELB, RDS, and AWS Batch. It is intended to be used in conjunction with the
existing functionality of the `AWS CLI <https://aws.amazon.com/cli/>`_ and `boto3 <https://boto3.readthedocs.io/>`_.

Installation
~~~~~~~~~~~~
::

   pip3 install aegea

Before you do this, you will also need to install some system library dependencies:

+--------------+---------+-------------------------------------------------------------------------------------------------------+
| OS           | Python  | Command                                                                                               |
+==============+=========+=======================================================================================================+
| Mac OS       |         | Install `Homebrew <https://brew.sh>`_, then run ``brew install python``.                              |
+--------------+---------+-------------------------------------------------------------------------------------------------------+
| Ubuntu       | Python 2| sudo apt-get update;                                                                                  |
|              |         | sudo apt-get install build-essential python-pip python-dev python-cffi libffi-dev libssl-dev moreutils|
+--------------+---------+-------------------------------------------------------------------------------------------------------+
| Ubuntu       | Python 3| sudo apt-get update;                                                                                  |
|              |         | sudo apt-get install build-essential python3-{pip,dev,cffi} libffi-dev libssl-dev moreutils           |
+--------------+---------+-------------------------------------------------------------------------------------------------------+
| Red Hat      | Python 2| sudo yum install python-devel python-cffi openssl-devel moreutils                                     |
+--------------+---------+-------------------------------------------------------------------------------------------------------+
| Red Hat      | Python 3| sudo yum install python3-devel python3-cffi openssl-devel moreutils                                   |
+--------------+---------+-------------------------------------------------------------------------------------------------------+

Run ``aws configure`` to configure `IAM <https://aws.amazon.com/iam/>`_ access credentials that will be used by the
``aws`` and ``aegea`` commands. You can create a new IAM key at https://console.aws.amazon.com/iam/home#/users.

Aegea commands
~~~~~~~~~~~~~~
Below are some highlights from Aegea's suite of commands. Run ``aegea --help`` to see the full list of commands.

Aegea SSH
---------
The ``aegea ssh`` command (and its variant ``aegea scp``) is an SSH configuration wrapper that allows you to securely
resolve instance addresses by name and pre-fetch their public keys without the Trust-On-First-Use requirement. It also
optionally integrates with the `Bless <https://github.com/Netflix/bless>`_ package using the
`blessclient <https://github.com/chanzuckerberg/blessclient>`_ configuration convention.

Aegea Launch
------------
The ``aegea launch`` command launches EC2 instances. It has integrated support for Bless as well as DNS, runtime
cloud-init configuration, automatic location of Aegea-built AMIs or up-to-date Ubuntu or Amazon Linux AMIs, automatic
storage configuration, and other options.

Aegea Batch
-----------
The `AWS Batch <https://aws.amazon.com/batch>`_ API lets you run non-interactive command line workflows in Docker
containers, managing AWS ECS, Spot Fleet, and EC2 in your account on your behalf. Use the ``aegea batch`` family of commands
to interact with AWS Batch. The key command is ``aegea batch submit`` to submit jobs.

`aegea/missions/docker-example/ <aegea/missions/docker-example/>`_ is a root directory of an **aegea mission** -
a configuration management role. It has a rootfs.skel and a config.yml, which has directives to install packages,
etc. The example just installs the bwa APT package.

Run ``aegea-build-image-for-mission docker-example dex`` to build an ECR image called dex from the "docker-example"
mission. You can list ECR images with ``aegea ecr ls``, and delete them with e.g. ``aws ecr delete-repository dex``.

Run ``aegea batch submit --ecs-image dex --command "bwa aln || true" "bwa mem || true" --memory 2048 --vcpus 4 --watch``
to run a Batch job that requires 2 GB RAM and 4 cores to be allocated to the Docker container, using the "dex" image,
and executes two commands as listed after --command, using "bash -euo pipefail -c".

You can also use ``aegea batch submit --execute FILE``. This will slurp up FILE (any type of shell script or ELF
executable) and execute it in the job's Docker container.

The concurrency and cost of your Batch jobs is governed by the "Max vCPUs" setting in your compute environment.
To change the capacity or other settings of your compute environment, go to
https://console.aws.amazon.com/batch/home?region=us-east-1#/compute-environments, select "aegea_batch", and click "Edit".

AWS Batch launches and manages `ECS <https://aws.amazon.com/ecs/>`_ host instances to execute your jobs. You can see the
host instances by running ``aegea ls``.

Aegea ECS Run
-------------
The `ECS Fargate <https://aws.amazon.com/fargate/>`_ API is an interface to the AWS container-based virtualization platform,
Firecracker. ECS Fargate allows you to run workloads in fully managed containers: no instances run in your account; you are billed by
the second of container use, and containers usually start up within 20 seconds. Use the ``aegea ecs run`` command to interact with
ECS Fargate. Most ``aegea batch`` semantics are applicable to ``aegea ecs``, which interacts with ECS via the "one shot"
`ECS RunTask <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html>`_ API.

Configuration management
~~~~~~~~~~~~~~~~~~~~~~~~
Aegea supports ingesting configuration from a configurable array of sources. Each source is a JSON or YAML file.
Configuration sources that follow the first source update the configuration using recursive dictionary merging. Sources are
enumerated in the following order (i.e., in order of increasing priority):

- Site-wide configuration source, ``/etc/aegea/config.yml``
- User configuration source, ``~/.config/aegea/config.yml``
- Any sources listed in the colon-delimited variable ``AEGEA_CONFIG_FILE``
- Command line options

**Array merge operators**: When loading a chain of configuration sources, Aegea uses recursive dictionary merging to
combine the sources. Additionally, when the original config value is a list, Aegea supports array manipulation
operators, which let you extend and modify arrays defined in underlying configurations. See
https://github.com/kislyuk/tweak#array-merge-operators for a list of these operators.

Building AMIs and Docker images
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Aegea includes a lightweight configuration management system for building machine images based on
`cloud-init <http://cloudinit.readthedocs.io/>`_ (both Docker images and AMIs are supported).

TODO: ``build_image build_ami build_docker_image rootfs.skel``

.. image:: https://img.shields.io/travis/com/kislyuk/aegea.svg
   :target: https://travis-ci.com/kislyuk/aegea
.. image:: https://img.shields.io/pypi/v/aegea.svg
   :target: https://pypi.python.org/pypi/aegea
.. image:: https://img.shields.io/pypi/l/aegea.svg
   :target: https://pypi.python.org/pypi/aegea
.. image:: https://codecov.io/gh/kislyuk/aegea/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/kislyuk/aegea
