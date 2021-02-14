Introduction
============

cannon is a wrapper around pexpect_ to connect with remote server or network 
devices with ssh.

Example Usage - Cisco IOS
=========================

.. code:: python

    from cannon import Shell, Account

    sess = Shell(
        host='route-views.oregon-ix.net',
        # route-views doesn't need password
        credentials=(
            Account(user='rviews', passwd=''),
        ),

        log_screen=False,
        log_file="~/mylog.txt",
        debug=False,
        )

    sess.execute('term len 0')

    sess.execute('show version')
    version_text = sess.response

    # template is a TextFSM template
    values = sess.execute('show ip int brief',
        template="""Value INTF (\S+)\nValue IPADDR (\S+)\nValue STATUS (up|down|administratively down)\nValue PROTO (up|down)\n\nStart\n  ^${INTF}\s+${IPADDR}\s+\w+\s+\w+\s+${STATUS}\s+${PROTO} -> Record""")
    print("VALUES "+str(values))
    sess.close()

Example Usage - Linux
=====================

.. code:: python

    from getpass import getpass, getuser
    import sys
    import re

    from cannon import Account, Shell

    """Test for auth fallback, public-key authorization and linux sudo"""

    print("Test logging into linux with ssh...")
    # Test password fallback and ssh_key authorization...
    acct01 = Account(getuser(), passwd, ssh_key='~/.ssh/id_rsa')

    conn = Shell('localhost', credentials=(acct01,),
        mode="linux", debug=False, log_screen=True,
        strip_colors=True)

    conn.execute('uname -a', timeout=5)

    ########### sudo ##########################################################
    #
    index = conn.execute('sudo uname -a', prompts=(r"assword.+?:",))
    print("INDEX", index)
    conn.execute(passwd)

    conn.execute('sudo ls /tmp')
    conn.execute('ls')

    conn.execute('whoami', command_timeout=5)
    conn.interact()   # FIXME, I can't find a way to make interact() stop crashing
    print("WHOAMI RESULT QUOTED '{}'".format(conn.response))
    conn.execute('uptime', command_timeout=5)
    print("UPTIME '{}'".format(conn.response))
    conn.close()


.. _pexpect: https://pypi.python.org/pypi/pexpect
