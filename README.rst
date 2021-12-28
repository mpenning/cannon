Introduction
============

cannon is a wrapper around exscript_ to connect with remote server or network 
devices with ssh.

Example Usage - Cisco IOS
=========================

.. code:: python

    from cannon import Shell, Account

    sess = Shell(
        host='route-views.routeviews.org',
        # route-views doesn't need password
        credentials=(
            Account(user='rviews', passwd=''),
        ),

        log_screen=True,
        log_file="~/mylog.txt",
        debug=False,
        )

    sess.execute('term len 0')

    # relax_prompt reduces prompt matching to a minimum... relax_prompt is
    #     useful if the prompt may change while running a series of commands.
    sess.execute('show clock', relax_prompt=True)

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
    username = getuser()
    acct01 = Account(username, getpass("Password for %s" % username), ssh_key='~/.ssh/id_rsa')

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

    # FIXME, interact() is broken...
    #conn.interact()

    conn.execute('whoami', command_timeout=5)
    print("WHOAMI RESULT QUOTED '{}'".format(conn.response))
    conn.execute('uptime', command_timeout=5)
    print("UPTIME '{}'".format(conn.response))
    conn.close()


.. _exscript: https://pypi.python.org/pypi/exscript
