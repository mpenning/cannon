Introduction
============

cannon is a wrapper around pexpect_ to connect with remote server or network 
devices with ssh.

Example Usage
=============

.. code:: python

    from cannon import Shell, Account

    sess = Shell(
        host='route-views.oregon-ix.net',
        credentials=(
            Account(user='rviews', passwd=''),
        ),

        log_screen=False,
        log_file="~/mylog.txt",
        auto_priv_mode=False,
        debug=False,
        )
    sess.execute('term len 0')
    # template is a TextFSM template
    values = sess.execute('show ip int brief',
        template="""Value INTF (\S+)\nValue IPADDR (\S+)\nValue STATUS (up|down|administratively down)\nValue PROTO (up|down)\n\nStart\n  ^${INTF}\s+${IPADDR}\s+\w+\s+\w+\s+${STATUS}\s+${PROTO} -> Record""")
    print("VALUES "+str(values))
    sess.close()

.. _pexpect: https://pypi.python.org/pypi/pexpect
