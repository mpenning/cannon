import sys

sys.path.insert(0, "..")

import pytest
from cannon import Shell, Account

def test_routeviews_all_cmds():
    """ssh to route-views.routeviews.org and run commands.  Currently this also exercises cannon's ssh kexalgorithms and ssh cipher fallback"""
    conn = Shell(host='route-views.routeviews.org', account=Account('rviews', ''),)
    conn.execute('term len 0')
    assert "term len 0" in conn.response

    #conn.sync_prompt(require_detect_prompt=False)
    conn.execute('show ip bgp summ')
    for output_line in conn.response.splitlines():
        # Check that we can at least read the local ASN...
        if "6447" in output_line:
            assert "6447" in output_line
            break
    else:
        # Fail if no match on "6447"...
        assert False

    # Skipping these commands for now...
    #conn.execute('show proc cpu sort')
    #conn.execute('show inventory')
    #conn.execute('show users')
    #conn.execute('show version')

    # FIXME add more output assertions below...
    conn.execute('ping 4.2.2.2')

    try:
        conn.execute('exit')
        conn.close()
    except:
        pass

#intfs = conn.execute('show ip int brief', template="""Value INTF (\S+)\nValue IPADDR (\S+)\nValue STATUS (up|down|administratively down)\nValue PROTO (up|down)\n\nStart\n  ^${INTF}\s+${IPADDR}\s+\w+\s+\w+\s+${STATUS}\s+${PROTO} -> Record""")
#print(intfs)

#print("-----------------")
#print(version)
