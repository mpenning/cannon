from cannon import Shell, Account

print("Logging into route-views")
conn = Shell('route-views.oregon-ix.net', credentials=(Account('rviews', ''),),
    auto_priv_mode=False, log_file='mylog.txt', log_screen=True, debug=False)
conn.execute('term len 0')
conn.execute('show version')
conn.sync_prompt()

intfs = conn.execute('show ip int brief', template="""Value INTF (\S+)\nValue IPADDR (\S+)\nValue STATUS (up|down|administratively down)\nValue PROTO (up|down)\n\nStart\n  ^${INTF}\s+${IPADDR}\s+\w+\s+\w+\s+${STATUS}\s+${PROTO} -> Record""")
print(intfs)
