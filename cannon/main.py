
from traits.api import (
    Any,
    Str,
    Bool,
    Int,
    File,
    List,
    Range,
    PrefixList,
    HasRequiredTraits,
)
from Exscript.protocols.exception import InvalidCommandException
from Exscript.protocols.exception import TimeoutException  # <-- expect timeout
from Exscript import Account, PrivateKey
from Exscript.protocols import SSH2
import Exscript

#from paramiko.transport import ConnectionResetError
from paramiko.ssh_exception import SSHException
import paramiko.ssh_exception
import paramiko

from textfsm import TextFSM

from loguru import logger

import arrow


from getpass import getpass, getuser
from io import StringIO
import pkg_resources
import socket
import atexit
import time
import json
import copy
import sys
import re
import os

pkg_resources.require("Exscript==2.6.3")
pkg_resources.require("loguru==0.5.3")
pkg_resources.require("traits==6.3.2")
pkg_resources.require("textfsm==1.1.2")
pkg_resources.require("arrow==1.2.1")

# Base class for server tests...
# - Exscript/tests/Exscript/protocols/ProtocolTest.py
#
# Test suite for the SSH2 client...
# - Exscript/tests/Exscript/protocols/SSH2Test.py
#
# Test suite for the Dummy client...
# - Exscript/tests/Exscript/protocols/DummyTest.py



## Deprecating these for now...
#from Exscript import Logger as logger_exscript
#from Exscript.util.log import log_to


"""
Copyright 2022 - David Michael Pennington
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1.  Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""
TODO:

1. Incorporate tests against the Cisco free router testbeds
described by bigevilbeard, below...

- https://github.com/bigevilbeard/Basic_NetMiko/README.md
  - https://devnetsandbox.cisco.com/RM/Diagram/Index/e83cfd31-ade3-4e15-91d6-3118b867a0dd?diagramType=Topology
  - https://devnetsandbox.cisco.com/RM/Diagram/Index/38ded1f0-16ce-43f2-8df5-43a40ebf752e?diagramType=Topology

2. Fix Exscript SSH with legacy ciphers and kexexchange algorithms -> https://github.com/knipknap/exscript/issues/215
"""

HOST = ""
USERNAME = getuser()
PASSWORD = ""
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_PROMPT_LIST = []
DEFAULT_PROMPT_TIMEOUT = 30

logger_id = logger.add(sys.stderr)

@logger.catch(default=True, onerror=lambda _: sys.exit(1))
def account_factory(username="", password=None, private_key=""):
    assert username != ""

    if password is None:
        password = getpass("Login password for %s" % username)

    if isinstance(private_key, str) and private_key!="":
        private_key_path = os.path.expanduser(private_key)
        private_key_obj = PrivateKey(keytype='rsa').from_file(private_key_path)


#@log_args
@logger.catch(default=True, onerror=lambda _: sys.exit(1))
class Shell(HasRequiredTraits):
    host = Str(value="", required=True)
    port = Range(value=22, low=1, high=65534)
    username = Str(value=getuser(), required=False)
    password = Str(value='', required=False)
    private_key_path = File(value=os.path.expanduser("~/.ssh/id_rsa"))
    inventory=File(value=os.path.expanduser("~/inventory.ini"))
    # FIXME - needs more drivers... -> https://exscript.readthedocs.io/en/latest/Exscript.protocols.drivers.html
    driver = PrefixList(
        value="generic", values=["generic", "shell", "junos", "ios"], required=False
    )
    termtype = PrefixList(
        value="dumb", values=["dumb", "xterm", "vt100"], required=False
    )
    protocol = PrefixList(value='ssh', values=['ssh'], required=False)
    stdout = PrefixList(value=None, values=[None, sys.stdout], required=False)
    stderr = PrefixList(value=sys.stderr, values=[None, sys.stderr], required=False)
    banner_timeout = Range(value=20, low=1, high=30, required=False)
    connect_timeout = Range(value=10, low=1, high=30, required=False)
    prompt_timeout = Range(value=10, low=1, high=65535, required=False)
    prompt_list = List(Str, required=False)
    default_prompt_list = List(re.Pattern, required=False)
    account = Any(value=None, required=True)
    account_list = List(Exscript.account.Account, required=False)
    logfile = File(value=os.path.expanduser("/dev/null"))
    json_logfile = File(value="/dev/null", required=False)
    jh = Any(value=None)
    encoding = PrefixList(value="utf-8", values=["latin-1", "utf-8"], required=False)
    downgrade_ssh_crypto = Bool(value=False, values=[True, False])
    ssh_attempt_number = Range(value=1, low=1, high=3, required=False)
    conn = Any(required=False)
    debug = Range(value=0, low=0, high=5, required=False)
    allow_invalid_command = Bool(value=True, values=[True, False], required=False)
    MAX_SSH_ATTEMPT = Int(3)

    def __init__(self, **kwargs):
        HasRequiredTraits.__init__(self, **kwargs)

        assert self.host != ""
        assert len(self.account_list) == 0
        if isinstance(self.account, Account):
            self.append_account(self.account)
        else:
            raise ValueError("Account must be included in the Shell() call")

        # Ensure this was NOT called with username
        if kwargs.get("username", False) is not False:
            raise ValueError("Shell() calls with username are not supported")

        # Ensure this was NOT called with password
        if kwargs.get("password", False) is not False:
            raise ValueError("Shell() calls with password are not supported")

        # Check whether host matches an ip address in the inventory...
        host_address = self.search_inventory_for_host(self.host)
        print("HOST", host_address)

        self.conn = self.do_ssh_login(debug=self.debug)

        # Always store the original prompt(s) so we can fallback to them later
        self.default_prompt_list = self.conn.get_prompt()

        # Populate the initial prompt list...
        if self.json_logfile != "/dev/null":
            self.open_json_log()
            self.json_log_entry(cmd="ssh2", action="login", timeout=False)

    def __repr__(self):
        return """<Shell: %s>""" % self.host

    def search_inventory_for_host(self, host=None):
        for line in self.iter_inventory_lines():
            if re.search(r"^\s*(%s)" % self.host, line.lower()):
                print("MATCH", self.host, line)
                sys.exit(0)
                break

    def iter_inventory_lines(self):
        if os.path.isfile(os.path.expanduser(self.inventory)):
            with open(self.inventory, 'r', encoding="utf=8") as fh:
                for line in fh.read().splitlines():
                    yield line.lower()
        else:
            raise OSError("Cannot find inventory file named '%s'" % self.inventory)

    def do_ssh_login(self,
        connect_timeout=10,
        debug=0,
    ):
        assert isinstance(connect_timeout, int)
        assert isinstance(debug, int)
        assert len(self.account_list) > 0

        # FIXME - clean up PrivateKey here...
        private_key=PrivateKey(keytype='rsa').from_file(self.private_key_path)

        self.downgrade_ssh_crypto = False
        if self.protocol == "ssh":

            for self.ssh_attempt_number in [1, 2, 3]:

                assert self.ssh_attempt_number <= self.MAX_SSH_ATTEMPT

                # You have to change allowed ciphers / key exchange options
                # **before** the connection
                #     -> https://stackoverflow.com/a/31303321/667301
                if self.downgrade_ssh_crypto is True:
                    paramiko.Transport._preferred_ciphers = ('aes128-cbc', '3des-cbc',)
                    paramiko.Transport._preferred_kex = ('diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1',)

                conn = SSH2(driver=self.driver)

                # Save default values...
                DEFAULT_CONNECT_TIMEOUT = conn.get_connect_timeout()
                DEFAULT_PROMPT_LIST = conn.get_prompt()
                DEFAULT_PROMPT_TIMEOUT = conn.get_timeout()

                # FIXME - Exscript should be handling this but the pypi pkg doesn't
                #

                conn.set_connect_timeout(connect_timeout)
                try:
                    conn.connect(hostname=self.host, port=self.port)
                    break

                except socket.timeout as ee:
                    self.downgrade_ssh_crypto = True
                    if self.ssh_attempt_number == self.MAX_SSH_ATTEMPT:
                        error = "Timeout connecting to TCP port {1} on host:{0}".format(self.host, self.port)
                        logger.critical(error)
                        raise OSError(error)
                    else:
                        assert self.ssh_attempt_number < self.MAX_SSH_ATTEMPT
                        time.sleep(0.5)

                except SSHException as ee:
                    self.downgrade_ssh_crypto = True
                    if self.ssh_attempt_number == self.MAX_SSH_ATTEMPT: 
                        error = "Connection to host:{0} on TCP port {1} was reset".format(self.host, self.port)
                        logger.critical(error)
                        raise OSError(error)
                    else:
                        assert self.ssh_attempt_number < self.MAX_SSH_ATTEMPT
                        time.sleep(0.5)

            login_success = False
            for account in self.account_list:
                conn.login(account)
                try:
                    assert isinstance(conn, SSH2)   # This succeeds if logged in...
                    login_success = True
                    break
                except AssertionError as aa:
                    # login with account failed...
                    continue

            assert login_success is True
            if login_success is True:
                self.password = account.password
            else:
                raise ValueError("Login to host='%s' failed" % self.host)

            conn.set_connect_timeout(DEFAULT_CONNECT_TIMEOUT)

            return conn

        else:
            raise ValueError("FATAL: proto='%s' isn't a valid protocol" % proto)

    ## TODO - we should use a true try / except here...
    def open_json_log(self):
        if self.json_logfile == "/dev/null":
            return None
        else:
            self.jh = open(os.path.expanduser(self.json_logfile), "w",
                encoding="utf-8")
            atexit.register(self.close_json_log)
            return True

    ## TODO - we should use a true try / except here...
    def close_json_log(self):
        if self.json_logfile == "/dev/null":
            return None
        else:
            self.jh.flush()
            self.jh.close()
            return True

    def json_log_entry(self, cmd=None, action=None, result=None, timeout=False):
        if self.json_logfile == "/dev/null":
            return None
        assert isinstance(cmd, str)
        assert isinstance(action, str)
        assert action in set(["login", "execute", "send", "expect", "output"])
        assert isinstance(result, str) or (result is None)
        assert isinstance(timeout, bool)
        # Pretty json output... or reference json docs
        #     https://stackoverflow.com/a/12944035/667301
        self.jh.write(json.dumps(
            {"time": str(arrow.now()),
             "cmd": cmd,
             "host": self.host,
             "action": action,
             "result": result,
             "timeout": timeout,
             }, indent=4, sort_keys=True)+","
            +os.linesep)

    def append_account(self, account):
        # From the exscript docs...
        #     key = PrivateKey.from_file('~/.ssh/id_rsa', 'my_key_password')
        self.account_list.append(account)

    def _extend_prompt(self, prompt_list=()):
        retval = list()
        for ii in prompt_list:
            if isinstance(ii, str):
                compiled = re.compile(ii)
                retval.append(compiled)

            elif isinstance(ii, re.Pattern):
                retval.append(ii)

            else:
                raise ValueError("Cannot process prompt:'%s'" % ii)

        for ii in self.conn.get_prompt():
            retval.append(ii)

        self.conn.set_prompt(retval)

    def interact(self):
        raise NotImplementedError
        print("Delegating processing to a human...")
        finished = False
        while not finished:
            cmd = input()
            self.execute(cmd.strip(), consume=False)

    def tfsm(self, template=None, input_str=None):
        """Run the textfsm template against input_str"""
        assert isinstance(template, str)
        assert isinstance(input_str, str)
        if os.path.isfile(os.path.expanduser(str(template))):
            # open the textfsm template from disk...
            fh = open(template, "r")
        else:
            # build a fake filehandle around textfsm template string
            fh = StringIO(template)
        fsm = TextFSM(fh)
        header = fsm.header
        values = fsm.ParseText(input_str)
        assert values != [], "Could not match any values with the template."

        ## Pack the extracted values into a list of dicts, using keys from
        ##   the header file
        retval = list()

        # Values is a nested list of captured information
        for ii in (values, values[0]):
            if not isinstance(ii, list):
                continue
            for row in ii:
                try:
                    # Require the row to be a list
                    assert isinstance(row, list)
                    # Require row to be exactly as long as the header list
                    assert len(row) == len(header)
                    row_dict = {}
                    for idx, value in enumerate(row):
                        row_dict[header[idx]] = value
                    retval.append(row_dict)
                except AssertionError:
                    break
            if len(retval) > 0:
                return retval
            else:
                raise ValueError("Cannot parse the textfsm template")

    def execute(self, cmd="", prompt_list=(), timeout=0, template=None, debug=0, consume=True):
        assert isinstance(cmd, str)
        if cmd.strip()=="":
            assert len(cmd.splitlines()) == 0
        else:
            assert len(cmd.splitlines()) == 1
        assert isinstance(timeout, int)
        assert (template is None) or isinstance(template, str)
        assert isinstance(debug, int)

        cmd = cmd.strip()

        if debug > 0:
            logger.debug("Calling execute(cmd='%s', timeout=%s)" % (cmd, timeout))

        if len(prompt_list) > 0:
            self._extend_prompt(prompt_list)

        normal_timeout = self.conn.get_timeout()
        if timeout > 0:
            self.conn.set_timeout(timeout)

        # Handle prompt_list...
        self.set_custom_prompts(prompt_list)

        self.json_log_entry(cmd=cmd, action="execute", timeout=False)

        # Handle sudo command...
        if cmd.strip()[0:4]=="sudo":
            pre_sudo_prompts = self.conn.get_prompt()
            # FIXME I removed re.compile from the sudo prompt. Example prompt:
            #    [sudo] password for mpenning: 
            sudo_prompt = re.compile(r"[\r\n].+?:")
            prompts_w_sudo = copy.deepcopy(pre_sudo_prompts)
            prompts_w_sudo.insert(0, sudo_prompt)
            self.conn.set_prompt(prompts_w_sudo)

            # Sending sudo cmd here...
            self.conn.send(cmd+os.linesep)
            prompt_idx, re_match_object = self.conn.expect_prompt()
            # idx==0 is a sudo password prompt...
            if prompt_idx==0:
                self.conn.set_prompt(self.default_prompt_list)
                self.conn.send(self.password+os.linesep)
                prompt_idx, re_match_object = self.conn.expect_prompt()
                assert isinstance(prompt_idx, int)

            else:
                raise ValueError("Cannot complete 'execute(cmd='%s')" % cmd)
            self.conn.set_prompt(pre_sudo_prompts)

        # Handle non-sudo execute()...
        else:
            try:
                self.conn.execute(cmd)

            except ConnectionResetError as dd:
                error = "SSH session with {0} was reset while running cmd='{1}'".format(self.host, cmd)
                raise ConnectionResetError(error)

            except InvalidCommandException as ee:
                print(str(ee))

                if self.allow_invalid_command is False:
                    error = "cmd='%s' is an invalid command" % cmd
                    logger.critical(error)
                    raise InvalidCommandException(error)

        # Reset the prompt list at the end of the command...
        if len(prompt_list) > 0:
            self.reset_prompt()

        # Reset the timeout at the end of the command...
        if self.conn.get_timeout() != normal_timeout:
            self.conn.set_timeout(normal_timeout)

        # save the raw response...
        cmd_output = self.conn.response

        self.json_log_entry(cmd=cmd, action="output", result=cmd_output, timeout=False)
        ## TextFSM
        ## If template is specified, parse the response into a list of dicts...
        if isinstance(template, str):
            return self.tfsm(template, cmd_output)
        else:
            return cmd_output

    def send(self, cmd="", debug=0):
        assert isinstance(cmd, str)
        assert len(cmd.splitlines()) == 1
        assert isinstance(debug, int)

        self.json_log_entry(cmd=cmd, action="send", result=None, timeout=False)

        self.conn.send(cmd)

    def expect(self, prompt_list=(), timeout=0, debug=0):
        """Expect prompts, including those in prompt_list"""
        assert isinstance(debug, int)
        if debug > 0:
            pass

        normal_timeout = self.conn.get_timeout()
        if timeout > 0:
            self.conn.set_timeout(timeout)

        normal_prompts = self.conn.get_prompt()

        # Handle prompt_list...
        self.set_custom_prompts(prompt_list)

        prompt_idx, re_match_object = self.conn.expect_prompt()

        self.conn.set_timeout(normal_timeout)
        # Reset the prompt list at the end of the command...
        if len(prompt_list) > 0:
            self.reset_prompt()

        self.json_log_entry(cmd=cmd, action="expect", result=None, timeout=False)
        return prompt_idx, re_match_object

    def set_timeout(self, timeout=0):
        """Set the command timeout"""
        if isinstance(timeout, int) and timeout>0:
            return self.conn.set_timeout(timeout)

    def set_custom_prompts(self, prompt_list=()):
        """Wrapper around set_prompt()"""
        return self.set_prompt(prompt_list)

    def reset_prompt(self):
        """Reset all prompts to default"""
        return self.conn.set_prompt(self.default_prompt_list)

    def set_prompt(self, prompt_list=()):
        """Extend the expected prompts with prompts in prompt_list"""
        normal_prompts = self.conn.get_prompt()
        custom_prompts = copy.copy(normal_prompts)
        if (isinstance(prompt_list, tuple) or isinstance(prompt_list, list)) and len(prompt_list) > 0:
            prompt_list.reverse()
            for prompt in prompt_list:
                if isinstance(prompt, str):
                    custom_prompts.insert(0, re.compile(prompt))

                elif isinstance(prompt, re.Pattern):
                    custom_prompts.insert(0, prompt)

                else:
                    raise ValueError("Cannot process prompt='%s'" % prompt)
            self.conn.set_prompt(custom_prompts)

        return normal_prompts, custom_prompts

    def close(self, force=True, timeout=0, debug=0):
        self.conn.close(force=force)

    @property
    def response(self):
        return self.conn.response

@logger.catch(default=True, onerror=lambda _: sys.exit(1))
def reset_conn_parameters(conn=None):
    assert isinstance(conn, SSH2)
    conn.set_connect_timeout(DEFAULT_CONNECT_TIMEOUT)
    conn.set_prompt(DEFAULT_PROMPT_LIST)
    conn.set_timeout(DEFAULT_PROMPT_TIMEOUT)


if __name__=="__main__":
    pass
