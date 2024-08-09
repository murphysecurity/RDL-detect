#!/usr/bin/env python
# coding=utf-8
"""
基于https://github.com/fortra/impacket/blob/master/examples/rpcdump.py
应对CVE-2024-38077漏洞，通过RPC协议快速排查RDL服务开放情况

Author: MurphySec 2024.08.09
Thanks:
   Javier Kohen
   Alberto Solino (@agsolino)
"""

from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse

from impacket.http import AUTH_NTLM
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import uuid, version
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpch import RPC_PROXY_INVALID_RPC_PORT_ERR, \
    RPC_PROXY_CONN_A1_0X6BA_ERR, RPC_PROXY_CONN_A1_404_ERR, \
    RPC_PROXY_RPC_OUT_DATA_404_ERR

class RPCDump:
    KNOWN_PROTOCOLS = {
        135: {'bindstr': r'ncacn_ip_tcp:%s[135]'},
        139: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
        443: {'bindstr': r'ncacn_http:[593,RpcProxy=%s:443]'},
        445: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
        593: {'bindstr': r'ncacn_http:%s'}
        }

    def __init__(self, username = '', password = '', domain='', hashes = None, port=135):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__port = port
        self.__stringbinding = '' 
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remoteName, remoteHost):
        """Dumps the list of endpoints registered with the mapper
        listening at addr. remoteName is a valid host name or IP
        address in string format.
        """
        entries = []

        self.__stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remoteName
        logging.debug('StringBinding %s' % self.__stringbinding)
        rpctransport = transport.DCERPCTransportFactory(self.__stringbinding)

        if self.__port in [139, 445]:
            # Setting credentials for SMB
            rpctransport.set_credentials(self.__username, self.__password, self.__domain,
                                         self.__lmhash, self.__nthash)

            # Setting remote host and port for SMB
            rpctransport.setRemoteHost(remoteHost)
            rpctransport.set_dport(self.__port)
        elif self.__port in [443]:
            # Setting credentials only for RPC Proxy, but not for the MSRPC level
            rpctransport.set_credentials(self.__username, self.__password, self.__domain,
                                         self.__lmhash, self.__nthash)

            # Usually when a server doesn't support NTLM, it also doesn't expose epmapper (nowadays
            # only RDG servers may potentially expose a epmapper via RPC Proxy).
            #
            # Also if the auth is not NTLM, there is no way to get a target
            # NetBIOS name, but epmapper ACL requires you to specify it.
            rpctransport.set_auth_type(AUTH_NTLM)
        else:
            # We don't need to authenticate to 135 and 593 ports
            pass

        try:
            entries = self.__fetchList(rpctransport)
        except Exception as e:
            #raise

            # This may contain UTF-8
            error_text = 'Protocol failed: %s' % e
            logging.critical(error_text)

            if RPC_PROXY_INVALID_RPC_PORT_ERR in error_text or \
               RPC_PROXY_RPC_OUT_DATA_404_ERR in error_text or \
               RPC_PROXY_CONN_A1_404_ERR in error_text or \
               RPC_PROXY_CONN_A1_0X6BA_ERR in error_text:
                logging.critical("This usually means the target does not allow "
                                 "to connect to its epmapper using RpcProxy.")
                return

        # Display results.

        endpoints = {}
        # Let's groups the UUIDS
        for entry in entries:
            binding = epm.PrintStringBinding(entry['tower']['Floors'])
            tmpUUID = str(entry['tower']['Floors'][0])
            if (tmpUUID in endpoints) is not True:
                endpoints[tmpUUID] = {}
                endpoints[tmpUUID]['Bindings'] = list()
            if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
                endpoints[tmpUUID]['EXE'] = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
            else:
                endpoints[tmpUUID]['EXE'] = 'N/A'
            endpoints[tmpUUID]['annotation'] = entry['annotation'][:-1].decode('utf-8')
            endpoints[tmpUUID]['Bindings'].append(binding)

            if tmpUUID[:36] in epm.KNOWN_PROTOCOLS:
                endpoints[tmpUUID]['Protocol'] = epm.KNOWN_PROTOCOLS[tmpUUID[:36]]
            else:
                endpoints[tmpUUID]['Protocol'] = "N/A"
            #print("Transfer Syntax: %s" % entry['tower']['Floors'][1])

        found = False
        for endpoint in list(endpoints.keys()):
            if '3d267954-eeb7-11d1-b94e-00c04fa3080d' in endpoint.lower():
                logging.info('RPC探测发现 %s 主机开放Terminal Server Licensing服务，可能受影响' % remoteName)
                print('服务信息：')
                print("Protocol: %s " % endpoints[endpoint]['Protocol'])
                print("Provider: %s " % endpoints[endpoint]['EXE'])
                print("UUID    : %s %s" % (endpoint, endpoints[endpoint]['annotation']))
                print("Bindings: ")
                found = True
                for binding in endpoints[endpoint]['Bindings']:
                    print("          %s" % binding)
                break
        
        if not entries:
            logging.info('%s 主机未开放RPC服务，探测失败' % remoteName)

        if entries and not found:
            logging.info('RPC探测发现 %s 主机未开放Terminal Server Licensing服务，不受影响' % remoteName)


    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        dce.connect()

        resp = epm.hept_lookup(None, dce=dce)

        dce.disconnect()

        return resp

# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()

    parser = argparse.ArgumentParser(add_help = True, description = "基于RPC dump排查RDL服务开放情况")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('connection')

    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. If '
                       'ommited it will use whatever was specified as target. This is useful when target is the NetBIOS '
                       'name and you cannot resolve it')
    group.add_argument('-port', choices=['135', '139', '443', '445', '593'], nargs='?', default='135', metavar="destination port",
                       help='Destination port to connect to RPC Endpoint Mapper')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.target_ip is None:
        options.target_ip = remoteName

    dumper = RPCDump(username, password, domain, options.hashes, int(options.port))

    dumper.dump(remoteName, options.target_ip)

