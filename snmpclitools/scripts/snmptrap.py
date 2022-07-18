#!/usr/bin/env python
#
# This file is part of snmpclitools software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpclitools/license.html
#
# Notificaton Originator
#
import os
import socket
import sys
import traceback

from pysnmp import error
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import ntforg
from pysnmp.proto.api import v1, v2c
from pysnmp.proto.proxy import rfc2576

from snmpclitools.cli import base
from snmpclitools.cli import main
from snmpclitools.cli import mibview
from snmpclitools.cli import msgmod
from snmpclitools.cli import pdu
from snmpclitools.cli import secmod
from snmpclitools.cli import target


def getUsage():
    return """\
Usage: %s [OPTIONS] <MANAGER> <PARAMETERS>
%s%s%s%s
TRAP options:
   -C<TRAPOPT>:   set various application specific behaviours:
              i:  send INFORM-PDU, expect a response
%s
SNMPv1 TRAP management parameters:
   enterprise-oid agent generic-trap specific-trap uptime <management-params>
   where:
              generic-trap:         coldStart|warmStart|linkDown|linkUp|authenticationFailure
                                    |egpNeighborLoss|enterpriseSpecific
SNMPv2/SNMPv3 management parameters:
   uptime trap-oid <management-params>
%s\
""" % (os.path.basename(sys.argv[0]),
       main.getUsage(),
       msgmod.getUsage(),
       secmod.getUsage(),
       mibview.getUsage(),
       target.getUsage(),
       pdu.getWriteUsage())


# Construct c/l interpreter for this app

class Scanner(msgmod.MPScannerMixIn,
              secmod.SMScannerMixIn,
              mibview.MibViewScannerMixIn,
              target.TargetScannerMixIn,
              pdu.ReadPduScannerMixIn,
              main.MainScannerMixIn,
              base.ScannerTemplate):

    def t_appopts(self, s):
        """ -C """
        self.rv.append(base.ConfigToken('appopts'))

    def t_genericTrap(self, s):
        """ coldStart|warmStart|linkDown|linkUp|authenticationFailure|egpNeighborLoss|enterpriseSpecific """
        self.rv.append(base.ConfigToken('genericTrap', s))


class Parser(msgmod.MPParserMixIn,
             secmod.SMParserMixIn,
             mibview.MibViewParserMixIn,
             target.TargetParserMixIn,
             pdu.WritePduParserMixIn,
             main.MainParserMixIn,
             base.ParserTemplate):

    def p_trapParams(self, args):
        """
        TrapV1Params ::= EnterpriseOid whitespace AgentName whitespace GenericTrap whitespace SpecificTrap whitespace Uptime whitespace VarBinds
        EnterpriseOid ::= string
        AgentName ::= string
        GenericTrap ::= genericTrap
        SpecificTrap ::= string
        Uptime ::= string

        TrapV2cParams ::= Uptime whitespace TrapOid whitespace VarBinds
        TrapOid ::= string
        """

    def p_paramsSpec(self, args):
        """
        Params ::= TrapV1Params
        Params ::= TrapV2cParams
        """

    def p_appOptions(self, args):
        """
        Option ::= ApplicationOption

        ApplicationOption ::= appopts whitespace string
        ApplicationOption ::= appopts string
        """


class __Generator(base.GeneratorTemplate):

    def n_ApplicationOption(self, cbCtx, node):

        snmpEngine, ctx = cbCtx

        if len(node) > 2:
            opt = node[2].attr

        else:
            opt = node[1].attr

        for c in opt:
            if c == 'i':
                ctx['informMode'] = 1

            else:
                raise error.PySnmpError('bad -C option - "%s"' % c)

    def n_EnterpriseOid(self, cbCtx, node):
        snmpEngine, ctx = cbCtx
        ctx['EnterpriseOid'] = node[0].attr

    def n_AgentName(self, cbCtx, node):
        snmpEngine, ctx = cbCtx

        try:
            ctx['AgentName'] = socket.gethostbyname(node[0].attr)

        except socket.error:
            raise error.PySnmpError(
                'Bad agent name %s: %s' % (node[0].attr, sys.exc_info()[1])
            )

    def n_GenericTrap(self, cbCtx, node):
        snmpEngine, ctx = cbCtx
        ctx['GenericTrap'] = node[0].attr

    def n_SpecificTrap(self, cbCtx, node):
        snmpEngine, ctx = cbCtx
        ctx['SpecificTrap'] = node[0].attr

    def n_Uptime(self, cbCtx, node):
        snmpEngine, ctx = cbCtx
        ctx['Uptime'] = int(node[0].attr)

    def n_TrapOid(self, cbCtx, node):
        snmpEngine, ctx = cbCtx
        ctx['TrapOid'] = node[0].attr

    def n_TrapV1Params_exit(self, cbCtx, node):
        snmpEngine, ctx = cbCtx

        # Initialize v1 PDU with passed params, then proxy it into v2c PDU
        v1Pdu = v1.TrapPDU()
        v1.apiTrapPDU.setDefaults(v1Pdu)

        if 'EnterpriseOid' in ctx:
            v1.apiTrapPDU.setEnterprise(v1Pdu, ctx['EnterpriseOid'])

        if 'AgentName' in ctx:
            v1.apiTrapPDU.setAgentAddr(v1Pdu, ctx['AgentName'])

        if 'GenericTrap' in ctx:
            v1.apiTrapPDU.setGenericTrap(v1Pdu, ctx['GenericTrap'])

        if 'SpecificTrap' in ctx:
            v1.apiTrapPDU.setSpecificTrap(v1Pdu, ctx['SpecificTrap'])

        if 'Uptime' in ctx:
            v1.apiTrapPDU.setTimeStamp(v1Pdu, ctx['Uptime'])

        ctx['pdu'] = rfc2576.v1ToV2(v1Pdu)

    def n_TrapV2cParams_exit(self, cbCtx, node):
        snmpEngine, ctx = cbCtx

        if 'informMode' in ctx:
            pdu = v2c.InformRequestPDU()
            v2c.apiPDU.setDefaults(pdu)

        else:
            pdu = v2c.TrapPDU()
            v2c.apiTrapPDU.setDefaults(pdu)

        v2c.apiPDU.setVarBinds(
            pdu,
            [(v2c.ObjectIdentifier('1.3.6.1.2.1.1.3.0'), v2c.TimeTicks(ctx['Uptime'])),
             (v2c.ObjectIdentifier('1.3.6.1.6.3.1.1.4.1.0'), v2c.ObjectIdentifier(ctx['TrapOid']))]
        )

        ctx['pdu'] = pdu


def generator(cbCtx, ast):
    snmpEngine, ctx = cbCtx
    return __Generator().preorder((snmpEngine, ctx), ast)


# Run SNMP engine


def cbFun(snmpEngine, notificationHandle, errorIndication, pdu, cbCtx):
    if errorIndication:
        sys.stderr.write('%s\n' % errorIndication)
        return

    errorStatus = v2c.apiPDU.getErrorStatus(pdu)
    varBinds = v2c.apiPDU.getVarBinds(pdu)

    if errorStatus:
        errorIndex = v2c.apiPDU.getErrorIndex(pdu)
        sys.stderr.write(
            '%s at %s\n' %
            (errorStatus.prettyPrint(),
             errorIndex and varBinds[int(errorIndex) - 1] or '?')
        )
        return

    for oid, val in varBinds:
        sys.stdout.write(
            '%s\n' % cbCtx['mibViewProxy'].getPrettyOidVal(
                cbCtx['mibViewController'], oid, val
            )
        )


snmpEngine = engine.SnmpEngine()

try:
    # Parse c/l into AST
    ast = Parser().parse(
        Scanner().tokenize(' '.join(sys.argv[1:]))
    )

    ctx = {}

    # Apply configuration to SNMP entity
    main.generator((snmpEngine, ctx), ast)
    msgmod.generator((snmpEngine, ctx), ast)
    secmod.generator((snmpEngine, ctx), ast)
    mibview.generator((snmpEngine, ctx), ast)
    target.generatorTrap((snmpEngine, ctx), ast)
    pdu.writePduGenerator((snmpEngine, ctx), ast)
    generator((snmpEngine, ctx), ast)

    v2c.apiPDU.setVarBinds(
        ctx['pdu'], v2c.apiPDU.getVarBinds(ctx['pdu']) + ctx['varBinds']
    )

    ntforg.NotificationOriginator().sendPdu(
        snmpEngine,
        ctx['addrName'],
        ctx.get('contextEngineId'),
        ctx.get('contextName', ''),
        ctx['pdu'],
        cbFun, ctx
    )

    snmpEngine.transportDispatcher.runDispatcher()

except KeyboardInterrupt:
    sys.stderr.write('Shutting down...\n')

except error.PySnmpError:
    sys.stderr.write('Error: %s\n%s' % (sys.exc_info()[1], getUsage()))
    sys.exit(1)

except Exception:
    sys.stderr.write('Process terminated: %s\n' % sys.exc_info()[1])

    for line in traceback.format_exception(*sys.exc_info()):
        sys.stderr.write(line.replace('\n', ';'))

    sys.exit(1)
