#!/usr/bin/env python
# This file is part of snmpclitools software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpclitools/license.html
#
# GETBULK command generator
#
import os
import sys
import time
import traceback

from pysnmp import error
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.proto import rfc1902

from snmpclitools.cli import base
from snmpclitools.cli import main
from snmpclitools.cli import mibview
from snmpclitools.cli import msgmod
from snmpclitools.cli import pdu
from snmpclitools.cli import secmod
from snmpclitools.cli import target


def getUsage():
    return """\
Usage: %s [OPTIONS] <AGENT> <PARAMETERS>
%s%s%s%s
GETBULK options:
-C BULKOPTS:   set various application specific behaviours:
          n<NUM>   set non-repeaters to <NUM>
          r<NUM>   set max-repetitions to <NUM>
          c:       do not check returned OIDs are increasing
          t:       display wall-clock time to complete the request
          p:       print the number of variables found
%s%s\
""" % (os.path.basename(sys.argv[0]), main.getUsage(), msgmod.getUsage(),
       secmod.getUsage(), mibview.getUsage(), target.getUsage(),
       pdu.getReadUsage())


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


class Parser(msgmod.MPParserMixIn,
             secmod.SMParserMixIn,
             mibview.MibViewParserMixIn,
             target.TargetParserMixIn,
             pdu.ReadPduParserMixIn,
             main.MainParserMixIn,
             base.ParserTemplate):

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

        p = n = r = None

        for c in opt:
            if c == 'n':
                p = n = []

            elif c == 'r':
                p = r = []

            elif c == 'c':
                ctx['ignoreNonIncreasingOids'] = 1
                p = None

            elif c == 't':
                ctx['displayWallClock'] = time.time()
                p = None

            elif c == 'p':
                ctx['reportFoundVars'] = 1
                p = None

            elif p is not None and '0' <= c <= '9':
                p.append(c)

            else:
                raise error.PySnmpError('bad -C option - "%s"' % c)

        if n is not None:
            ctx['nonRepeaters'] = int(''.join(n))

        if r is not None:
            ctx['maxRepetitions'] = int(''.join(r))


def generator(cbCtx, ast):
    snmpEngine, ctx = cbCtx
    return __Generator().preorder((snmpEngine, ctx), ast)


def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBindTable, cbCtx):

    if errorIndication:
        if (errorIndication != 'oidNotIncreasing' or
                not ctx.get('ignoreNonIncreasingOids')):
            sys.stderr.write('Error: %s\n' % errorIndication)
            return

    if errorStatus:
        sys.stderr.write(
            '%s at %s\n' %
            (errorStatus.prettyPrint(),
             errorIndex and varBindTable[0][int(errorIndex) - 1] or '?')
        )
        return

    for varBindRow in varBindTable:
        colIdx = -1
        inTableFlag = 0

        for oid, val in varBindRow:
            colIdx += 1

            if cbCtx['myHeadVars'][colIdx].isPrefixOf(oid):
                sys.stdout.write(
                    '%s\n' % cbCtx['mibViewProxy'].getPrettyOidVal(
                        cbCtx['mibViewController'], oid, val
                    )
                )
                inTableFlag += 1

        if cbCtx.get('reportFoundVars'):
            cbCtx['reportFoundVars'] += inTableFlag

        if not inTableFlag:
            return  # stop on end-of-table

    return True  # continue walking


# Run SNMP engine

snmpEngine = engine.SnmpEngine()

ctx = {}

try:
    # Parse c/l into AST
    ast = Parser().parse(
        Scanner().tokenize(' '.join(sys.argv[1:]))
    )

    # Apply configuration to SNMP entity
    main.generator((snmpEngine, ctx), ast)
    msgmod.generator((snmpEngine, ctx), ast)
    secmod.generator((snmpEngine, ctx), ast)
    mibview.generator((snmpEngine, ctx), ast)
    target.generator((snmpEngine, ctx), ast)
    pdu.readPduGenerator((snmpEngine, ctx), ast)
    generator((snmpEngine, ctx), ast)

    ctx['myHeadVars'] = [rfc1902.ObjectName(x[0]) for x in ctx['varBinds']]

    cmdgen.BulkCommandGenerator().sendVarBinds(
        snmpEngine,
        ctx['addrName'],
        ctx.get('contextEngineId'), ctx.get('contextName', ''),
        ctx.get('nonRepeaters', 0), ctx.get('maxRepetitions', 25),
        ctx['varBinds'],
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

if ctx.get('reportFoundVars'):
    sys.stdout.write(
        'Variables found: %s\n' % (ctx['reportFoundVars'] - 1))

if ctx.get('displayWallClock'):
    sys.stdout.write(
        'Total traversal time = %.4f seconds'
        '\n' % (time.time() - ctx['displayWallClock']))
