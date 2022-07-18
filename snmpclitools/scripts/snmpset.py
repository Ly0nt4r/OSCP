#!/usr/bin/env python
#
# This file is part of snmpclitools software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpclitools/license.html
#
# SET command generator
#
import os
import sys
import traceback

from pysnmp import error
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import cmdgen

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
%s%s%s%s%s%s
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
              pdu.WritePduScannerMixIn,
              main.MainScannerMixIn,
              base.ScannerTemplate):
    pass


class Parser(msgmod.MPParserMixIn,
             secmod.SMParserMixIn,
             mibview.MibViewParserMixIn,
             target.TargetParserMixIn,
             pdu.WritePduParserMixIn,
             main.MainParserMixIn,
             base.ParserTemplate):
    pass


# Run SNMP engine

def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBinds, cbCtx):

    if errorIndication:
        sys.stderr.write('%s\n' % errorIndication)

    elif errorStatus:
        sys.stderr.write(
            '%s at %s\n' %
            (errorStatus.prettyPrint(),
             errorIndex and varBinds[int(errorIndex) - 1] or '?')
        )

    else:
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
    target.generator((snmpEngine, ctx), ast)
    pdu.writePduGenerator((snmpEngine, ctx), ast)

    cmdgen.SetCommandGenerator().sendVarBinds(
        snmpEngine,
        ctx['addrName'],
        ctx.get('contextEngineId'), ctx.get('contextName', ''),
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
