import os
from lxml import etree
from app.utils.logs import CustomLogger

# Logging configuration
logger = CustomLogger('test')

class NmapXMLReport:
    class NmapRun:
        def __init__(self, element):
            self.scanner = element.get('scanner')
            self.args = element.get('args')
            self.start = element.get('start')
            self.startstr = element.get('startstr')
            self.version = element.get('version')
            self.profile_name = element.get('profile_name')
            self.xmloutputversion = element.get('xmloutputversion')

        def __str__(self):
            return f"NmapRun(scanner={self.scanner}, args={self.args}, start={self.start}, startstr={self.startstr}, version={self.version}, profile_name={self.profile_name}, xmloutputversion={self.xmloutputversion})"

    class ScanInfo:
        def __init__(self, element):
            self.type = element.get('type')
            self.scanflags = element.get('scanflags')
            self.protocol = element.get('protocol')
            self.numservices = element.get('numservices')
            self.services = element.get('services')

        def __str__(self):
            return f"ScanInfo(type={self.type}, scanflags={self.scanflags}, protocol={self.protocol}, numservices={self.numservices}, services={self.services})"

    class Verbose:
        def __init__(self, element):
            self.level = element.get('level')

        def __str__(self):
            return f"Verbose(level={self.level})"

    class Debugging:
        def __init__(self, element):
            self.level = element.get('level')

        def __str__(self):
            return f"Debugging(level={self.level})"

    class Target:
        def __init__(self, element):
            self.specification = element.get('specification')
            self.status = element.get('status')
            self.reason = element.get('reason')

        def __str__(self):
            return f"Target(specification={self.specification}, status={self.status}, reason={self.reason})"

    class TaskBegin:
        def __init__(self, element):
            self.task = element.get('task')
            self.time = element.get('time')
            self.extrainfo = element.get('extrainfo')
        def __str__(self):
            return f"TaskBegin(task={self.task}, time={self.time}, extrainfo={self.extrainfo})"

    class TaskProgress:
        def __init__(self, element):
            self.task = element.get('task')
            self.time = element.get('time')
            self.percent = element.get('percent')
            self.remaining = element.get('remaining')
            self.etc = element.get('etc')
        def __str__(self):
            return f"TaskProgress(task={self.task}, time={self.time}, percent={self.percent}, remaining={self.percent}, etc={self.etc})"

    class TaskEnd:
        def __init__(self, element):
            self.task = element.get('task')
            self.time = element.get('time')
            self.extrainfo = element.get('extrainfo')

        def __str__(self):
            return f"TaskEnd(task={self.task}, time={self.time}, extrainfo={self.extrainfo})"

    class Host:
        def __init__(self, element):
            self.starttime = element.get('starttime')
            self.endtime = element.get('endtime')
            self.timedout = element.get('timedout')
            self.comment = element.get('comment')
            self.status = [NmapXMLReport.Status(e) for e in element.findall('status')]
            self.addresses = [NmapXMLReport.Address(e) for e in element.findall('address')]
            self.hostnames = [NmapXMLReport.Hostnames(e) for e in element.findall('hostnames')]
            self.ports = [self.Port(e) for e in element.findall('ports/port')]
            self.extraports = [self.Extraports(e) for e in element.findall('ports/extraports')]
            self.os = [self.OS(e) for e in element.findall('os')]
            self.distance = [self.Distance(e) for e in element.findall('distance')]
            self.uptime = [self.Uptime(e) for e in element.findall('uptime')]
            self.tcpsequence = [self.TcpSequence(e) for e in element.findall('tcpsequence')]
            self.ipidsequence = [self.IpidSequence(e) for e in element.findall('ipidsequence')]
            self.tcptssequence = [self.TcptsSequence(e) for e in element.findall('tcptssequence')]
            self.trace = [self.Trace(e) for e in element.findall('trace')]

        def __str__(self):
            return f"Host(starttime={self.starttime}, endtime={self.endtime}, timedout={self.timedout}, comment={self.comment}, status={self.status}, addresses={self.addresses}, hostnames={self.hostnames}, ports={self.ports}, extraports={self.extraports})"

        class Port:
            def __init__(self, element):
                self.protocol = element.get('protocol')
                self.portid = element.get('portid')
                self.state = [self.State(e) for e in element.findall('state')]
                self.owner = [self.Owner(e) for e in element.findall('owner')]
                self.service = [self.Service(e) for e in element.findall('service')]
                self.script = [self.Script(e) for e in element.findall('script')]

            def __str__(self):
                return f"Port(protocol={self.protocol}, portid={self.portid}, state={self.state})"

            class State:
                def __init__(self, element):
                    self.state = element.get('state')
                    self.reason = element.get('reason')
                    self.reason_ttl = element.get('reason_ttl')
                    self.reason_ip = element.get('reason_ip')

                def __str__(self):
                    return f"State(state={self.state}, reason={self.reason}, reason_ttl={self.reason_ttl}, reason_ip={self.reason_ip})"

            class Owner:
                def __init__(self, element):
                    self.name = element.get('name')

                def __str__(self):
                    return f"Owner(name={self.name})"

            class Service:
                def __init__(self, element):
                    self.name = element.get('name')
                    self.conf = element.get('conf')
                    self.method = element.get('method')
                    self.version = element.get('version')
                    self.product = element.get('product')
                    self.extrainfo = element.get('extrainfo')
                    self.tunnel = element.get('tunnel')
                    self.proto = element.get('proto')
                    self.rpcnum = element.get('rpcnum')
                    self.lowver = element.get('lowver')
                    self.highver = element.get('highver')
                    self.hostname = element.get('hostname')
                    self.ostype = element.get('ostype')
                    self.devicetype = element.get('devicetype')
                    self.servicefp = element.get('servicefp')
                    self.cpe = [cpe.text for cpe in element.findall('cpe')]

                def __str__(self):
                    return f"Service(name={self.name}, conf={self.conf}, method={self.method}, version={self.version}, product={self.product}, extrainfo={self.extrainfo}, tunnel={self.tunnel}, proto={self.proto}, rpcnum={self.rpcnum}, lowver={self.lowver}, highver={self.highver}, hostname={self.hostname}, ostype={self.ostype}, devicetype={self.devicetype}, servicefp={self.servicefp}, cpe={self.cpe})"

                class Cpe:
                    def __init__(self, element):
                        self.cpe_data = element.text

                    def __str__(self):
                        return f"Cpe(cpe_data={self.cpe_data})"

            class Script:
                def __init__(self, element):
                    self.id = element.get('id')
                    self.output = element.get('output')
                    self.content = element.text

                def __str__(self):
                    return f"Script(id={self.id}, output={self.output}, content={self.content})"

        class Extraports:
            def __init__(self, element):
                self.state = element.get('state')
                self.count = element.get('count')
                self.extrareasons = [self.Extrareasons(e) for e in element.findall('extrareasons')]

            def __str__(self):
                return f"Extraports(state={self.state}, count={self.count}, extrareasons={self.extrareasons})"

            class Extrareasons:
                def __init__(self, element):
                    self.reason = element.get('reason')
                    self.count = element.get('count')
                    self.proto = element.get('proto')
                    self.ports = element.get('ports')

                def __str__(self):
                    return f"Extrareasons(reason={self.reason}, count={self.count}, proto={self.proto}, ports={self.ports})"

        class OS:
            def __init__(self, element):
                self.portused = [self.PortUsed(portused) for portused in element.findall('portused')]
                self.osmatch = [self.OSMatch(osmatch) for osmatch in element.findall('osmatch')]
                self.osfingerprint = [self.OSFingerprint(osfingerprint) for osfingerprint in
                                      element.findall('osfingerprint')]

            def __str__(self):
                return f'OS(portused={self.portused}, osmatch={self.osmatch}, osfingerprint={self.osfingerprint})'

            class PortUsed:
                def __init__(self, element):
                    self.state = element.get('state')
                    self.proto = element.get('proto')
                    self.portid = element.get('portid')

                def __str__(self):
                    return f'PortUsed(state={self.state}, proto={self.proto}, portid={self.portid})'

            class OSMatch:
                def __init__(self, element):
                    self.name = element.get('name')
                    self.accuracy = element.get('accuracy')
                    self.line = element.get('line')
                    self.osclass = [self.OSClass(osclass) for osclass in element.findall('osclass')]

                def __str__(self):
                    return f'OSMatch(name={self.name}, accuracy={self.accuracy}, line={self.line}, osclass={self.osclass})'

                class OSClass:
                    def __init__(self, element):
                        self.vendor = element.get('vendor')
                        self.osgen = element.get('osgen')
                        self.type = element.get('type')
                        self.accuracy = element.get('accuracy')
                        self.osfamily = element.get('osfamily')
                        self.cpe = [cpe.text for cpe in element.findall('cpe')]

                    def __str__(self):
                        return f'OSClass(vendor={self.vendor}, osgen={self.osgen}, type={self.type}, accuracy={self.accuracy}, osfamily={self.osfamily}, cpe={self.cpe})'

            class OSFingerprint:
                def __init__(self, element):
                    self.fingerprint = element.get('fingerprint')

                def __str__(self):
                    return f'OSFingerprint(fingerprint={self.fingerprint})'

        class Distance:
            def __init__(self, element):
                self.value = element.get('value')

            def __str__(self):
                return f'Distance(value={self.value})'

        class Uptime:
            def __init__(self, element):
                self.seconds = element.get('seconds')
                self.lastboot = element.get('lastboot')

            def __str__(self):
                return f'Uptime(seconds={self.seconds}, lastboot={self.lastboot})'

        class TcpSequence:
            def __init__(self, element):
                self.index = element.get('index')
                self.difficulty = element.get('difficulty')
                self.values = element.get('values')

            def __str__(self):
                return f'TcpSequence(index={self.index}, difficulty={self.difficulty}, values={self.values})'

        class IpidSequence:
            def __init__(self, element):
                self.class_ = element.get('class')
                self.values = element.get('values')

            def __str__(self):
                return f'IpidSequence(class={self.class_}, values={self.values})'

        class TcptsSequence:
            def __init__(self, element):
                self.class_ = element.get('class')
                self.values = element.get('values')

            def __str__(self):
                return f'TcptsSequence(class={self.class_}, values={self.values})'

        class Trace:
            def __init__(self, element):
                self.proto = element.get('proto')
                self.port = element.get('port')
                self.hops = [self.Hop(e) for e in element.findall('hop')]

            def __str__(self):
                return f'Trace(proto={self.proto}, port={self.port}, hops={self.hops})'

            class Hop:
                def __init__(self, element):
                    self.ttl = element.get('ttl')
                    self.rtt = element.get('rtt')
                    self.ipaddr = element.get('ipaddr')
                    self.host = element.get('host')

                def __str__(self):
                    return f'Hop(ttl={self.ttl}, rtt={self.rtt}, ipaddr={self.ipaddr}, host={self.host})'

    class Status:
        def __init__(self, element):
            self.state = element.get('state')
            self.reason = element.get('reason')
            self.reason_ttl = element.get('reason_ttl')

        def __str__(self):
            return f"Status(state={self.state}, reason={self.reason}, reason_ttl={self.reason_ttl})"

    class Address:
        def __init__(self, element):
            self.addr = element.get('addr')
            self.addrtype = element.get('addrtype')
            self.vendor = element.get('vendor')

        def __str__(self):
            return f"Address(addr={self.addr}, addrtype={self.addrtype}, vendor={self.vendor})"

    class Hostnames:
        def __init__(self, element):
            self.hostnames = [self.Hostname(e) for e in element.findall('hostname')]

        def __str__(self):
            return f"Hostnames(hostnames={self.hostnames})"

        class Hostname:
            def __init__(self, element):
                self.name = element.get('name')
                self.type = element.get('type')

            def __str__(self):
                return f"Hostname(name={self.name}, type={self.type})"

    class HostHint:
        def __init__(self, element):
            self.status = NmapXMLReport.Status(element.find('status'))
            self.addresses = [NmapXMLReport.Address(e) for e in element.findall('address')]
            self.hostnames = NmapXMLReport.Hostnames(element.find('hostnames'))
        def __str__(self):
            return f"HostHint(status={self.status}, addresses={self.addresses}, hostnames={self.hostnames})"

    class Table:
        def __init__(self, element):
            self.key = element.get('key')
            self.table_elements = [self.Elem(elem) for elem in element.findall('elem')]
            self.nested_tables = [self.Table(table) for table in element.findall('table')]

        def __str__(self):
            return f"Table(key={self.key}, table_elements={self.table_elements}, nested_tables={self.nested_tables})"

        class Elem:
            def __init__(self, element):
                self.key = element.get('key')
                self.content = element.text

            def __str__(self):
                return f"Elem(key={self.key}, content={self.content})"

    def __init__(self, xml_file):

        self.xml_file = xml_file
        if NmapXMLReport.validateNmapDTD(self):
            tree = etree.parse(self.xml_file)
            root = tree.getroot()

            self.nmaprun = [self.NmapRun(e) for e in root.findall('nmaprun')]
            self.scaninfo = [self.ScanInfo(e) for e in root.findall('scaninfo')]
            self.verbose = [self.Verbose(e) for e in root.findall('verbose')]
            self.debugging = [self.Debugging(e) for e in root.findall('debugging')]
            self.target = [self.Target(e) for e in root.findall('target')]
            self.task_begins = [self.TaskBegin(e) for e in root.findall('taskbegin')]
            self.task_progresses = [self.TaskProgress(e) for e in root.findall('taskprogress')]
            self.task_ends = [self.TaskEnd(e) for e in root.findall('taskend')]
            self.hosts = [self.Host(e) for e in root.findall('host')]
            self.hosthints = [self.HostHint(e) for e in root.findall('hosthint')]

    def __str__(self):
        return f"NmapXMLReport(\n{self.nmaprun}\n{self.scaninfo}\n{self.verbose}\n{self.debugging}\n{self.target}\n{self.task_begins}\n{self.task_progresses}\n{self.task_ends})"

    def validateNmapDTD(self):
        try:
            dir_path = os.path.dirname(os.path.realpath(__file__))
            xml_dtd = os.path.join(dir_path, 'data', 'nmap.dtd')
            xml_file = self.xml_file
            xml_file = etree.parse(xml_file)

            # Parse the DTD file
            with open(xml_dtd, 'rb') as f:
                dtd = etree.DTD(f)

            # Validate the XML against the DTD
            is_valid = dtd.validate(xml_file)

            return is_valid
        except OSError as OE:
            logger.error(OE)
            exit(1)

# PARSER EXAMPLES
"""
nmap_report = NmapXMLReport('../../examples/Offsec/DC-4/nmap/tcp-1000-scripts.xml')
print(nmap_report)

for nmaprun in nmap_report.nmaprun:
    print(nmaprun)

for scaninfo in nmap_report.scaninfo:
    print(scaninfo)

for verbose in nmap_report.verbose:
    print(verbose)

for debugging in nmap_report.debugging:
    print(debugging)

for target in nmap_report.target:
    print(target)

for task_begins in nmap_report.task_begins:
    print(task_begins)

for task_progresses in nmap_report.task_progresses:
    print(task_progresses)

for task_ends in nmap_report.task_ends:
    print(task_ends)

for host in nmap_report.hosts:
    for status in host.status:
        print(status)
    for address in host.addresses:
        print(address)

    for hostnames in host.hostnames:
        for hostname in hostnames.hostnames:
            print(hostname)
    for port in host.ports:
        for state in port.state:
            print(state)

        for owner in port.owner:
            print(owner)

        for service in port.service:
            print(service)

        for script in port.script:
            print(script)

    for os in host.os:
        print(os)
        for portused in os.portused:
            print(portused)

        for osmatch in os.osmatch:
            print(osmatch)

            for osclass in osmatch.osclass:
                print(osclass)

                for cpe in osclass.cpe:
                    print(cpe)

        for osfingerprint in os.osfingerprint:
            print(osfingerprint)

    for distance in host.distance:
        print(distance)

    for uptime in host.uptime:
        print(uptime)

    for tcpsequence in host.tcpsequence:
        print(tcpsequence)

    for ipidsequence in host.ipidsequence:
        print(ipidsequence)

    for tcptssequence in host.tcptssequence:
        print(tcptssequence)

    for trace in host.trace:
        print(trace)
        for hops in trace.hops:
            print(hops)

for hosthints in nmap_report.hosthints:
    print(hosthints)
"""