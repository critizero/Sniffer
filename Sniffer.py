
from scapy.arch.windows import *
import threading
import os
from scapy.all import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from SelectInterfaces import SelectInterfaces

class Sniffer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.pkt_types_dir = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6', 0x88CC: 'LLDP', 0x891D: 'TTE'}
        self.ipv4_protocol = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6',
                              50: 'ESP', 89: 'OSPF'}
        self.tcp_port = {20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS'}
        self.udp_port = {53: 'DNS'}
        self.stop_capture = False
        self.packet_list = []
        self.process_interface = ''
        self.pkt_idx = 0

        self.initUI()
        self.toGetInterface()

    def dataInitial(self):
        self.stop_capture = False
        self.packet_list = []
        self.process_interface = ''
        self.pkt_idx = 0

    def initUI(self):
        hbox = QHBoxLayout()

        # 状态栏
        self.statusBar().showMessage('Ready')

        # 活动
        select_action = QAction(QIcon('icons/select.png'), 'Select Interface', self)
        select_action.setStatusTip('Select a interface')
        select_action.triggered.connect(self.toGetInterface)
        save_action = QAction(QIcon('icons/save.png'), 'Save', self)
        save_action.setStatusTip('Save package to file')
        save_action.triggered.connect(self.toSaveData)
        exit_action = QAction(QIcon('icons/exit.png'), 'Exit', self)
        exit_action.setStatusTip('Exit application')
        exit_action.triggered.connect(self.close)

        start_action = QAction(QIcon('icons/start.png'), 'Start', self)
        start_action.setStatusTip('Start')
        start_action.triggered.connect(self.toStart)
        stop_action = QAction(QIcon('icons/stop.png'), 'Stop', self)
        stop_action.setStatusTip('Stop')
        stop_action.triggered.connect(self.toStop)


        # 菜单栏
        menubar = self.menuBar()
        file_menu = menubar.addMenu('&File')
        file_menu.addAction(select_action)
        file_menu.addAction(save_action)
        file_menu.addAction(exit_action)

        # 工具栏
        file_toolbar = self.addToolBar('File')
        file_toolbar.addAction(exit_action)
        file_toolbar.addAction(select_action)
        file_toolbar.addAction(save_action)
        run_toolbar = self.addToolBar('Run')
        run_toolbar.addAction(start_action)
        run_toolbar.addAction(stop_action)

        vbox = QVBoxLayout()

        # Filter
        filter_box = QHBoxLayout()
        self.filter_le = QLineEdit(self)
        filter_but = QPushButton('Filter', self)
        filter_but.clicked.connect(self.toStart)
        filter_box.addWidget(self.filter_le)
        filter_box.addWidget(filter_but)
        vbox.addLayout(filter_box)

        # Packages
        self.package_lw = QListWidget()
        self.package_lw.itemClicked.connect(self.showDetails)
        self.package_lw.itemDoubleClicked.connect(self.showDoubleDetails)
        # Details
        self.details_tw = QTreeWidget()
        self.details_tw.setColumnCount(2)
        self.details_tw.setHeaderLabels(['Layer', 'Value'])
        # Binary data
        self.binary_te = QTextEdit()

        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(self.package_lw)
        main_splitter.addWidget(self.details_tw)
        main_splitter.addWidget(self.binary_te)
        vbox.addWidget(main_splitter)

        global_widget = QWidget()
        global_widget.setLayout(vbox)
        self.setCentralWidget(global_widget)

        self.setWindowTitle('Sniffer')
        self.resize(1200, 800)
        self.windowCenter()
        self.setWindowIcon(QIcon('icons/web.png'))
        self.show()

    def toGetInterface(self):
        interface_dialog = SelectInterfaces(self)
        interface_dialog.Signal_interface.connect(self.dealInterface)
        interface_dialog.show()

    def dealInterface(self, interface_str):
        self.setWindowTitle('Sniffer - %s' % interface_str)
        # self.package_lw.addItem(interface_str)
        self.process_interface = interface_str
        self.toStart()
        print(interface_str)

    def toSaveData(self):
        print('Saving')
        # For safely saving
        do_save = threading.Thread(target=self.doSaveData(), daemon=False)
        do_save.start()

    def doSaveData(self):
        file_name, ok = QFileDialog.getSaveFileName(self, 'Save File', 'package.pcap', 'pcap(*.pcap)')
        try:
            for pkt in self.packet_list:
                wrpcap(file_name, pkt, append=True)
        except Exception as err:
            print(err)

    def toStart(self):
        print('Start')
        do_capture = threading.Thread(target=self.doStart, daemon=True)
        do_capture.start()

    def doStart(self):
        self.dataInitial()
        self.package_lw.clear()
        filter_message = self.filter_le.text()
        try:
            sniff(iface=self.process_interface, filter=filter_message, prn=self.processPackage, stop_filter=self.isStop)
        except Exception as err:
            print(err)
        finally:
            print('finish')

    def processPackage(self, x):
        self.packet_list.append(x)
        pkt_idx = self.pkt_idx
        self.pkt_idx += 1
        pkt_src = x[Ether].src
        pkt_dst = x[Ether].dst
        pkt_type = x[Ether].type
        pkt_protocol = 'LOOP'
        if pkt_type in self.pkt_types_dir:
            pkt_protocol = self.pkt_types_dir[pkt_type]
        if pkt_protocol == 'IPv4':
            pkt_src = x[IP].src
            pkt_dst = x[IP].dst
            pkt_type = x[IP].proto
            if pkt_type in self.ipv4_protocol:
                pkt_protocol = self.ipv4_protocol[pkt_type]
        if TCP in x:
            sport = x[TCP].sport
            dport = x[TCP].dport
            if sport in self.tcp_port:
                pkt_protocol = self.tcp_port[sport]
            if dport in self.tcp_port:
                pkt_protocol = self.tcp_port[dport]
        if UDP in x:
            sport = x[UDP].sport
            dport = x[UDP].dport
            if sport in self.udp_port:
                pkt_protocol = self.tcp_port[sport]
            if dport in self.udp_port:
                pkt_protocol = self.tcp_port[dport]
        pkt_info = x.summary()
        pkt_detail = "{0:0>5} | {1:<20} -> {2:<20} | {3:<10} | {4:<30}".format(pkt_idx, pkt_src, pkt_dst, pkt_protocol,
                                                                               pkt_info)
        self.package_lw.addItem(pkt_detail)

    def toStop(self):
        print('Stop')
        self.stop_capture = True

    def isStop(self, x):
        return self.stop_capture

    def showDoubleDetails(self, item):
        print('double click show')
        self.showDetails(item)
        idx = int(item.text().split('|')[0])
        pkt = self.packet_list[idx]
        raw_details = pkt.show(dump=True)
        QMessageBox.information(self, 'Details', raw_details, QMessageBox.Yes)

    def showDetails(self, item):
        print('show')
        self.binary_te.clear()
        self.details_tw.clear()
        try:
            idx = int(item.text().split('|')[0])
            pkt = self.packet_list[idx]
            # hexdump(pkt)
            self.fillTreeDetails(pkt)
            self.binary_te.setPlainText(hexdump(pkt, dump=True))
        except Exception as err:
            print(err)

    def fillTreeDetails(self, pkt):
        print('tree')

        ether = QTreeWidgetItem(self.details_tw)
        ether.setText(0, 'Ether')
        ether_dst = QTreeWidgetItem(ether)
        ether_dst.setText(0, 'dst')
        ether_dst.setText(1, pkt[Ether].dst)
        ether_src = QTreeWidgetItem(ether)
        ether_src.setText(0, 'src')
        ether_src.setText(1, pkt[Ether].src)
        ether_type = QTreeWidgetItem(ether)
        ether_type.setText(0, 'type')
        if pkt[Ether].type in self.pkt_types_dir:
            ether_type.setText(1, self.pkt_types_dir[pkt[Ether].type])
        else:
            ether_type.setText(1, hex(pkt[Ether].type))

        if IP in pkt:
            ipv4 = QTreeWidgetItem(self.details_tw)
            ipv4.setText(0, 'IP')
            ip_version = QTreeWidgetItem(ipv4)
            ip_version.setText(0, 'version')
            ip_version.setText(1, str(pkt[IP].version))
            ip_ihl = QTreeWidgetItem(ipv4)
            ip_ihl.setText(0, 'ihl')
            ip_ihl.setText(1, str(pkt[IP].ihl))
            ip_tos = QTreeWidgetItem(ipv4)
            ip_tos.setText(0, 'tos')
            ip_tos.setText(1, str(pkt[IP].tos))
            ip_len = QTreeWidgetItem(ipv4)
            ip_len.setText(0, 'length')
            ip_len.setText(1, hex(pkt[IP].len))
            ip_id = QTreeWidgetItem(ipv4)
            ip_id.setText(0, 'id')
            ip_id.setText(1, hex(pkt[IP].id))
            ip_flags = QTreeWidgetItem(ipv4)
            ip_flags.setText(0, 'flags')
            ip_flags.setText(1, pkt[IP].flags.__str__())
            ip_frag = QTreeWidgetItem(ipv4)
            ip_frag.setText(0, 'frag')
            ip_frag.setText(1, str(pkt[IP].frag))
            ip_ttl = QTreeWidgetItem(ipv4)
            ip_ttl.setText(0, 'ttl')
            ip_ttl.setText(1, hex(pkt[IP].ttl))
            ip_proto = QTreeWidgetItem(ipv4)
            ip_proto.setText(0, 'protocol')
            if pkt[IP].proto in self.ipv4_protocol:
                ip_proto.setText(1, self.ipv4_protocol[pkt[IP].proto])
            else:
                ip_proto.setText(1, hex(pkt[IP].proto))
            ip_chksum = QTreeWidgetItem(ipv4)
            ip_chksum.setText(0, 'checksum')
            ip_chksum.setText(1, hex(pkt[IP].chksum))
            ip_src = QTreeWidgetItem(ipv4)
            ip_src.setText(0, 'src')
            ip_src.setText(1, pkt[IP].src)
            ip_dst = QTreeWidgetItem(ipv4)
            ip_dst.setText(0, 'dst')
            ip_dst.setText(1, pkt[IP].dst)
            ip_options = QTreeWidgetItem(ipv4)
            ip_options.setText(0, 'options')
            ip_options.setText(1, str(pkt[IP].options))

        if ARP in pkt:
            arp = QTreeWidgetItem(self.details_tw)
            arp.setText(0, 'ARP')
            arp_hwtype = QTreeWidgetItem(arp)
            arp_hwtype.setText(0, 'hwtype')
            arp_hwtype.setText(1, hex(pkt[ARP].hwtype))
            arp_ptype = QTreeWidgetItem(arp)
            arp_ptype.setText(0, 'ptype')
            arp_ptype.setText(1, hex(pkt[ARP].ptype))
            arp_hwlen = QTreeWidgetItem(arp)
            arp_hwlen.setText(0, 'hwlen')
            arp_hwlen.setText(1, hex(pkt[ARP].hwlen))
            arp_plen = QTreeWidgetItem(arp)
            arp_plen.setText(0, 'plen')
            arp_plen.setText(1, hex(pkt[ARP].plen))
            arp_op = QTreeWidgetItem(arp)
            arp_op.setText(0, 'op')
            arp_op.setText(1, pkt[ARP].op)
            arp_hwsrc = QTreeWidgetItem(arp)
            arp_hwsrc.setText(0, 'hwsrc')
            arp_hwsrc.setText(1, pkt[ARP].hwsrc)
            arp_psrc = QTreeWidgetItem(arp)
            arp_psrc.setText(0, 'psrc')
            arp_psrc.setText(1, pkt[ARP].psrc)
            arp_hwdst = QTreeWidgetItem(arp)
            arp_hwdst.setText(0, 'hwdst')
            arp_hwdst.setText(1, pkt[ARP].hedst)
            arp_pdst = QTreeWidgetItem(arp)
            arp_pdst.setText(0, 'pdst')
            arp_pdst.setText(1, pkt[ARP].pdst)

        if TCP in pkt:
            tcp = QTreeWidgetItem(self.details_tw)
            tcp.setText(0, 'TCP')
            tcp_sport = QTreeWidgetItem(tcp)
            tcp_sport.setText(0, 'sport')
            if pkt[TCP].sport in self.tcp_port:
                tcp_sport.setText(1, self.tcp_port[pkt[TCP].sport])
            else:
                tcp_sport.setText(1, str(pkt[TCP].sport))
            tcp_dport = QTreeWidgetItem(tcp)
            tcp_dport.setText(0, 'dport')
            if pkt[TCP].dport in self.tcp_port:
                tcp_dport.setText(1, self.tcp_port[pkt[TCP].dport])
            else:
                tcp_dport.setText(1, str(pkt[TCP].dport))
            tcp_seq = QTreeWidgetItem(tcp)
            tcp_seq.setText(0, 'seq')
            tcp_seq.setText(1, str(pkt[TCP].seq))
            tcp_ack = QTreeWidgetItem(tcp)
            tcp_ack.setText(0, 'ack')
            tcp_ack.setText(1, str(pkt[TCP].ack))
            tcp_dataofs = QTreeWidgetItem(tcp)
            tcp_dataofs.setText(0, 'dataofs')
            tcp_dataofs.setText(1, str(pkt[TCP].dataofs))
            tcp_reserved = QTreeWidgetItem(tcp)
            tcp_reserved.setText(0, 'reserved')
            tcp_reserved.setText(1, str(pkt[TCP].reserved))
            tcp_window = QTreeWidgetItem(tcp)
            tcp_window.setText(0, 'window')
            tcp_window.setText(1, str(pkt[TCP].window))
            tcp_chksum = QTreeWidgetItem(tcp)
            tcp_chksum.setText(0, 'checksum')
            tcp_chksum.setText(1, str(pkt[TCP].chksum))
            tcp_urgptr = QTreeWidgetItem(tcp)
            tcp_urgptr.setText(0, 'urgptr')
            tcp_urgptr.setText(1, str(pkt[TCP].urgptr))
            tcp_options = QTreeWidgetItem(tcp)
            tcp_options.setText(0, 'options')
            tcp_options.setText(1, str(pkt[TCP].options))

        if UDP in pkt:
            udp = QTreeWidgetItem(self.details_tw)
            udp.setText(0, 'UDP')
            udp_sport = QTreeWidgetItem(udp)
            udp_sport.setText(0, 'sport')
            if pkt[UDP].sport in self.udp_port:
                udp_sport.setText(1, self.udp_port[pkt[UDP].sport])
            else:
                udp_sport.setText(1, str(pkt[UDP].sport))
            udp_dport = QTreeWidgetItem(udp)
            udp_dport.setText(0, 'dport')
            if pkt[UDP].dport in self.udp_port:
                udp_dport.setText(1, self.udp_port[pkt[UDP].dport])
            else:
                udp_dport.setText(1, str(pkt[UDP].dport))
            udp_len = QTreeWidgetItem(udp)
            udp_len.setText(0, 'length')
            udp_len.setText(1, str(pkt[UDP].len))
            udp_chksum = QTreeWidgetItem(udp)
            udp_chksum.setText(0, 'checksum')
            udp_chksum.setText(1, str(pkt[UDP].chksum))

        if Raw in pkt:
            raw = QTreeWidgetItem(self.details_tw)
            raw.setText(0, 'Raw')
            raw_load = QTreeWidgetItem(raw)
            raw_load.setText(0, 'load')
            raw_load.setText(1, str(pkt[Raw].load))

        if Padding in pkt:
            padding = QTreeWidgetItem(self.details_tw)
            padding.setText(0, 'Padding')
            padding_load = QTreeWidgetItem(padding)
            padding_load.setText(0, 'load')
            padding_load.setText(1, str(pkt[Padding].load))


    # def hexDump(self, src):
    #     result = []
    #     for i in range(0, len(src), 16):
    #         s = src[i:i + 16]
    #         hex_part = ' '.join([hex(x)[2:].upper().zfill(2) for x in s])
    #         text_part = ''.join([chr(x) if 0x20 <= x < 0x7f else '.' for x in s])
    #         result.append("{0:04X}".format(i) + ' '*3 + hex_part.ljust(48) + ' '*3 + text_part)
    #     return '\n'.join(result)

    def windowCenter(self):
        fg = self.frameGeometry()
        dw = QDesktopWidget().availableGeometry().center()
        fg.moveCenter(dw)
        self.move(fg.topLeft())
