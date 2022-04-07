
from scapy.arch.windows import get_windows_if_list
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *


class SelectInterfaces(QDialog):
    Signal_interface = pyqtSignal(str)

    def __init__(self, parent=None):
        super(SelectInterfaces, self).__init__(parent)
        self.interfaces = []
        self.get_active_interface()
        self.initUI()

    def initUI(self):
        hbox = QHBoxLayout()

        # Add Interfaces Select Button
        interfaces_box = QVBoxLayout()
        interfaces_box.addStretch(1)
        interfaces_lab = QLabel('选择一个需要监听的网络接口：')
        interfaces_box.addWidget(interfaces_lab)
        for idx, intf in enumerate(self.interfaces):
            new_net = QRadioButton(intf['name'])
            button_tip = 'Name: %s\nIP: %s\nDescription: %s' % (intf['name'], intf['ip'], intf['desc'])
            new_net.setToolTip(button_tip)
            new_net.clicked.connect(lambda: self.net_button_clicked(self.sender()))
            if idx == 0:
                new_net.setChecked(True)
            interfaces_box.addWidget(new_net)
        interfaces_box.addStretch(1)
        hbox.addLayout(interfaces_box)

        # Message Frame
        message_box = QVBoxLayout()
        message_box.addStretch(1)
        author_label = QLabel('作者：陈晴方\n学号：202118018670053\n培养单位：信息工程研究所')
        message_box.addWidget(author_label)
        self.message_le = QLineEdit(self)
        self.message_le.setText(self.interfaces[0]['name'])
        message_box.addWidget(self.message_le)
        message_bot_box = QHBoxLayout()
        message_bot_box.addStretch(1)
        message_bot_exit = QPushButton('退出', self)
        message_bot_exit.setToolTip('退出Sniffer')
        message_bot_exit.clicked.connect(self.close)
        message_bot_exit.resize(message_bot_box.sizeHint())
        message_bot_box.addWidget(message_bot_exit)
        message_bot_ok = QPushButton('监听', self)
        message_bot_ok.setToolTip('开始抓取数据包')
        message_bot_ok.clicked.connect(self.interface_confirmed)
        message_bot_ok.resize(message_bot_ok.sizeHint())
        message_bot_box.addWidget(message_bot_ok)
        message_box.addLayout(message_bot_box)
        message_box.addStretch(1)
        hbox.addLayout(message_box)

        self.setLayout(hbox)
        self.setWindowTitle('Sniffer - Select Interface')
        self.resize(400, 250)
        self.window_center()
        self.setWindowIcon(QIcon('icons/web.png'))
        self.show()

    def window_center(self):
        fg = self.frameGeometry()
        dw = QDesktopWidget().availableGeometry().center()
        fg.moveCenter(dw)
        self.move(fg.topLeft())

    def net_button_clicked(self, sender):
        self.message_le.setText(sender.text())
        # print(sender.text())

    def interface_confirmed(self):
        final_interface = self.message_le.text()
        self.Signal_interface.emit(final_interface)
        self.close()

    def get_active_interface(self):
        _interfaces = get_windows_if_list()
        for itf in _interfaces:
            if itf['ips'].__len__() == 0:
                continue
            tmp = {}
            tmp['name'] = itf['name']
            tmp['desc'] = itf['description']
            tmp['ip'] = itf['ips'][1]
            self.interfaces.append(tmp)