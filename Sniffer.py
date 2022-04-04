
from scapy.arch.windows import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from SelectInterfaces import SelectInterfaces


class Sniffer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.toGetInterface()

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
        filter_box.addWidget(self.filter_le)
        filter_box.addWidget(filter_but)
        vbox.addLayout(filter_box)

        # Packages
        self.package_lw = QListWidget()
        self.package_lw.clicked.connect(self.showDetails)
        # Details
        self.details_tw = QTreeWidget()
        self.details_tw.setColumnCount(1)
        self.details_tw.setHeaderLabel('Layer')
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
        self.window_center()
        self.setWindowIcon(QIcon('icons/web.png'))
        self.show()

    def toGetInterface(self):
        interface_dialog = SelectInterfaces(self)
        interface_dialog.Signal_interface.connect(self.dealInterface)
        interface_dialog.show()

    def dealInterface(self, interface_str):
        self.setWindowTitle('Sniffer - %s' % interface_str)
        self.package_lw.addItem(interface_str)
        print(interface_str)

    def toSaveData(self):
        print('Saving')

    def toStart(self):
        print('Start')

    def toStop(self):
        print('Stop')

    def showDetails(self):
        print('show')

    def window_center(self):
        fg = self.frameGeometry()
        dw = QDesktopWidget().availableGeometry().center()
        fg.moveCenter(dw)
        self.move(fg.topLeft())
