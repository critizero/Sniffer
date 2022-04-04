
import sys
from scapy.arch.windows import *
from PyQt5.QtWidgets import QApplication
import Sniffer


if __name__ == '__main__':
    app = QApplication(sys.argv)
    sniffer = Sniffer.Sniffer()
    sys.exit(app.exec_())
