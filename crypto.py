import re
import sys
import os
import ctypes
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QInputDialog, QLineEdit, QMessageBox
from PyQt5 import uic, QtWidgets
from PyQt5.QtGui import QIcon
import main


class Cryptor(QMainWindow):
    def __init__(self):
        super(Cryptor, self).__init__()
        uic.loadUi('ui_d.ui', self)
        self.setWindowTitle('Brian_Cliff')
        self.encrypt.clicked.connect(self.encrypty)
        self.decrypt.clicked.connect(self.decrypty)
        self.file_upload.clicked.connect(self.attach_file)
        self.clear.clicked.connect(self.clear_text)
    # Encryption method
    def encrypty(self):
        self.plain = self.text.toPlainText()
        if self.plain!='':
            self.setPasswd()
            print(self.spanner)
            ct=main.Cliff.encrypta(self, pt=self.plain,encpasswd=self.spanner)
            print(ct)
            self.text.clear()
            self.text.appendPlainText(ct)
            
        else:
            # change: Removed about
            QMessageBox.about(self,"Encryption status", "Nothing to encrypt")
    
  #Decryption method
    def decrypty(self):
        ctext=self.text.toPlainText()
        if ctext !='':
            self.setPasswd()
            print(self.spanner)
            pt=main.Cliff.decrypta(self, ct=ctext,passwd=self.spanner)
            print("pt123", pt)
            self.text.clear()
            self.text.appendPlainText(pt)
        else:
            # change: Removed about
            QMessageBox.about(self,"Decryption status", "Nothing to decrypt")
  
       
    def attach_file(self):
        options=QFileDialog.Options()
        options |=QFileDialog.DontUseNativeDialog
        fileName,_=QFileDialog.getOpenFileName(self, 'Select File',os.path.expanduser('~/Documentts'))
        if fileName:
            try:
                self.filename=fileName
                self.path.setText(fileName)
            except:
                return None
    
    
    def clear_text(self):
        beta=self.Text.toPlainText()
        alpha=self.path.Text()
        if beta !='':
            self.Text.clear()
        elif alpha!='':
            self.path.clear()
        else:
            QMessageBox.about(self,"Empty", "No Text to clear")
        if ctypes.windll.user32.OpenClipboard(None):
           ctypes.windll.user32.EmptyClipboard()
           ctypes.windll.user32.CloseClipboard()

    
    def setPasswd(self):
        text,ok=QInputDialog.getText(self,"Password","Kindly input password:",QLineEdit.Password,"")
        if text!='':
            if re.search(r".{8}", text) and re.search(r"[A-Z]", text) and re.search(r"[a-z]", text) and re.search(r"[0-9]", text) and re.search(r"[$!#@]", text) and re.search(r"\W", text):
                self.spanner = text
                self.confirmPassword()
            else:
                QMessageBox.about(self, "Password", "Weak Password \n Password should have at least \n one capital letter, \n number \n special character:")
                self.spanner = text
                self.setPasswd()
        else:
            pass


#define confirm password
    
    
    def confirmPassword(self):
        text, ok = QInputDialog.getText(self, "password", "Kindly re-enter the encryption password: ", QLineEdit.Password,"")
        if text!='':
            self.nut = text
            if self.nut == self.spanner:
                self.spanner = self.nut
            else:
                QMessageBox.about(self, "Error","password do not match")
                self.setPasswd()
        else:
            pass
          
        

if __name__=="__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setWindowIcon(QIcon("icon.jpg"))
    window = Cryptor()
    window.setWindowTitle('Brian_Cliff')
    window.show()
    sys.exit(app.exec_())