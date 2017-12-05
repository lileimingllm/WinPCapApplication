#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <PCapWrapper.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
//    SOCKET * socket;
//    recv();
}

MainWindow::~MainWindow()
{
    delete ui;
}
