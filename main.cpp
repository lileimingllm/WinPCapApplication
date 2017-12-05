#include "mainwindow.h"
#include <QApplication>
#include "pcap.h"

#include <qdebug.h>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    //    MainWindow w;
    //    w.show();
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 获取本地机器设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    /* 打印列表 */
    for(d= alldevs; d != NULL; d= d->next)
    {
        qDebug() << (d->name);
        if (d->description)
            qDebug() << (d->description);
        else
            qDebug() << (" (No description available)\n");
    }

    if (i == 0)
    {
        qDebug() << ("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return 0;
    }

    /* 不再需要设备列表了，释放它 */
    pcap_freealldevs(alldevs);
    return a.exec();
}



