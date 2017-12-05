#include "PCapWrapper.h"
#include "remote-ext.h"


int PCapWrapper::m_devCount = 0;
/*! 记录有效网络设备的信息*/
pcap_if_t * PCapWrapper::m_allDev = 0;


int PCapWrapper::findDevices()
{
    releaseFoundDevices();
    char errbuf[PCAP_ERRBUF_SIZE] = { '\0' };
    m_devCount = 0;

    if (::pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &m_allDev, errbuf) == 0)
    {
        for(pcap_if_t *dev=m_allDev; dev != 0; dev=dev->next)
        {
            m_devCount++;
        }
    }
    return m_devCount;
}


void PCapWrapper::releaseFoundDevices()
{
    if(m_devCount > 0)
    {
        pcap_freealldevs(m_allDev);
        m_allDev = 0;
        m_devCount = 0;
    }
}

int PCapWrapper::deviceCount()
{
    return m_devCount;
}


const char* PCapWrapper::deviceDescription(int index)
{
    pcap_if_t*dev = getDevice(index);
    return dev
            ? (dev->description ? dev->description : "")
            : 0;
}

const char* PCapWrapper::deviceName(int index)
{
    pcap_if_t*dev = getDevice(index);

    return dev ? dev->name : 0;
}

pcap_if_t* PCapWrapper::getDevice(int index)
{
    /*因为m_deviceCount与m_allDev是密切关联且一致的，因此使用它来判定。*/
    if(index<0 || index>= deviceCount())
    {
        return 0;
    }

    pcap_if_t *ret = 0;
    int i = 0;

    for(pcap_if_t *dev=m_allDev; dev != 0; dev=dev->next)
    {
        if(i++ == index)
        {
            ret = dev;
            break;
        }
        /*Else do nothing, and continue*/
    }

    return ret;
}

/******************** object member function *********************************/
PCapWrapper::PCapWrapper()
    :m_fp(0),m_errorString("")
{
}

PCapWrapper::~PCapWrapper()
{
    close();
}

bool PCapWrapper::open(const char* deviceName, unsigned int snapLenth, unsigned int timeout)
{
    if(deviceName == 0)
    {
        m_errorString = std::string("Invalid argument.");
        return false;
    }

    m_errorString.clear();
    char errbuf[PCAP_ERRBUF_SIZE] = { '\0' };
    if ( (m_fp= pcap_open(deviceName, snapLenth,
                          PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                          timeout,
                          NULL,             // 远程机器验证
                          errbuf
                          ) ) == 0)
    {
        m_errorString = std::string(errbuf);
        return false;
    }
    /*Else ok */

    return true;

}

bool PCapWrapper::open(int index, unsigned int snapLenth, unsigned int timeout)
{
    return open(deviceName(index), snapLenth, timeout);
}


bool PCapWrapper::isOpened()const
{
    return m_fp != 0;
}

bool PCapWrapper::send(const unsigned char* packet, unsigned int size)
{
    if(packet == 0)
    {
        m_errorString = std::string("Invalid argument.");
        return false;
    }

    if(!isOpened())
    {
        m_errorString = std::string("Not Open.");
        return false;
    }

    if(pcap_sendpacket(m_fp , packet, size) != 0)
    {
        m_errorString = std::string("Send Error.");
        return false;
    }

    m_errorString.clear();
    return true;
}


bool PCapWrapper::recv( struct pcap_pkthdr **header, const unsigned char **pktData, bool isBlock)
{
    if((header==0) || (pktData==0))
    {
        m_errorString = std::string("Invalid argument.");
        return false;
    }

    if(!isOpened())
    {
        m_errorString = std::string("Not Open.");
        return false;
    }

    int result = 0;

    /* 返回0 并且 isBlock为true就循环，否则停止，准备返回 */
    while( ((result = ::pcap_next_ex( m_fp, header, pktData))==0) && isBlock)
    {
        /*Do nothing.*/
    }

    if(result > 0)
    {
        /* ok , return*/
        m_errorString.clear();
        return true;
    }
    /*Else <=0*/

    if(result == 0)
    {
        m_errorString = std::string("Timeout");
    }
    else
    {
        // <0
        m_errorString = std::string("Recv Error");
    }

    return false;
}


void PCapWrapper::close()
{
    if(m_fp != 0)
    {
        ::pcap_close(m_fp);
        m_fp = 0;
    }
}

std::string PCapWrapper::errorString()const
{
    return m_errorString;
}
