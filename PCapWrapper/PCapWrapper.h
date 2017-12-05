#ifndef PCAPWRAPPER_H
#define PCAPWRAPPER_H

#include "pcap.h"
#include <string>
#include <vector>

class PCapWrapper
{
public:

    /*! 查找主机上所有的网卡
        \return 返回网卡的个数
        \sa releaseFoundDevices().
     */
    static int findDevices();
    /*! 释放查找的记录
        释放之后，所有参数为 index 的函数不再可用。
        \sa findDevices().
     */
    static void releaseFoundDevices();

    /*! 返回主机上的网卡数量
        \return 网络设备的数量，或者为0。
        \note  调用  releaseFoundDevices() 后，该函数永远返回0.
        \note 调用此函数前确保已经正确调用过 findDevices()， 并且没有使用过 releaseFoundDevices()。
     */
    static int deviceCount();

    /*! 返回 \a index 对应的网卡描述
        \param index    是查找到的网络设备的下标。
        \return 成功返回描述字符串，否则返回null
        \note 可能描述字符串为空，这种情况返回的是 "" (注意不是null).
        \note 调用此函数前确保已经正确调用过 findDevices()， 并且没有使用过 releaseFoundDevices()。
     */
    static const char* deviceDescription(int index);
    /*! 返回 \a index 对应的网卡名称
        \param index    是查找到的网络设备的下标。
        \return 成功返回描述字符串，否则返回0
        \note 调用此函数前确保已经正确调用过 findDevices()， 并且没有使用过 releaseFoundDevices()。
     */
    static const char* deviceName(int index);

    /*! 打开 \a deviceName 对应的网络设备.
        \param deviceName 是网络设备的名字. \sa deviceName().
        \param snapLenth  是最多获取的字节数.
        \param timeout  是读取超时的限制，单位 ms.

     */

    /*! 构造函数*/
    PCapWrapper();

    /*! 析构函数*/
    ~PCapWrapper();

    bool open(const char* deviceName, unsigned int snapLenth = 65535, unsigned int timeout = 1000);
    /*! 重载函数，打开 \a index 对应的网络设备.
        \param index    是查找到的网络设备的下标。
        \param snapLenth  是最多获取的字节数.
        \param timeout  是读取超时的限制，单位 ms.
        \note 调用此函数前确保已经正确调用过 findDevices()， 并且没有使用过 releaseFoundDevices()。
     */
    bool open(int index, unsigned int snapLenth = 65535, unsigned int timeout = 1000);

    /*! 检查是否已经打开了
        \return 已经打开了返回true,否则返回false.
        \sa open() close().
     */
    bool isOpened()const;

    /*! 发送一个大小为 \a size 的 \a packet
        \param packet 是起始地址
        \param size   是字节大小
        \return 成功返回true,否则返回false.
        \sa    isOpened().
     */
    bool send(const unsigned char* packet, unsigned int size);

    /*! 接收一条可用的数据
        \param header是一个 pcap_pkthdr  指针的地址 ， 成功后可以通过调用该指针获取信息。
        \param pktData 是一个 const unsigned char  指针的地址 ， 成功后可以通过调用该指针获取信息。
        \param isBlock 表示是否阻塞，如果为true的话，将一直读取直到有正确数据或者出错，如果为false，除了以上情况，超时也会返回false.
        \sa open().
        \return 成功返回true,否则返回false.
     */
    bool recv( struct pcap_pkthdr **header, const unsigned char **pktData, bool isBlock = true);

    /*! 关闭打开的网络设备。*/
    void close();

    /*! 返回包含错误原因的字符串。*/
    std::string errorString()const;
private:
    /*! 设置为私有，禁止拷贝*/
    PCapWrapper(const PCapWrapper&);
    /*! 设置为私有，禁止拷贝*/
    PCapWrapper& operator =(const PCapWrapper&);
    /*! 根据\a index 查找设备。*/

    static pcap_if_t* getDevice(int index);

    /*! 有效网络设备个数*/
    static int m_devCount;
    /*! 记录有效网络设备的信息*/
    static pcap_if_t *m_allDev;
    /*! 记录打开的网络设备*/
    pcap_t *m_fp;
    /*! 记录错误信息*/
    std::string m_errorString;
};

#endif // PCAPWRAPPER_H
