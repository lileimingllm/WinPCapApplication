#ifndef PCAPWRAPPER_H
#define PCAPWRAPPER_H

#include "pcap.h"
#include <string>
#include <vector>

class PCapWrapper
{
public:

    /*! �������������е�����
        \return ���������ĸ���
        \sa releaseFoundDevices().
     */
    static int findDevices();
    /*! �ͷŲ��ҵļ�¼
        �ͷ�֮�����в���Ϊ index �ĺ������ٿ��á�
        \sa findDevices().
     */
    static void releaseFoundDevices();

    /*! ���������ϵ���������
        \return �����豸������������Ϊ0��
        \note  ����  releaseFoundDevices() �󣬸ú�����Զ����0.
        \note ���ô˺���ǰȷ���Ѿ���ȷ���ù� findDevices()�� ����û��ʹ�ù� releaseFoundDevices()��
     */
    static int deviceCount();

    /*! ���� \a index ��Ӧ����������
        \param index    �ǲ��ҵ��������豸���±ꡣ
        \return �ɹ����������ַ��������򷵻�null
        \note ���������ַ���Ϊ�գ�����������ص��� "" (ע�ⲻ��null).
        \note ���ô˺���ǰȷ���Ѿ���ȷ���ù� findDevices()�� ����û��ʹ�ù� releaseFoundDevices()��
     */
    static const char* deviceDescription(int index);
    /*! ���� \a index ��Ӧ����������
        \param index    �ǲ��ҵ��������豸���±ꡣ
        \return �ɹ����������ַ��������򷵻�0
        \note ���ô˺���ǰȷ���Ѿ���ȷ���ù� findDevices()�� ����û��ʹ�ù� releaseFoundDevices()��
     */
    static const char* deviceName(int index);

    /*! �� \a deviceName ��Ӧ�������豸.
        \param deviceName �������豸������. \sa deviceName().
        \param snapLenth  ������ȡ���ֽ���.
        \param timeout  �Ƕ�ȡ��ʱ�����ƣ���λ ms.

     */

    /*! ���캯��*/
    PCapWrapper();

    /*! ��������*/
    ~PCapWrapper();

    bool open(const char* deviceName, unsigned int snapLenth = 65535, unsigned int timeout = 1000);
    /*! ���غ������� \a index ��Ӧ�������豸.
        \param index    �ǲ��ҵ��������豸���±ꡣ
        \param snapLenth  ������ȡ���ֽ���.
        \param timeout  �Ƕ�ȡ��ʱ�����ƣ���λ ms.
        \note ���ô˺���ǰȷ���Ѿ���ȷ���ù� findDevices()�� ����û��ʹ�ù� releaseFoundDevices()��
     */
    bool open(int index, unsigned int snapLenth = 65535, unsigned int timeout = 1000);

    /*! ����Ƿ��Ѿ�����
        \return �Ѿ����˷���true,���򷵻�false.
        \sa open() close().
     */
    bool isOpened()const;

    /*! ����һ����СΪ \a size �� \a packet
        \param packet ����ʼ��ַ
        \param size   ���ֽڴ�С
        \return �ɹ�����true,���򷵻�false.
        \sa    isOpened().
     */
    bool send(const unsigned char* packet, unsigned int size);

    /*! ����һ�����õ�����
        \param header��һ�� pcap_pkthdr  ָ��ĵ�ַ �� �ɹ������ͨ�����ø�ָ���ȡ��Ϣ��
        \param pktData ��һ�� const unsigned char  ָ��ĵ�ַ �� �ɹ������ͨ�����ø�ָ���ȡ��Ϣ��
        \param isBlock ��ʾ�Ƿ����������Ϊtrue�Ļ�����һֱ��ȡֱ������ȷ���ݻ��߳������Ϊfalse�����������������ʱҲ�᷵��false.
        \sa open().
        \return �ɹ�����true,���򷵻�false.
     */
    bool recv( struct pcap_pkthdr **header, const unsigned char **pktData, bool isBlock = true);

    /*! �رմ򿪵������豸��*/
    void close();

    /*! ���ذ�������ԭ����ַ�����*/
    std::string errorString()const;
private:
    /*! ����Ϊ˽�У���ֹ����*/
    PCapWrapper(const PCapWrapper&);
    /*! ����Ϊ˽�У���ֹ����*/
    PCapWrapper& operator =(const PCapWrapper&);
    /*! ����\a index �����豸��*/

    static pcap_if_t* getDevice(int index);

    /*! ��Ч�����豸����*/
    static int m_devCount;
    /*! ��¼��Ч�����豸����Ϣ*/
    static pcap_if_t *m_allDev;
    /*! ��¼�򿪵������豸*/
    pcap_t *m_fp;
    /*! ��¼������Ϣ*/
    std::string m_errorString;
};

#endif // PCAPWRAPPER_H
