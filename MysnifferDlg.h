
// MysnifferDlg.h : ͷ�ļ�
//
#pragma once

#include "afxcmn.h"

#include "pcap.h"
#include <stdlib.h>
#include "afxwin.h"

struct ether_header
{
	u_char smac[6];
	/* Ŀ����̫����ַ */
	u_char dmac[6];
	/* Դ��̫����ַ */
	u_short ether_type;
	/* ��̫������ */
};

typedef struct IPv4
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_addr;

typedef struct IP_Header
{
	u_char ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)  
	u_char  tos;            // ��������(Type of service)   
	u_short tlen;           // �ܳ�(Total length)   
	u_short identification; // ��ʶ(Identification)  
	u_short flags;			// ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)  
	u_char  ttl;            // ���ʱ��(Time to live) 
	u_char  protocol;       // Э��(Protocol)  
	u_short checknum;       // �ײ�У���(Header checksum)  
	ip_addr  saddr;			// Դ��ַ(Source address)  
	ip_addr  daddr;			// Ŀ�ĵ�ַ(Destination address)  
	u_int   op_pad;         // ѡ�������(Option + Padding)  
}ip_header;

struct icmp_header
{
	u_int8_t icmp_type;/* ICMP���� */
	u_int8_t icmp_code;/* ICMP���� */
	u_int16_t icmp_checksum;/* У��� */
	u_int16_t icmp_id;/* ��ʶ�� */
	u_int16_t icmp_sequence;/* ������ */
};

struct ARP_header
{
	u_short HardwareType;	 //Ӳ������
	u_short ProtocolType;	 //Э������
	u_short HardwareAddLen;	 //Ӳ����ַ����
	u_short ProtocolAddLen;	 //Э���ַ����
	u_short OperationField;  //�����ֶ�
	u_char SourceMacAdd[6];  //Դmac��ַ
	ip_addr SourceIpAdd;	 //Դip��ַ
	u_char DestMacAdd[6];	 //Ŀ��mac��ַ
	ip_addr DestIpAdd;		 //Ŀ��ip��ַ
};

typedef struct UDP_Header
{
	u_short sport;          // Դ�˿�(Source port)  
	u_short dport;          // Ŀ�Ķ˿�(Destination port)  
	u_short len;            // UDP���ݰ�����(Datagram length)  
	u_short crc;            // У���(Checksum)  
}udp_header;

typedef struct TCP_Header
{
	u_int16_t tcp_source_port;/* Դ�˿ں� */
	u_int16_t tcp_destination_port;/* Ŀ�Ķ˿ں� */
	u_int32_t tcp_sequence_lliiuuwweennttaaoo;/* ���к� */
	u_int32_t tcp_acknowledgement;/* ȷ�����к� */
#ifdef WORDS_BIGENDIAN   
	u_int8_t tcp_offset : 4,
		/* ƫ�� */
		tcp_reserved : 4;
	/* δ�� */
#else   
	u_int8_t tcp_reserved : 4,/* δ�� */
		tcp_offset : 4;/* ƫ�� */
#endif   
	u_int8_t tcp_flags;/* ��� */
	u_int16_t tcp_windows;/* ���ڴ�С */
	u_int16_t tcp_checksum;/* У��� */
	u_int16_t tcp_urgent_pointer;/* ����ָ�� */
}tcp_header;
// CMysnifferDlg �Ի���
class CMysnifferDlg : public CDialogEx
{
// ����
public:
	CMysnifferDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_Mysniffer_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��
	

// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnNMCustomdrawProgress1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnItemchangedListDevice(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnItemchangedListDevice1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnEnChangeEditDataaction1();
	afx_msg void OnClickListDevice1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnClickedButtonGetDevice();
	afx_msg void OnClickListPack(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnClickedButtonStart();

	afx_msg
		void getoffset(FILE * fp);
	int getpkg(FILE * fp, int id, pcap_pkthdr * header, const u_char * data);
	afx_msg void OnStnClickedStaticSip();
	//afx_msg void OnClickedButtonSend();

	void getAllDevs();
	void startCap();

	// ��ʾHTTPЭ�����ϸ��Ϣ
	//void GetHTTPDetail(HTREEITEM & hItem, const u_char *pkt_data);
	// �жϸ�Э���Ƿ�ΪHTTPЭ��
	bool IsHTTP(const u_char *pkt_data);
	CString _arp();
	CString _ip();
	CString _tcp();
	CString _udp();
	CString _icmp();
	CString _http();

	void an_ethernet();
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	int iplen;


	pcap_t *adhandle;
	const u_char *pkt_data;
	pcap_pkthdr *header;
	pcap_dumper_t *dumpfp;

	FILE *file;
	
	pcap_t *fp;
	long pkgoffset[500 + 20000];
	pcap_pkthdr *head;
	const u_char *pdata;
	

	HANDLE hThread;
	DWORD ThreadID;

	int devnum;

	CString m_info;
	CString m_select;
	CListCtrl m_device;
	CListCtrl m_pack;
	CString str;
	CString m_str2;
	CComboBox m_comboBoxRule;
	
	afx_msg void OnEnChangeEditDmac();
	afx_msg void OnEnChangeEditDataInfoaction();
	
	afx_msg void OnClickedButtonStop();
	afx_msg void OnCbnSelchangeCombo1();
};
