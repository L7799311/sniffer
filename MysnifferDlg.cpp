
// MysnifferDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "Mysniffer.h"
#include "MysnifferDlg.h"
#include "afxdialogex.h"

#include <vector>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#define LINE_LEN 16
#define MAXSIZE 5000
int number = 0;
CMysnifferDlg *dlg;//�� �ڷ���CMySnifferDIg�еĳ�Ա��ָ��
CString pack_str[MAXSIZE];
static bool STATE;
// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMysnifferDlg �Ի���



CMysnifferDlg::CMysnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_Mysniffer_DIALOG, pParent)
	, m_info(_T(""))
	, m_select(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMysnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_comboBoxRule);
	DDX_Text(pDX, IDC_EDIT_DATA_INFOACTION, m_info);
	//  DDX_Text(pDX, IDC_EDIT_DATA_INFOACTION, m_info);
	DDX_Text(pDX, IDC_EDIT_DATA_INFOACTION, m_info);
	DDX_Text(pDX, IDC_EDIT_SELECT_DEVICE, m_select);
	DDX_Control(pDX, IDC_LIST_DEVICE, m_device);
	DDX_Control(pDX, IDC_LIST_PACK, m_pack);
}

BEGIN_MESSAGE_MAP(CMysnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_DEVICE, &CMysnifferDlg::OnLvnItemchangedListDevice)
	ON_BN_CLICKED(IDC_BUTTON_GET_DEVICE, &CMysnifferDlg::OnClickedButtonGetDevice)
	ON_NOTIFY(NM_CLICK, IDC_LIST_PACK, &CMysnifferDlg::OnClickListPack)
	ON_BN_CLICKED(IDC_BUTTON_START, &CMysnifferDlg::OnClickedButtonStart)
	ON_EN_CHANGE(IDC_EDIT_DATA_INFOACTION, &CMysnifferDlg::OnEnChangeEditDataInfoaction)
	ON_BN_CLICKED(IDC_BUTTON_STOP, &CMysnifferDlg::OnClickedButtonStop)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CMysnifferDlg::OnCbnSelchangeCombo1)
END_MESSAGE_MAP()


// CMysnifferDlg ��Ϣ�������

BOOL CMysnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	//SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	//SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	STATE = FALSE;
	AfxGetMainWnd()->SetWindowText("Mysniffer");
	dlg = this;
	number = 0;
	devnum = 0;
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(FALSE);
	DWORD dwStyle1 = m_device.GetExtendedStyle();
	dwStyle1 |= LVS_EX_FULLROWSELECT;
	dwStyle1 |= LVS_EX_GRIDLINES;
	m_device.SetExtendedStyle(dwStyle1);
	m_device.InsertColumn(0, "NO", LVCFMT_LEFT, 100);
	m_device.InsertColumn(1, "�����豸", LVCFMT_LEFT, 400);
	m_device.InsertColumn(2, "���������� ����",LVCFMT_LEFT,500);
	//�����б�m_ pack��ʽ
	DWORD dwStyle = m_pack.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;
	dwStyle |= LVS_EX_GRIDLINES;
	m_pack.SetExtendedStyle(dwStyle);
	//���m_ pack���б���
	
	m_pack.InsertColumn(0,"���", LVCFMT_LEFT, 60);
	m_pack.InsertColumn(1,"IPЭ��汾", LVCFMT_LEFT, 120);
	m_pack.InsertColumn(2,"Э��", LVCFMT_LEFT, 80);
	m_pack.InsertColumn(3,"ԴIP��ַ", LVCFMT_LEFT, 120);
	m_pack.InsertColumn(4,"Ŀ��IP��ַ", LVCFMT_LEFT, 120);
	m_pack.InsertColumn(5,"ԴMAC��ַ", LVCFMT_LEFT, 140);
	m_pack.InsertColumn(6,"Ŀ��MAC��ַ", LVCFMT_LEFT, 140);
	m_pack.InsertColumn(7,"���ݰ�����ʱ��", LVCFMT_LEFT, 120);
	m_pack.InsertColumn(8,"���ݰ���С", LVCFMT_LEFT, 100);

	m_comboBoxRule.AddString(_T("ѡ����˹���"));
	/*��ʼ�����˹����б�*/
	m_comboBoxRule.AddString(_T("tcp"));
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("ip"));
	m_comboBoxRule.AddString(_T("icmp"));
	m_comboBoxRule.AddString(_T("arp"));
	//m_comboBoxRule.AddString(_T("http"));
	m_comboBoxRule.SetCurSel(0);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CMysnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CMysnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		//dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CMysnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMysnifferDlg::OnNMCustomdrawProgress1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	*pResult = 0;
}

void CMysnifferDlg::OnLvnItemchangedListDevice(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	*pResult = 0;
}


void CMysnifferDlg::OnLvnItemchangedListDevice1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	*pResult = 0;
}


void CMysnifferDlg::OnEnChangeEditDataaction1()
{
	// TODO:  ����ÿؼ��� RICHEDIT �ؼ���������
	// ���ʹ�֪ͨ��������д CDialogEx::OnInitDialog()
	// ���������� CRichEditCtrl().SetEventMask()��
	// ͬʱ�� ENM_CHANGE ��־�������㵽�����С�

	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}


void CMysnifferDlg::OnClickListDevice1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);

	// TODO: �ڴ���ӿؼ�֪ͨ����������
	*pResult = 0;
}


void CMysnifferDlg::OnClickedButtonGetDevice()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->getAllDevs();
	

}


void CMysnifferDlg::OnClickListPack(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	POSITION Pos = m_pack.GetFirstSelectedItemPosition();
	int num = (int)Pos;
	
	GetDlgItem(IDC_EDIT_DATA_INFOACTION)->SetWindowText(pack_str[num]);
	*pResult = 0;
}


void CMysnifferDlg::OnClickedButtonStart()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(TRUE);
	if (STATE == FALSE) {
		this->m_pack.DeleteAllItems();
	}
	STATE = TRUE;
	this->startCap();
	

}

void CMysnifferDlg::getAllDevs()
{
	pcap_if_t *d;
	int i = 0;
	/* ��ȡ���ػ����豸�б� */
	//if (this->alldevs != NULL) return this->alldevs;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &this->alldevs, this->errbuf) == -1)
	{
		exit(1);
	}

	/* ��ӡ�б� */
	for (d = this->alldevs; d != NULL; d = d->next)
	{
		str.Format("%d", i + 1);
		m_device.InsertItem(i, str);
		str = d->name;
		m_device.SetItemText(i, 1, str);
		if (d->description) {
			str = d->description;
			m_device.SetItemText(i, 2, str);
		}
		else
		{
			str = "�޷���ȡ�豸����";
			m_device.SetItemText(i, 2, str);
		}
		i++;
	}
	devnum = i;
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(TRUE);
	return;
}

static UINT WINAPI ThreadFunc()
{
	int res = 10;
	int cot = 0;
	if ((dlg->dumpfp = pcap_dump_open(dlg->adhandle, "data.pcap")) == NULL) 
	{
		exit(-1);
	}
	//u_char *oldtime;
	while ((res = pcap_next_ex(dlg->adhandle, &dlg->header, &dlg->pkt_data)) >= 0)
	{
		if(STATE == FALSE){
			return 0;
		}
		pcap_t *adhandle = dlg->adhandle;
		pcap_pkthdr *header = dlg->header;
		const u_char *pkt_data = dlg->pkt_data;
		if (number == MAXSIZE) break;
		if (res == 0) continue;
		int counter, counter2;
		struct tm *ltime;
		char timestr[16];
		time_t local_tv_sec;
		if (number != 0)
		{
			// =(u_char) local_tv_sec;
			//dlg->analyse(oldtime);
		}
		
		pcap_dump((u_char *)dlg->dumpfp,(const pcap_pkthdr *)dlg->header,(const u_char *)dlg->pkt_data);
		
		number++;
		dlg->str.Format("%d", number);//��ӡ�������
		dlg->m_pack.InsertItem(number - 1, dlg->str);//��ӡ����ʱ��
		local_tv_sec = header->ts.tv_sec;//��ʱ���ת���ɿ�ʶ��ĸ�ʽ
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		dlg->str = timestr;
		dlg->m_pack.SetItemText(number - 1, 7, dlg->str);
		dlg->str.Format("%d", header->len);//��ӡ���ĳ���
		dlg->m_pack.SetItemText(number - 1, 8, dlg->str);
		dlg->an_ethernet();
		
	}
	pcap_dump_close(dlg->dumpfp);
	return 0;
}

void CMysnifferDlg::startCap()
{
	int filter_index;
	pcap_if_t *d;
	int inum = 0;
	int i = this->devnum;
	int res;
	u_int netmask;
	CString message;
	CString select;
	GetDlgItemText(IDC_EDIT_SELECT_DEVICE, str);
	
	struct bpf_program fcode;
	filter_index = this->m_comboBoxRule.GetCurSel();
	if (CB_ERR == filter_index)
	{
		MessageBox(_T("������ѡ�����"));
		return ;
	}

	POSITION Pos = m_device.GetFirstSelectedItemPosition();
	if(Pos == NULL && str == "") {
		message = "����δѡ��������";
		MessageBox(message, "INFO");
		return;
	}
	int pos = (int)Pos;
	CString d1, d2;

	//GetDlgItemText(IDC_EDIT_SELECT_DEVICE,str);

	inum = atoi((char *)(LPSTR)(LPCTSTR)str);
	if (inum != pos && Pos != NULL && str != "") {
		message = "��ѡ����豸��������豸����ͬ������������";
		MessageBox(message, "INFO");
		this->m_device.DeleteAllItems();
		return;
	}
	if (str == "") {
		inum = pos;
		str.Format("%d", pos);
	}

	if (inum < 1 || inum > i)
	{
		message = "�豸��ų�����Χ.";
		MessageBox(message, "ERROR");
		pcap_freealldevs(alldevs);
		return;
	}
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // Ҫ��׽�����ݰ��Ĳ��� 
						  // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
	)) == NULL)
	{
		message = "�޷���������.";
		MessageBox(message, "error");
		pcap_freealldevs(alldevs);
		return;
	}
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;
	//pcap_freealldevs(alldevs);

	//���������
	if (0 == filter_index)
	{
		char filter[] = "";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("�﷨�����޷����������"));
			pcap_freealldevs(alldevs);
			return ;
		}
	}
	else {
		CString str;
		char *filter;
		int len, x;
		this->m_comboBoxRule.GetLBText(filter_index, str);
		len = str.GetLength() + 1;
		filter = (char*)malloc(len);
		for (x = 0; x < len; x++)
		{
			filter[x] = str.GetAt(x);
		}
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("�﷨�����޷����������"));
			pcap_freealldevs(alldevs);
			return ;
		}
	}


	//���ù�����
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		MessageBox(_T("���ù���������"));
		pcap_freealldevs(alldevs);
		return ;
	}

	this->hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadFunc , NULL, 0, &ThreadID);

	return;
}


void CMysnifferDlg::an_ethernet()
{
	u_short ethernet_type;
	ether_header *ethernet;
	u_char *macaddr;
	ethernet = (ether_header *)this->pkt_data;
	static int ethernet_number = 1;
	ethernet_type = ntohs(ethernet->ether_type);
	macaddr = ethernet->dmac;
	str.Format("%.2x", macaddr[0]);
	dlg->m_str2 = str;
	for (int cc = 1; cc < 6; cc++)
	{
		str.Format(":%.2x", macaddr[cc]);
		dlg->m_str2 += str;
	}
	dlg->m_pack.SetItemText(number - 1, 5, m_str2);
	/* ���Դ��̫����ַ */
	macaddr = ethernet->smac;
	m_str2.Format("%.2x", macaddr[0]);
	dlg->str = m_str2;
	for(int cc = 1;cc < 6; cc ++)
	{
		m_str2.Format(":%.2x", macaddr[cc]);
		dlg->str += m_str2;
	}
	dlg->m_pack.SetItemText(number - 1, 6, str);

	/* ���Ŀ����̫����ַ */
	int counter=0, counter2=0;
	dlg->str.Format("%08x ", counter + 16);
	for (counter = 1; (counter < (header->caplen + 1)); counter++)
	{
		dlg->m_str2.Format("%.2x ", pkt_data[counter - 1]);
		dlg->str += dlg->m_str2;
		if ((counter % LINE_LEN) == 0)
		{
			dlg->str += " ";
			for (counter2 = 0; counter2 < LINE_LEN; counter2++)
			{
				if ((pkt_data[counter + counter2 - LINE_LEN - 1] >= 32) && (pkt_data[counter + counter2 - LINE_LEN - 1] <= 126)) 
				{
					
					dlg->str += pkt_data[counter + counter2 - LINE_LEN - 1];
				}
				else dlg->str += ".";
			}
			dlg->str += "\r\n"; 
			dlg->m_str2.Format("%08x ", counter + 16);
			dlg->str += dlg->m_str2;
		}
	}
	dlg->str += "\r\n--------- ��̫�� ---------\r\n";
	CString temp;
	temp.Format("%02x:%02x:%02x:%02x:%02X:%02X", *ethernet->dmac, *(ethernet->dmac + 1), *(ethernet->dmac + 2), *(ethernet->dmac + 3), *(ethernet->dmac + 4), *(ethernet->dmac + 5));
	dlg->str += "Դ�˿ڣ�" + temp+"\r\n";
	temp.Format("%02x:%02x:%02x:%02x:%02X:%02X", *ethernet->smac, *(ethernet->smac + 1), *(ethernet->smac + 2), *(ethernet->smac + 3), *(ethernet->smac + 4), *(ethernet->smac + 5));
	dlg->str += "Ŀ�Ķ˿ڣ�" + temp+"\r\n";
	dlg->str += "Type: ";
	switch (ethernet_type)
	{
	case 0x86dd:
		dlg->str+="IPV6\r\n";
		this->m_pack.SetItemText(number - 1, 1, "IPV6");
		dlg->str += "\r\n-----------IPV6-----------\r\n";
		break;
	case 0x0806:
		dlg->str += "ARP\r\n";
		this->m_pack.SetItemText(number - 1, 2, "ARP");
		//dlg->str += "\r-----------ARP------------\r\n";
		dlg->str += this->_arp();
		break;
	case 0x0800:
		this->str += "IP\r\n";

		//->str += "\r\n-----------IPV4-----------\r\n";
		dlg->str += this->_ip();
		break;
	default:
		break;
	}

	pack_str[number] = dlg->str;


}

CString CMysnifferDlg::_arp()
{
	ARP_header *arp;
	u_short version;
	u_short hardware_type;
	u_short operation_code;
	u_char *macaddr;
	u_short hardware_length;
	u_short protocol_length;
	CString s ,r, temp;
	arp = (ARP_header *)((u_char *)pkt_data + 14);
	hardware_type = ntohs(arp->HardwareType);
	version = ntohs(arp->ProtocolType);
	operation_code = ntohs(arp->OperationField);
	hardware_length = arp->HardwareAddLen;
	protocol_length = arp->ProtocolAddLen;
	if (version == 0x0800) this->m_pack.SetItemText(number - 1, 1, "IPV4");
	if (version == 0x86dd) this->m_pack.SetItemText(number - 1, 1, "IPV6");

	s = "";
	m_str2.Format("%d", arp->SourceIpAdd.byte1);
	s += m_str2;
	m_str2.Format(".%d", arp->SourceIpAdd.byte2);
	s += m_str2;
	m_str2.Format(".%d", arp->SourceIpAdd.byte3);
	s += m_str2;
	m_str2.Format(".%d", arp->SourceIpAdd.byte4);
	s += m_str2;
	this->m_pack.SetItemText(number - 1, 3, s);

	s = "";
	m_str2.Format("%d", arp->DestIpAdd.byte1);
	s += m_str2;
	m_str2.Format(".%d", arp->DestIpAdd.byte2);
	s += m_str2;
	m_str2.Format(".%d", arp->DestIpAdd.byte3);
	s += m_str2;
	m_str2.Format(".%d", arp->DestIpAdd.byte4);
	s += m_str2;
	this->m_pack.SetItemText(number - 1, 4, s);
	r += "----------- ARPЭ�� -----------\r\n";
	temp.Format("%d", hardware_type);
	r += "Ӳ�����ͣ�" + temp + "\r\n";
	temp.Format("%d", version);
	r += "Э�����ͣ�0x%02x" + temp + "\r\n";
	temp.Format("%d", hardware_length);
	r += "Ӳ����ַ���ȣ�" + temp + "\r\n";
	temp.Format("%d", protocol_length);
	r += "Э���ַ���ȣ�" + temp + "\r\n";
	temp.Format("%d", operation_code);
	r += "�����룺" + temp + "\r\n";
	macaddr = arp->SourceMacAdd;
	r += "Դ��̫����ַ:";
	temp.Format("%02x:%02x:%02x:%02x:%02x:%02x", *macaddr,
		*(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));
	r += temp + "\r\n";
	macaddr = arp->DestMacAdd;
	r += "Ŀ����̫����ַ:";
	temp.Format("%02x:%02x:%02x:%02x:%02x:%02x", *macaddr,
		*(macaddr + 1), *(macaddr + 2), *(macaddr + 3), *(macaddr + 4), *(macaddr + 5));
	r += temp + "\r\n";
	temp.Format("%d.%d.%d.%d", arp->SourceIpAdd.byte1, arp->SourceIpAdd.byte2, arp->SourceIpAdd.byte3, arp->SourceIpAdd.byte4);
	r += "ԴIP��ַ:" + temp + "\r\n";
	temp.Format("%d.%d.%d.%d", arp->DestIpAdd.byte1, arp->DestIpAdd.byte2, arp->DestIpAdd.byte3, arp->DestIpAdd.byte4);
	r += "Ŀ��IP��ַ:" + temp + "\r\n";

	return r;
}

CString CMysnifferDlg::_ip()
{
	ip_header *ip;
	u_short version;
	u_short header_lenth;
	u_int offset;
	u_char tos;
	u_short id;
	u_char flag;
	u_int16_t checksum;
	CString s;
	ip = (ip_header*)(pkt_data + 14);
	version = ((ip->ver_ihl & 0xf0) >> 4);
	header_lenth = (ip->ver_ihl & 0xf) * 4;
	tos = ip->tos;
	id = ntohs(ip->identification);
	flag = (ip->identification >> 13);
	offset = ntohs((ip->flags & 0x1fff));
	checksum = ntohs(ip->checknum);

	if (version == 4) this->m_pack.SetItemText(number - 1, 1, "IPV4");
	if (version == 6) this->m_pack.SetItemText(number - 1, 1, "IPV6");

	s = "";
	m_str2.Format("%d", ip->saddr.byte1);
	s += m_str2;
	m_str2.Format(".%d", ip->saddr.byte2);
	s += m_str2;
	m_str2.Format(".%d", ip->saddr.byte3);
	s += m_str2;
	m_str2.Format(".%d", ip->saddr.byte4);
	s += m_str2;
	this->m_pack.SetItemText(number - 1, 3, s);

	s = "";
	m_str2.Format("%d", ip->daddr.byte1);
	s += m_str2;
	m_str2.Format(".%d", ip->daddr.byte2);
	s += m_str2;
	m_str2.Format(".%d", ip->daddr.byte3);
	s += m_str2;
	m_str2.Format(".%d", ip->daddr.byte4);
	s += m_str2;
	this->m_pack.SetItemText(number - 1, 4, s);
	CString r, temp;
	r += "----------- IPЭ�� -----------\r\n";
	temp.Format("%d", version);
	r += "�汾��:" + temp + "\r\n";
	temp.Format("%d", header_lenth);
	r += "�ײ�����:" + temp + "\r\n";
	temp.Format("%d", tos);
	r += "��������:" + temp + "\r\n";
	temp.Format("%d", ntohs(ip->tlen));
	r += "�ܳ���:" + temp + "\r\n";
	temp.Format("%d", ntohs(ip->identification));
	r += "��ʶ:" + temp + "\r\n";
	temp.Format("%d", offset);
	r += "ƫ��:" + temp + "\r\n";
	temp.Format("%d", ip->ttl);
	r += "����ʱ��:" + temp + "\r\n";
	temp.Format("%d", checksum);
	r += "У���:" + temp + "\r\n";
	temp.Format("%d.%d.%d.%d", ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);
	r += "ԴIP��ַ:" + temp + "\r\n";
	temp.Format("%d.%d.%d.%d", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
	r += "Ŀ��IP��ַ:" + temp + "\r\n";
	r += "Э�飺";
	switch (ip->protocol)
	{
	case 6:
		r += "TCP\r\n";
		this->m_pack.SetItemText(number - 1, 2, "TCP");
		r += this->_tcp();
		
		break;
	case 17:
		r += "UDP\r\n";
		this->m_pack.SetItemText(number - 1, 2, "UDP");
		r += this->_udp();
		break;
	case 1:
		r += "ICMP\r\n";
		this->m_pack.SetItemText(number - 1, 2, "ICMP");
		r += this->_icmp();
		break;
	default:
		break;
	}
	return r;

}

// ��ʾHTTPЭ�����ϸ��Ϣ
CString CMysnifferDlg::_http()
{
	CString r, temp;
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ver_ihl;
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data + 14 + ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->tcp_offset * 4;


	u_char *http_pkt = (u_char *)(pkt_data + 14 + ip_hdrLen + tcp_hdrLen);
	u_short http_pktLen = ntohs(ip_hdr->tlen) - (ip_hdrLen + tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);

	//http_packet * http_pktHdr = new http_packet ;// HTTP packet's  struct
	vector<CString> strVecRequestHttp; // ��������ͷ����
	vector<CString> strVecRespondHttp; // ������Ӧͷ����
	CString chrVecTmp = NULL; // ����������������ʱ�ַ�
	CString strVecTmp = NULL; // ����������������ʱ�ַ���

	u_char * pchrHttpAllData = NULL; //����HTTPЭ�������ʼλ�ã���������ͷ����Ӧͷ����
	u_char * pchrHttpRequestPos = NULL; //����HTTPЭ���������ͷ����ʼλ��
	u_char * pchrHttpRespondPos = NULL; //����HTTPЭ�������Ӧͷ����ʼλ��
	pchrHttpAllData = http_pkt; //��ֵ�õ�HTTPЭ����Ŀ�ʼλ��

	CString strHttpALLData = NULL;//����HTTPЭ��������ݰ�,��������ͷ����Ӧͷ����
	CString strHttpRequestData = NULL;//����HTTPЭ���������ͷ������
	CString strHttpRespondData = NULL;//����HTTPЭ�������Ӧͷ������

	u_short httpAllPos = 0;
	u_short httpAllLen = 0;
	httpAllLen = http_pktLen;
	r += "----------- HTTPЭ�� -----------\r\n";
	if (IsHTTP(pkt_data)) // check is http
	{

		if (*pkt_data == 'H') // �����һ���ַ�ΪH����������HTTP��ͷ�ģ���Ϊ��Ӧͷ������ӦΪ����ͷ
		{
			for (int i = 0; i < httpAllLen; i++) // get http_Get data
			{
				//chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); // format
				//strHttpRespondData += chrVecTmp;//��¼������HTTP��Ӧͷ������

				chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); //��¼ÿһ�е����ݣ�����������ʱ�ַ�����
				strVecTmp += chrVecTmp;
				if (i > 2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //���ݻس����з��жϣ�����ÿ�б�����vector������
				{
					strVecRespondHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}
			r += "��Ӧͷ:\r\n";
			for (u_short irespond = 0; irespond < strVecRespondHttp.size(); irespond++) {
				temp.Format("%d", strVecRespondHttp[irespond]);
				r += temp + "\r\n";
			}

		}
		else
		{
			for (int i = 0; i < httpAllLen; i++) // get http_Get data
			{
				//chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); // format
				//strHttpRequestData += chrVecTmp;//��¼������HTTP����ͷ������

				chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); //��¼ÿһ�е����ݣ�����������ʱ�ַ�����
				strVecTmp += chrVecTmp;
				if (i > 2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //���ݻس����з��жϣ�����ÿ�б�����vector������
				{
					strVecRequestHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}
			r += "����ͷ:\r\n";
			for (u_short irequest = 0; irequest < strVecRequestHttp.size(); irequest++) {
				temp.Format("%d", strVecRequestHttp[irequest]);
				r += temp + "\r\n";
			}

		}
	}
	return r;

}
// �жϸ�Э���Ƿ�ΪHTTPЭ��
bool CMysnifferDlg::IsHTTP(const u_char *pkt_data)
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ver_ihl;
	tcp_header * tcp_hdr = (tcp_header *)(pkt_data + 14 + ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->tcp_offset * 4;

	u_char *http_pkt = (u_char *)(pkt_data + 14 + ip_hdrLen + tcp_hdrLen);
	u_short http_pktLen = ntohs(ip_hdr->tlen) - (ip_hdrLen + tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);

	CString chrTmp = NULL;
	CString strTmp = NULL;
	CString strHttp = NULL;

	int httpPos = 0;

	if (ip_hdr->protocol == 6)
	{
		for (int i = 0; i < http_pktLen; i++) // ����ȡ��һ���Ƿ���HTTP�ַ���
		{
			chrTmp.Format(TEXT("%c"), http_pkt[i]);
			strTmp += chrTmp;
			if (i > 2 && http_pkt[i - 1] == 13 && http_pkt[i] == 10)
				break;
		}
		//AfxMessageBox(strTmp);
		httpPos = strTmp.Find(TEXT("HTTP"), 0);

		if (httpPos != -1 && httpPos != 65535) // �����һ�к����ַ���HTTP����ΪHTTPЭ��
		{
			return true;
		}
			return false;

	}
	return false;
}

CString CMysnifferDlg::_tcp()
{
	tcp_header* tcp;/* TCPЭ����� */
	u_char flags;/* ��� */
	int header_length;/* ���� */
	u_short source_port;/* Դ�˿� */
	u_short destination_port;/* Ŀ�Ķ˿� */
	u_short windows;/* ���ڴ�С */
	u_short urgent_pointer;/* ����ָ�� */
	u_int sequence;/* ���к� */
	u_int acknowledgement;/* ȷ�Ϻ� */
	u_int16_t checksum;/* У��� */
	CString r, temp;
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = (ip_hdr->ver_ihl & 0xf) * 4;
	tcp = (tcp_header*)((u_char *)pkt_data + 14 + ip_hdrLen);/* ���TCPЭ������ */
	source_port = ntohs(tcp->tcp_source_port);/* ���Դ�˿� */
	destination_port = ntohs(tcp->tcp_destination_port);/* ���Ŀ�Ķ˿� */
	header_length = tcp->tcp_offset * 4;/* ���� */
	sequence = ntohl(tcp->tcp_sequence_lliiuuwweennttaaoo);/* ������ */
	acknowledgement = ntohl(tcp->tcp_acknowledgement);/* ȷ�������� */
	windows = ntohs(tcp->tcp_windows);/* ���ڴ�С */
	urgent_pointer = ntohs(tcp->tcp_urgent_pointer);/* ����ָ�� */
	flags = tcp->tcp_flags;/* ��ʶ */
	checksum = ntohs(tcp->tcp_checksum);/* У��� */
	r += "----------- TCPЭ�� -----------\r\n";
	temp.Format("%d", source_port);
	r += "Դ�˿ں�:" + temp + "\r\n";
	temp.Format("%d", destination_port);
	r += "Ŀ�Ķ˿ں�:" + temp + "\r\n";
	temp.Format("%u",sequence);
	r += "������:" + temp + "\r\n";
	temp.Format("%u", acknowledgement);
	r += "ȷ�Ϻ�:" + temp + "\r\n";
	temp.Format("%d", header_length);
	r += "�ײ�����:" + temp + "\r\n";
	temp.Format("%d", tcp->tcp_reserved);
	r += "����:" + temp + "\r\n";
	r += "���:\r\n";
	r += "PSH = ";
	if (flags & 0x08)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "ACK = ";
	if (flags & 0x10)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "SYN = ";
	if (flags & 0x02)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "URG = ";
	if (flags & 0x20)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "FIN = ";
	if (flags & 0x01)
		r += "1";
	else r += "0";
	r += "\r\n";
	r += "RST = ";
	if (flags & 0x04)
		r += "1";
	else r += "0";
	r += "\r\n";
	temp.Format("%d", windows);
	r += "���ڴ�С:" + temp + "\r\n";
	temp.Format("%d", checksum);
	r += "У���:" + temp + "\r\n";
	temp.Format("%d", urgent_pointer);
	r += "����ָ��:" + temp + "\r\n";
	if (IsHTTP(pkt_data)) {
		r += "Э��:HTTP\r\n";
		r += this->_http();
		this->m_pack.SetItemText(number - 1, 2, "HTTP");
	}
	return r;
}

CString CMysnifferDlg::_udp()
{
	//udp_header *udp;
	CString r, temp;
	u_short sport;
	u_short dport;
	u_short len;
	u_short crc;
	//ip = (ip_header *)((u_char *)pkt_data + 14);
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = (ip_hdr->ver_ihl & 0xf) * 4;
	udp_header *udp = (udp_header *)(pkt_data + 14 + ip_hdrLen);
	//udp = (udp_header *)((u_char *)pkt_data + 14 + iplen);

	sport = ntohs(udp->sport);
	dport = ntohs(udp->dport);
	len = udp->len;
	crc = ntohs(udp->crc);
	r += "----------- UDPЭ�� -----------\r\n";
	temp.Format("%d", sport);
	r += "Դ�˿ں�:" + temp + "\r\n";
	temp.Format("%d", dport);
	r += "Ŀ�Ķ˿ں�:" + temp + "\r\n";
	temp.Format("%u", len);
	r += "����:" + temp + "\r\n";
	temp.Format("%u", crc);
	r += "У���:" + temp + "\r\n";

	return r;
}

CString CMysnifferDlg::_icmp()
{
	ip_header *ip_hdr = (ip_header *)(pkt_data + 14);
	u_short ip_hdrLen = (ip_hdr->ver_ihl & 0xf) * 4;
	icmp_header *icmp = (icmp_header *)(pkt_data + 14 + ip_hdrLen);
	//struct icmp_header* icmp;
	/* ICMPЭ����� */
	//icmp = (struct icmp_header*)((u_char *)pkt_data + 14 + iplen);
	/* ���ICMPЭ������ */
	CString r, temp;
	r += "----------- ICMPЭ�� -----------\r\n";
	temp.Format("%d", icmp->icmp_type);
	r += "ICMP����:" + temp + "--";
	/* ���ICMP���� */
	switch (icmp->icmp_type)
	{
	case 8:
		r += "ICMP��������Э��\r\n";
		temp.Format("%u", icmp->icmp_code);
		r += "ICMP����:" + temp + "\r\n";
		temp.Format("%u", icmp->icmp_id);
		r += "��ʶ��:" + temp + "\r\n";
		temp.Format("%u", icmp->icmp_sequence);
		r += "������:" + temp + "\r\n";
		break;
	case 0:
		r += "ICMP����Ӧ��Э��\r\n";
		temp.Format("%u", icmp->icmp_code);
		r += "ICMP����:" + temp + "\r\n";
		temp.Format("%u", icmp->icmp_id);
		r += "��ʶ��:" + temp + "\r\n";
		temp.Format("%u", icmp->icmp_sequence);
		r += "������:" + temp + "\r\n";
		break;
	default:
		break;
	}
	temp.Format("%u", ntohs(icmp->icmp_checksum));
	r += "ICMPУ���:" + temp + "\r\n";
	/* ���ICMPУ��� */
	return r;
}


void CMysnifferDlg::OnStnClickedStaticSip()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}

void CMysnifferDlg::OnEnChangeEditDmac()
{
	// TODO:  ����ÿؼ��� RICHEDIT �ؼ���������
	// ���ʹ�֪ͨ��������д CDialogEx::OnInitDialog()
	// ���������� CRichEditCtrl().SetEventMask()��
	// ͬʱ�� ENM_CHANGE ��־�������㵽�����С�

	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}

void CMysnifferDlg::OnEnChangeEditDataInfoaction()
{
	// TODO:  ����ÿؼ��� RICHEDIT �ؼ���������
	// ���ʹ�֪ͨ��������д CDialogEx::OnInitDialog()
	// ���������� CRichEditCtrl().SetEventMask()��
	// ͬʱ�� ENM_CHANGE ��־�������㵽�����С�

	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}

void CMysnifferDlg::OnClickedButtonStop()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	STATE = FALSE;
	pcap_freealldevs(this->alldevs);
	this->file = NULL;
	number = 0;
	devnum = 0;
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(FALSE);
	this->m_device.DeleteAllItems();

}

void CMysnifferDlg::OnCbnSelchangeCombo1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}