#include "skynet.h"
#include "skynet_socket.h"

#include <pthread.h>
#include <unistd.h>

#include <grpcpp/grpcpp.h>
#include <string>

#include "protocol/gateway.grpc.pb.h"
#include "protocol/bom.pb.h"
#include <processthreadsapi.h>


using grpc::Server;
using grpc::ServerBuilder;

#define BACKLOG 128
#define BUFSIZE 4096

#ifdef __cplusplus 
extern "C" {
#endif
	struct agentc {
		struct skynet_context* ctx;
		HANDLE hProcess;
		HANDLE hThread;
		DWORD dwPID;
		HANDLE ChildIn_Read;
		HANDLE ChildIn_Write;
		HANDLE ChildOut_Read;
		HANDLE ChildOut_Write;
	};

	void CloseProcessHandle(struct agentc* ag)
	{
		if (INVALID_HANDLE_VALUE != ag->ChildIn_Write) {
			char buffer[BUFSIZE] = { "exit()\r\n" };
			DWORD BytesRead, BytesWritten;
			BytesRead = strlen(buffer);
			WriteFile(ag->ChildIn_Write, buffer, BytesRead, &BytesWritten, NULL);
			CloseHandle(ag->ChildIn_Write);
			ag->ChildIn_Write = INVALID_HANDLE_VALUE;
		}
		if (INVALID_HANDLE_VALUE != ag->ChildIn_Read) {
			CloseHandle(ag->ChildIn_Read);
			ag->ChildIn_Read = INVALID_HANDLE_VALUE;
		}
		if (INVALID_HANDLE_VALUE != ag->ChildOut_Write) {
			CloseHandle(ag->ChildOut_Write);
			ag->ChildOut_Write = INVALID_HANDLE_VALUE;
		}

		if (INVALID_HANDLE_VALUE != ag->hThread) {
			CloseHandle(ag->hThread);
			ag->hThread = INVALID_HANDLE_VALUE;
		}

		if (INVALID_HANDLE_VALUE != ag->hProcess) {
			CloseHandle(ag->hProcess);
			ag->hProcess = INVALID_HANDLE_VALUE;
		}
	}

	struct agentc*
		agentc_create(void) {
		struct agentc* ag = (struct agentc*)skynet_malloc(sizeof(*ag));
		if (ag) {
			memset(ag, 0, sizeof(*ag));
			ag->hProcess = INVALID_HANDLE_VALUE;
			ag->hThread = INVALID_HANDLE_VALUE;
			ag->ChildIn_Read = INVALID_HANDLE_VALUE;
			ag->ChildIn_Write = INVALID_HANDLE_VALUE;
			ag->ChildOut_Read = INVALID_HANDLE_VALUE;
			ag->ChildOut_Write = INVALID_HANDLE_VALUE;
		}
		return ag;
	}

	void
		agentc_release(struct agentc* ag) {
		CloseProcessHandle(ag);
		struct skynet_context* ctx = ag->ctx;
		skynet_free(ag);
	}

	void CreateIOPipe(struct agentc* ag)
	{
		SECURITY_ATTRIBUTES saAttr = { 0 };
		saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
		//���Ѹò�����bInheritHandle����ΪTRUE��
		//�������������ľ���ɱ��ӽ��̼̳С�
		//���磬��CreatePipe�����Ĺܵ�������CreateProcess�����Ľ���
		saAttr.bInheritHandle = TRUE;
		saAttr.lpSecurityDescriptor = NULL;

		//ChildIn_Write���ӽ��̵���������ChildIn_Read�Ǹ���������д���ӽ�������ľ��
		CreatePipe(&ag->ChildIn_Read, &ag->ChildIn_Write, &saAttr, 0);
		//�����ӽ��̲��ܼ̳н�������ܵ�����һ�ˣ�ChildIn_Write
		SetHandleInformation(ag->ChildIn_Write, HANDLE_FLAG_INHERIT, 0);
		//ChildOut_Write���ӽ��̵���������ChildOut_Read�Ǹ��������ڶ�ȡ�ӽ�������ľ��

		CreatePipe(&ag->ChildOut_Read, &ag->ChildOut_Write, &saAttr, 0);
		//�����ӽ��̲��ܼ̳з�������ܵ�����һ�ˣ�ChildOut_Read
		SetHandleInformation(ag->ChildOut_Read, HANDLE_FLAG_INHERIT, 0);
	}


	DWORD CreateAppIns(LPTSTR strInsName, STARTUPINFO& si, PROCESS_INFORMATION& pi)
	{
		DWORD iRet = 0;
				
		ZeroMemory(&pi, sizeof(pi));
		if (!CreateProcess(NULL,   // No module name (use command line)
			strInsName,      // Command line
			NULL,           // Process handle not inheritable
			NULL,           // Thread handle not inheritable
			FALSE,          // Set handle inheritance to FALSE
			CREATE_NEW_CONSOLE,              // No creation flags
			NULL,           // Use parent's environment block
			NULL,           // Use parent's starting directory
			&si,            // Pointer to STARTUPINFO structure
			&pi)           // Pointer to PROCESS_INFORMATION structure
			)
		{
			iRet = GetLastError();
			printf("CreateProcess failed (%d)./n", iRet);
		}
		return iRet;
	}

	

	static int
		_cb(struct skynet_context* ctx, void* ud, int type, int session, uint32_t source, const void* msg, size_t sz) {
		struct agentc* ag = (struct agentc*)ud;

		switch (type) {
		case PTYPE_TEXT:
		{
			CloseProcessHandle(ag);
			skynet_error(ctx, "agent started");
		}
		break;
		}
		return 0;
	}

	int agentc_init(struct agentc* ag, struct skynet_context* ctx, char* parm)
	{
		STARTUPINFO si;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);

		CreateIOPipe(ag);

		si.hStdError = ag->ChildOut_Write;
		si.hStdOutput = ag->ChildOut_Write;
		//����׼���붨�����ǽ�����ChildIn_Read��
		si.hStdInput = ag->ChildIn_Read;
		//�����ӽ��̽���StdIn�Լ�StdOut���ض���
		si.dwFlags |= STARTF_USESTDHANDLES;
		//si.dwFlags |= STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW; // ָ��wShowWindow��Ա��Ч  
		si.wShowWindow = TRUE; // �˳�Ա��ΪTRUE�Ļ�����ʾ�½����̵�������  

		PROCESS_INFORMATION pi;
		wchar_t freecadPath[512] = { L"D:\\Program Files\\FreeCAD 0.18\\bin\\FreeCADCmd.exe" };
		DWORD createRet = CreateAppIns(freecadPath, si, pi);
		if (0 != createRet) {
			
		}

		ag->hProcess = pi.hProcess;
		ag->hThread = pi.hThread;
		ag->dwPID = pi.dwProcessId;
				
		skynet_callback(ctx, ag, _cb);
		const char* self = skynet_command(ctx, "REG", NULL);
		uint32_t handle_id = strtoul(self + 1, NULL, 16);
		// it must be first message
		std::string strParam;
		if (parm) {
			strParam = parm;
		}
		skynet_send(ctx, 0, handle_id, PTYPE_TEXT, 0, (void*)strParam.c_str(), strParam.length());
		skynet_error(ctx, "agentc_init");
		return 0;
	}
#ifdef __cplusplus 
}
#endif
