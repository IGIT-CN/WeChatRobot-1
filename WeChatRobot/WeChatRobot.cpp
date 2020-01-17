// WeChatRobot.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <curl/curl.h>
#include <jsoncpp/json.h>
#include <sdk.h>
#include <string.h>
#include <windows.h>
#include <wchar.h>

#pragma comment(lib, "../lib/WeChatSDK.lib")
#pragma comment(lib, "../lib/json_vc71_libmt.lib")

struct MemoryStruct {
	char* memory;
	size_t size;
};

static bool isGetMes = false;
wchar_t *revwxid;
wchar_t *revmsg;

const wchar_t* datafrist = L"{\"reqType\":0,\"perception\" : {\"inputText\": {\"text\": \"";
const wchar_t* datalast = L"\"\
			},\
				\"inputImage\" : {\
					\"url\": \"imageUrl\"\
				},\
					\"selfInfo\" : {\
						\"location\": {\
							\"city\": \"南充\",\
								\"province\" : \"四川\",\
								\"street\" : \"南部县万年镇\"\
						}\
					}\
		},\
			\"userInfo\": {\
			\"apiKey\": \"0f4d0b4e5d9f45abb6071b5ec90de203\",\
				\"userId\" : \"542605\"\
		}\
	}";
static size_t
WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct* mem = (struct MemoryStruct*)userp;

	char* ptr = (char *)realloc(mem->memory, mem->size + realsize + 1);
	if (ptr == NULL) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

std::string CurlSet(const char* url, const char* data)
{
	CURL* curl;
	CURLcode res;
	std::string respond;

	struct curl_slist* headers = NULL;

	struct MemoryStruct chunk;

	chunk.memory = (char*)malloc(1);  /* will be grown as needed by the realloc above */
	chunk.size = 0;    /* no data at this point */

	/* In windows, this will init the winsock stuff */
	curl_global_init(CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init();
	if (curl) {
		/* First set the URL that is about to receive our POST. This URL can
		   just as well be a https:// URL if that is what should receive the
		   data. */
		curl_easy_setopt(curl, CURLOPT_URL, url);
		headers = curl_slist_append(headers, "Content-Type:application/json;charset=UTF-8");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		/* send all data to this function  */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

		/* we pass our 'chunk' struct to the callback function */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
		/* Now specify the POST data */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
		}
		else {
			/*
			 * Now, our chunk.memory points to a memory block that is chunk.size
			 * bytes big and contains the remote file.
			 *
			 * Do something nice with it!
			 */

			printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
			//std::cout << chunk.memory << std::endl;
			for (int i = 0; i < chunk.size; i++)
			{
				respond.push_back(*(chunk.memory+i));
			}
			//*respond = *chunk.memory;
		}
		/* always cleanup */
		curl_easy_cleanup(curl);
		free(chunk.memory);
	}
	curl_global_cleanup();
	return respond;
}

void Wchar_tToString(std::string& szDst, wchar_t* wchar)
{
	wchar_t* wText = wchar;
	DWORD dwNum = WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, NULL, 0, NULL, FALSE);// WideCharToMultiByte的运用
	char* psText; // psText为char*的临时数组，作为赋值给std::string的中间变量
	psText = new char[dwNum];
	WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, psText, dwNum, NULL, FALSE);// WideCharToMultiByte的再次运用
	szDst = psText;// std::string赋值
	delete[]psText;// psText的清除
}

char* UnicodeToUtf8(const wchar_t* unicode)
{
	int len;
	len = WideCharToMultiByte(CP_UTF8, 0, unicode, -1, NULL, 0, NULL, NULL);
	char* szUtf8 = (char*)malloc(len + 1);
	memset(szUtf8, 0, len + 1);
	WideCharToMultiByte(CP_UTF8, 0, unicode, -1, szUtf8, len, NULL, NULL);
	return szUtf8;
}

std::wstring Utf8ToUnicode(const std::string& strUTF8)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, strUTF8.c_str(), -1, NULL, 0);
	if (len == 0)
	{
		return L"";
	}

	wchar_t* pRes = new wchar_t[len];
	if (pRes == NULL)
	{
		return L"";
	}

	MultiByteToWideChar(CP_UTF8, 0, strUTF8.c_str(), -1, pRes, len);
	pRes[len - 1] = L'\0';
	std::wstring result = pRes;
	delete[] pRes;

	return result;
}


int TestRecvMoneyMsg(int pid, wchar_t* wxid, wchar_t* tid, wchar_t* msg)
{
	wprintf(L"%ws -> %ws, %ws\n", wxid, tid, msg);
	return 0;
}

int TestRecvTextMsg(int pid, wchar_t* wxid, wchar_t* msg)
{
	if (revmsg == NULL) {

	}
	else
		if (!wcscmp(revmsg, msg)) 
		{
			return 0;
		}
	std::string wxidstr;
	Wchar_tToString(wxidstr,wxid);

	if (wxidstr.find("wxid") == std::string::npos)
	{
		std::cout << "微信公众号消息、群消息" << std::endl;
		return 0;
	}
	else 
	{
		std::cout << "个人微信消息" << std::endl;
	}

	wprintf(L"%ws->%ws\n", wxid, msg);

	wchar_t *data;

	Json::Reader reader;
	Json::Value root;

	int groupType = 0;
	std::string resultType = "";
	std::string values = "";

	data = (wchar_t*)calloc((unsigned int)(wcslen(datafrist)+ wcslen(datalast)+ wcslen(wxid)), sizeof(wchar_t));

	try 
	{
		wcscat(data, datafrist);
		wcscat(data, msg);
		wcscat(data, datalast);
	}
	catch (std::exception  e)
	{
		std::cout << e.what() << std::endl;
		return 0;
	}
	
	std::wcout << data;
	std::string res;

	res = CurlSet("http://openapi.tuling123.com/openapi/api/v2", UnicodeToUtf8((const wchar_t*)data));

	if (reader.parse(res, root))
	{
		if (root["results"].isArray())
		{
			int nArraySize = root["results"].size();
			for (int i = 0; i < nArraySize; i++)
			{
				groupType = root["results"][i]["groupType"].asInt();
				resultType = root["results"][i]["resultType"].asString();

				std::string msgstr;
				if (resultType == "url")
					msgstr = root["results"][i]["values"]["url"].asString();
				else if (resultType == "text")
					msgstr = root["results"][i]["values"]["text"].asString();

				std::wstring tempstr = Utf8ToUnicode(msgstr.c_str());

				std::wcout << tempstr << std::endl;
				revwxid = (wchar_t*)calloc((unsigned int)wcslen(wxid), sizeof(wchar_t));
				revmsg = (wchar_t*)calloc((unsigned int)tempstr.length() * 2, sizeof(wchar_t));

				memcpy((void*)revwxid, (const void*)wxid, (unsigned int)wcslen(wxid) * 2);
				memcpy((void*)revmsg, (const void*)tempstr.c_str(), (unsigned int)tempstr.length() * 2);
			}
		}
	}
	isGetMes = true;
	return 0;
}

int main()
{
    std::cout << "Robot Chat Start!\n";
	DWORD pid = WXOpenWechat();
	if (pid <= 0) {
		std::cout << "open wechat error!" << std::endl;
		return -1;
	}

	while (!WXIsWechatAlive(pid)) {
		std::cout << ".";
		Sleep(1);
	}
	int max = 0;
	if (WXInitialize(pid) != ERROR_SUCCESS) {
		std::cout << "SuperWeChatPC初始化失败，请检查模块是否完整。<WeChatSDK.dll，WeChatSDKCore.dll>" << std::endl;
		getchar();
		return -1;
	}

	//if (WXInitialize(pid) != ERROR_SUCCESS) {
	//	std::cout << "WXInitialize error!" << std::endl;
	//	return -1;
	//}

	while (!WXIsWechatSDKOk(pid)) {
		std::cout << ".";
		Sleep(1);
	}

	std::cout << "superweixin initialize success!" << std::endl;

	WXAntiRevokeMsg(pid);

	std::cout << "start anti revoke msg, enter to unanti." << std::endl;

	getchar();

	WXUnAntiRevokeMsg(pid);

	WXSaveVoiceMsg(pid, L"c:\\wxmsg");

	std::cout << "start save voice msg, enter to stop." << std::endl;

	getchar();

	WXUnSaveVoiceMsg(pid);

	std::cout << "start recv msg." << std::endl;

	//WXRecvTransferMsg(pid, (PFNRECVMONEYMSG_CALLBACK)TestRecvMoneyMsg);

	//WXRecvPayMsg(pid, (PFNRECVMONEYMSG_CALLBACK)TestRecvMoneyMsg);

	WXRecvTextMsg(pid, (PFNRECVTEXTMSG_CALLBACK)TestRecvTextMsg);

	while (1) {
		if (isGetMes)
		{
			std::cout << "接收到消息" << std::endl;
			if (WXSendTextMsg(pid, revwxid, revmsg))
			{
				std::cout << "send message error!" << std::endl;
				break;
			}
			isGetMes = false;
		}
		std::cout << "";
		int i = 5000;
		while (i--);
	}
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
