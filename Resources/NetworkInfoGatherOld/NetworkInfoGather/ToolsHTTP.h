BOOL GetHTTPReturnCode(char* serverResponce, int* serverCode);
BOOL GetHTTPserverVersion(char* serverResponce, char* serverVersion, int bannerBufferSize);


#define GET_REQUEST_SIZE    1000
#define SERVER_VERSION_SIZE 100

extern const char* userAgentList[];