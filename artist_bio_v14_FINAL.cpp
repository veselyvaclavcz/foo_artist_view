// Artist Bio Component v14.0 - Enhanced with Text Fixes and Layout Switching
#define FOOBAR2000_TARGET_VERSION 80
#define _WIN32_WINNT 0x0600

#include "SDK-2025-03-07/foobar2000/SDK/foobar2000.h"
#include <windows.h>
#include <windowsx.h>
#include <winhttp.h>
#include <wininet.h>
#include <urlmon.h>
#include <shlwapi.h>
#pragma comment(lib, "wininet.lib")
#include <wincodec.h>
#include <olectl.h>
#include <ole2.h>
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")
#include <string>
#include <sstream>
#include <vector>
#include <regex>
#include <map>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib") 
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Component version
DECLARE_COMPONENT_VERSION(
    "Artist Bio Viewer Enhanced",
    "27.0.0", 
    "Artist Biography Viewer v27.0 for foobar2000\n"
    "Enhanced with Text Fixes and Layout Options\n"
    "Features:\n"
    "- FIXED: Text encoding (no weird characters)\n"
    "- Layout switching (horizontal/vertical)\n"
    "- High-quality Spotify artist images\n"
    "- Comprehensive Last.fm biography data\n"
    "- Right-click context menu\n"
    "- Double-click to switch layout\n"
    "- Custom scrollbar matching player theme"
);

VALIDATE_COMPONENT_FILENAME("foo_artist_bio.dll");

// Simple and direct UTF-8 double encoding fix
std::string fix_double_utf8_encoding(const std::string& text) {
    if (text.empty()) return text;
    
    std::string result = text;
    
    // The most common pattern: C3 83 C2 XX -> C3 XX
    // This handles á, é, í, ó, ú, ý, etc.
    size_t pos = 0;
    while (pos + 3 < result.length()) {
        if ((unsigned char)result[pos] == 0xC3 && 
            (unsigned char)result[pos+1] == 0x83 && 
            (unsigned char)result[pos+2] == 0xC2 && 
            pos + 3 < result.length()) {
            // Found the pattern, replace 4 bytes with 2
            unsigned char fourth = (unsigned char)result[pos+3];
            result[pos] = 0xC3;
            result[pos+1] = fourth;
            result.erase(pos+2, 2);
            pos += 2;
        } else {
            pos++;
        }
    }
    
    size_t orig_pos = 0;
    
    // Fix quotes and punctuation first (longer sequences)
    // â€™ -> ' (apostrophe)
    pos = 0;
    while ((pos = result.find("\xc3\xa2\xe2\x82\xac\xe2\x84\xa2", pos)) != std::string::npos) {
        result.replace(pos, 9, "'");
        pos += 1;
    }
    
    // â€œ -> " (left quote)
    pos = 0;
    while ((pos = result.find("\xc3\xa2\xe2\x82\xac\xc5\x93", pos)) != std::string::npos) {
        result.replace(pos, 8, "\"");
        pos += 1;
    }
    
    // â€� -> " (right quote)
    pos = 0;
    while ((pos = result.find("\xc3\xa2\xe2\x82\xac\xef\xbf\xbd", pos)) != std::string::npos) {
        result.replace(pos, 9, "\"");
        pos += 1;
    }
    
    // â€" -> – (en dash)
    pos = 0;
    while ((pos = result.find("\xc3\xa2\xe2\x82\xac\xe2\x80\x9d", pos)) != std::string::npos) {
        result.replace(pos, 9, "-");
        pos += 1;
    }
    
    // Czech characters with carons (must be before basic accented letters)
    // Å™ -> ř
    pos = 0;
    while ((pos = result.find("\xc3\x85\xe2\x84\xa2", pos)) != std::string::npos) {
        result.replace(pos, 5, "\xc5\x99");
        pos += 2;
    }
    
    // Ä -> č (when followed by certain bytes)
    pos = 0;
    while ((pos = result.find("\xc3\x84\xc4\x8d", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc4\x8d");
        pos += 2;
    }
    
    // Alternative Ä -> č
    pos = 0;
    while ((pos = result.find("\xc3\x84\x8d", pos)) != std::string::npos) {
        result.replace(pos, 3, "\xc4\x8d");
        pos += 2;
    }
    
    // Å¾ -> ž
    pos = 0;
    while ((pos = result.find("\xc3\x85\xc2\xbe", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc5\xbe");
        pos += 2;
    }
    
    // Ä› -> ě
    pos = 0;
    while ((pos = result.find("\xc3\x84\xe2\x80\x9b", pos)) != std::string::npos) {
        result.replace(pos, 5, "\xc4\x9b");
        pos += 2;
    }
    
    // Å¡ -> š
    pos = 0;
    while ((pos = result.find("\xc3\x85\xc2\xa1", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc5\xa1");
        pos += 2;
    }
    
    // Basic Latin accented characters
    // Ã¡ -> á
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\xa1", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\xa1");
        pos += 2;
    }
    
    // Ã© -> é
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\xa9", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\xa9");
        pos += 2;
    }
    
    // Ã­ -> í
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\xad", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\xad");
        pos += 2;
    }
    
    // Ã³ -> ó
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\xb3", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\xb3");
        pos += 2;
    }
    
    // Ãº -> ú
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\xba", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\xba");
        pos += 2;
    }
    
    // Ã½ -> ý
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\xbd", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\xbd");
        pos += 2;
    }
    
    // Ã¤ -> ä
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\xa4", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\xa4");
        pos += 2;
    }
    
    // Ã¶ -> ö
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\xb6", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\xb6");
        pos += 2;
    }
    
    // Ã¸ -> ø
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\xb8", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\xb8");
        pos += 2;
    }
    
    // Capital letters
    // Ã -> Á
    pos = 0;
    while ((pos = result.find("\xc3\x83\xc2\x81", pos)) != std::string::npos) {
        result.replace(pos, 4, "\xc3\x81");
        pos += 2;
    }
    
    return result;
}

// Helper to decode HTML entities
std::string decode_html_entities(const std::string& text) {
    std::string result = text;
    
    // Common HTML entities
    size_t pos = 0;
    while ((pos = result.find("&quot;", pos)) != std::string::npos) {
        result.replace(pos, 6, "\"");
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("&amp;", pos)) != std::string::npos) {
        result.replace(pos, 5, "&");
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("&lt;", pos)) != std::string::npos) {
        result.replace(pos, 4, "<");
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("&gt;", pos)) != std::string::npos) {
        result.replace(pos, 4, ">");
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("&#39;", pos)) != std::string::npos) {
        result.replace(pos, 5, "'");
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("&apos;", pos)) != std::string::npos) {
        result.replace(pos, 6, "'");
        pos += 1;
    }
    
    // Remove \n literal
    pos = 0;
    while ((pos = result.find("\\n", pos)) != std::string::npos) {
        result.replace(pos, 2, "\n");
        pos += 1;
    }
    
    // Fix UTF-8 weird characters - using hex values to avoid compilation issues
    pos = 0;
    while ((pos = result.find("\xe2\x80\x9c", pos)) != std::string::npos) {
        result.replace(pos, 3, "\"");  // Left double quote
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("\xe2\x80\x9d", pos)) != std::string::npos) {
        result.replace(pos, 3, "\"");  // Right double quote
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("\xe2\x80\x98", pos)) != std::string::npos) {
        result.replace(pos, 3, "'");  // Left single quote
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("\xe2\x80\x99", pos)) != std::string::npos) {
        result.replace(pos, 3, "'");  // Right single quote/apostrophe
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("\xe2\x80\x93", pos)) != std::string::npos) {
        result.replace(pos, 3, "-");  // En dash
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("\xe2\x80\x94", pos)) != std::string::npos) {
        result.replace(pos, 3, "-");  // Em dash
        pos += 1;
    }
    pos = 0;
    while ((pos = result.find("\xe2\x80\xa6", pos)) != std::string::npos) {
        result.replace(pos, 3, "...");  // Ellipsis
        pos += 3;
    }
    pos = 0;
    while ((pos = result.find("\xe2\x80\xa2", pos)) != std::string::npos) {
        result.replace(pos, 3, "*");  // Bullet point
        pos += 1;
    }
    
    return result;
}

// Format large numbers with commas
std::string format_number(const std::string& num_str) {
    std::string result = num_str;
    for (int i = result.length() - 3; i > 0; i -= 3) {
        result.insert(i, ",");
    }
    return result;
}

// Multi-source music API client with full data extraction
class music_api_client {
private:
    std::wstring string_to_wstring(const std::string& str) {
        if (str.empty()) return std::wstring();
        int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        std::wstring result(size, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
        return result;
    }
    
    std::string url_encode(const std::string& str) {
        std::ostringstream encoded;
        for (char c : str) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded << c;
            } else {
                encoded << '%' << std::hex << std::uppercase << (int)(unsigned char)c;
            }
        }
        return encoded.str();
    }
    
    std::string http_get_wininet(const std::wstring& host, const std::wstring& path, bool use_https = true) {
        std::string response_data;
        
        console::formatter() << "Artist Bio: Using WinINet - host: " << pfc::stringcvt::string_utf8_from_wide(host.c_str()) 
                            << " path: " << pfc::stringcvt::string_utf8_from_wide(path.c_str());
        
        HINTERNET hInternet = InternetOpenW(L"Artist Bio Viewer/11.0", 
            INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        
        if (!hInternet) {
            console::print("Artist Bio: InternetOpen failed");
            return response_data;
        }
        
        INTERNET_PORT port = use_https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
        HINTERNET hConnect = InternetConnectW(hInternet, host.c_str(), port, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (!hConnect) {
            console::print("Artist Bio: InternetConnect failed");
            InternetCloseHandle(hInternet);
            return response_data;
        }
        
        DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        if (use_https) {
            dwFlags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | 
                      INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        }
        
        HINTERNET hRequest = HttpOpenRequestW(hConnect, L"GET", path.c_str(), 
            NULL, NULL, NULL, dwFlags, 0);
        
        if (!hRequest) {
            console::print("Artist Bio: HttpOpenRequest failed");
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return response_data;
        }
        
        if (!HttpSendRequestW(hRequest, NULL, 0, NULL, 0)) {
            DWORD error = GetLastError();
            console::formatter() << "Artist Bio: HttpSendRequest failed with error: " << error;
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return response_data;
        }
        
        // Read response
        char buffer[4096];
        DWORD bytesRead;
        
        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = 0;
            response_data.append(buffer, bytesRead);
            console::formatter() << "Artist Bio: Read " << bytesRead << " bytes";
        }
        
        console::formatter() << "Artist Bio: Total response: " << response_data.length() << " bytes";
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return response_data;
    }
    
    std::string http_post_wininet(const std::wstring& host, const std::wstring& path, const std::string& data, const std::string& headers) {
        std::string response_data;
        
        HINTERNET hInternet = InternetOpenW(L"Artist Bio Viewer/12.0", 
            INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        
        if (!hInternet) return response_data;
        
        HINTERNET hConnect = InternetConnectW(hInternet, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return response_data;
        }
        
        DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | 
                       INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | 
                       INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        
        HINTERNET hRequest = HttpOpenRequestW(hConnect, L"POST", path.c_str(), 
            NULL, NULL, NULL, dwFlags, 0);
        
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return response_data;
        }
        
        std::wstring wide_headers = string_to_wstring(headers);
        
        if (!HttpSendRequestW(hRequest, wide_headers.c_str(), wide_headers.length(), 
                             (LPVOID)data.c_str(), data.length())) {
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return response_data;
        }
        
        // Read response
        char buffer[4096];
        DWORD bytesRead;
        
        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = 0;
            response_data.append(buffer, bytesRead);
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return response_data;
    }
    
    std::string http_get_wininet_with_headers(const std::wstring& host, const std::wstring& path, const std::string& headers) {
        std::string response_data;
        
        HINTERNET hInternet = InternetOpenW(L"Artist Bio Viewer/12.0", 
            INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        
        if (!hInternet) return response_data;
        
        HINTERNET hConnect = InternetConnectW(hInternet, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return response_data;
        }
        
        DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | 
                       INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | 
                       INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        
        HINTERNET hRequest = HttpOpenRequestW(hConnect, L"GET", path.c_str(), 
            NULL, NULL, NULL, dwFlags, 0);
        
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return response_data;
        }
        
        std::wstring wide_headers = string_to_wstring(headers);
        
        if (!HttpSendRequestW(hRequest, wide_headers.c_str(), wide_headers.length(), NULL, 0)) {
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return response_data;
        }
        
        // Read response
        char buffer[4096];
        DWORD bytesRead;
        
        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = 0;
            response_data.append(buffer, bytesRead);
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return response_data;
    }
    
    // Simple memory stream for URLDownloadToMemory
    class MemoryStream : public IStream {
    public:
        std::string data;
        size_t position = 0;
        ULONG ref_count = 1;
        
        // IUnknown methods
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
            if (riid == IID_IUnknown || riid == IID_IStream) {
                *ppvObject = this;
                AddRef();
                return S_OK;
            }
            return E_NOINTERFACE;
        }
        
        ULONG STDMETHODCALLTYPE AddRef() override {
            return ++ref_count;
        }
        
        ULONG STDMETHODCALLTYPE Release() override {
            if (--ref_count == 0) {
                delete this;
                return 0;
            }
            return ref_count;
        }
        
        // IStream methods
        HRESULT STDMETHODCALLTYPE Read(void* pv, ULONG cb, ULONG* pcbRead) override {
            return E_NOTIMPL;
        }
        
        HRESULT STDMETHODCALLTYPE Write(const void* pv, ULONG cb, ULONG* pcbWritten) override {
            data.append((const char*)pv, cb);
            if (pcbWritten) *pcbWritten = cb;
            return S_OK;
        }
        
        HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER dlibMove, DWORD dwOrigin, ULARGE_INTEGER* plibNewPosition) override {
            return E_NOTIMPL;
        }
        
        HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER libNewSize) override {
            return E_NOTIMPL;
        }
        
        HRESULT STDMETHODCALLTYPE CopyTo(IStream* pstm, ULARGE_INTEGER cb, ULARGE_INTEGER* pcbRead, ULARGE_INTEGER* pcbWritten) override {
            return E_NOTIMPL;
        }
        
        HRESULT STDMETHODCALLTYPE Commit(DWORD grfCommitFlags) override {
            return S_OK;
        }
        
        HRESULT STDMETHODCALLTYPE Revert() override {
            return E_NOTIMPL;
        }
        
        HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) override {
            return E_NOTIMPL;
        }
        
        HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) override {
            return E_NOTIMPL;
        }
        
        HRESULT STDMETHODCALLTYPE Stat(STATSTG* pstatstg, DWORD grfStatFlag) override {
            return E_NOTIMPL;
        }
        
        HRESULT STDMETHODCALLTYPE Clone(IStream** ppstm) override {
            return E_NOTIMPL;
        }
    };
    
    std::string http_get(const std::wstring& host, const std::wstring& path, bool use_https = true) {
        std::string response_data;
        
        // Build full URL
        std::wstring protocol = use_https ? L"https://" : L"http://";
        std::wstring full_url = protocol + host + path;
        
        console::formatter() << "Artist Bio: Downloading via PowerShell from: " << pfc::stringcvt::string_utf8_from_wide(full_url.c_str());
        
        // Create temp file for output
        wchar_t temp_path[MAX_PATH];
        wchar_t temp_file[MAX_PATH];
        GetTempPathW(MAX_PATH, temp_path);
        GetTempFileNameW(temp_path, L"bio", 0, temp_file);
        
        // Build PowerShell command
        std::wstring command = L"powershell -Command \"(Invoke-WebRequest -Uri '";
        command += full_url;
        command += L"' -UseBasicParsing).Content | Out-File -FilePath '";
        command += temp_file;
        command += L"' -Encoding UTF8\"";
        
        // Execute PowerShell
        STARTUPINFOW si = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        PROCESS_INFORMATION pi = {0};
        
        if (CreateProcessW(NULL, (LPWSTR)command.c_str(), NULL, NULL, FALSE, 
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            // Wait for PowerShell to complete (max 5 seconds)
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            
            // Read the temp file
            HANDLE hFile = CreateFileW(temp_file, GENERIC_READ, FILE_SHARE_READ, 
                                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD file_size = GetFileSize(hFile, NULL);
                if (file_size != INVALID_FILE_SIZE && file_size > 0) {
                    std::vector<char> buffer(file_size);
                    DWORD bytes_read = 0;
                    if (ReadFile(hFile, buffer.data(), file_size, &bytes_read, NULL)) {
                        response_data.assign(buffer.data(), bytes_read);
                        console::formatter() << "Artist Bio: Downloaded " << bytes_read << " bytes via PowerShell";
                    }
                }
                CloseHandle(hFile);
            }
            
            // Delete temp file
            DeleteFileW(temp_file);
        } else {
            console::print("Artist Bio: Failed to execute PowerShell");
        }
        
        return response_data;
    }
    
    std::string http_get_old(const std::wstring& host, const std::wstring& path, bool use_https = true) {
        std::string response_data;
        
        console::formatter() << "Artist Bio: http_get called - host: " << pfc::stringcvt::string_utf8_from_wide(host.c_str()) 
                            << " path: " << pfc::stringcvt::string_utf8_from_wide(path.c_str())
                            << " https: " << (use_https ? "yes" : "no");
        
        HINTERNET hSession = WinHttpOpen(
            L"Artist Bio Viewer/10.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );
        
        if (!hSession) {
            console::print("Artist Bio: Failed to open WinHTTP session");
            return response_data;
        }
        
        HINTERNET hConnect = WinHttpConnect(
            hSession,
            host.c_str(),
            use_https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT,
            0
        );
        
        if (!hConnect) {
            console::formatter() << "Artist Bio: Failed to connect to " << pfc::stringcvt::string_utf8_from_wide(host.c_str());
            WinHttpCloseHandle(hSession);
            return response_data;
        }
        
        DWORD flags = use_https ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"GET",
            path.c_str(),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            flags
        );
        
        if (!hRequest) {
            console::print("Artist Bio: Failed to create HTTP request");
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return response_data;
        }
        
        // Disable SSL certificate validation for testing
        if (use_https) {
            DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
                           SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                           SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
        }
        
        BOOL bResults = WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0
        );
        
        if (!bResults) {
            DWORD error = GetLastError();
            console::formatter() << "Artist Bio: WinHttpSendRequest failed with error: " << error;
        } else {
            bResults = WinHttpReceiveResponse(hRequest, NULL);
            if (!bResults) {
                DWORD error = GetLastError();
                console::formatter() << "Artist Bio: WinHttpReceiveResponse failed with error: " << error;
            }
        }
        
        if (bResults) {
            console::print("Artist Bio: Request succeeded, getting status code");
            DWORD dwStatusCode = 0;
            DWORD dwSize = sizeof(dwStatusCode);
            WinHttpQueryHeaders(
                hRequest,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &dwStatusCode,
                &dwSize,
                WINHTTP_NO_HEADER_INDEX
            );
            
            console::formatter() << "Artist Bio: HTTP Status Code: " << dwStatusCode;
            
            if (dwStatusCode == 200) {
                DWORD dwDownloaded = 0;
                char buffer[4096];
                
                console::print("Artist Bio: Attempting to read response data directly");
                
                // Try reading directly without checking availability
                do {
                    dwDownloaded = 0;
                    if (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &dwDownloaded)) {
                        if (dwDownloaded > 0) {
                            buffer[dwDownloaded] = 0; // Null terminate for safety
                            response_data.append(buffer, dwDownloaded);
                            console::formatter() << "Artist Bio: Read chunk of " << dwDownloaded << " bytes";
                        }
                    } else {
                        DWORD error = GetLastError();
                        if (error != ERROR_WINHTTP_INVALID_SERVER_RESPONSE) {
                            console::formatter() << "Artist Bio: WinHttpReadData error: " << error;
                        }
                        break;
                    }
                } while (dwDownloaded > 0);
                
                console::formatter() << "Artist Bio: Total response size: " << response_data.length() << " bytes";
            } else {
                console::formatter() << "Artist Bio: Unexpected status code, not reading response";
            }
        }
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return response_data;
    }
    
public:
    struct track_info {
        std::string name;
        std::string playcount;
        std::string listeners;
    };
    
    struct album_info {
        std::string name;
        std::string playcount;
        std::string image_url;
    };
    
    struct artist_info {
        // Basic info
        std::string name;
        std::string mbid; // MusicBrainz ID
        std::string url;
        
        // Biography
        std::string biography_summary;
        std::string biography_full;
        std::string published_date;
        
        // Images
        std::string image_small;
        std::string image_medium;
        std::string image_large;
        std::string image_extralarge;
        std::string image_mega;
        
        // Statistics
        std::string listeners;
        std::string playcount;
        std::string userplaycount;
        
        // Tags/Genres
        std::vector<std::pair<std::string, std::string>> tags; // name, count
        
        // Similar artists
        std::vector<std::pair<std::string, std::string>> similar_artists; // name, match%
        
        // Top tracks
        std::vector<track_info> top_tracks;
        
        // Top albums
        std::vector<album_info> top_albums;
        
        // Additional info
        std::string on_tour;
        std::map<std::string, std::string> links; // External links
        
        bool found = false;
    };
    
    // Get comprehensive artist info from Last.fm
    artist_info get_artist_info_complete(const std::string& artist_name) {
        artist_info result;
        
        // Get Spotify access token first
        std::string spotify_access_token = get_spotify_access_token();
        
        if (!spotify_access_token.empty()) {
            // Get Spotify data for high-quality images and metadata
            get_spotify_data(artist_name, spotify_access_token, result);
        }
        
        // Get Last.fm data for biography and additional info
        get_lastfm_data(artist_name, result);
        
        return result;
    }
    
private:
    // Spotify credentials and functions
    const std::string SPOTIFY_CLIENT_ID = "36c970e603804c17acd54b2a1f2f4e8d";
    const std::string SPOTIFY_CLIENT_SECRET = "9197266313734f199e0c93e40f373f47";
    
    std::string get_spotify_access_token() {
        console::print("Artist Bio: Getting Spotify access token...");
        
        std::string response_data;
        std::string credentials = SPOTIFY_CLIENT_ID + ":" + SPOTIFY_CLIENT_SECRET;
        std::string auth_data = "grant_type=client_credentials";
        std::string auth_encoded = base64_encode(credentials);
        
        console::print("Artist Bio: Using WinINet for Spotify auth");
        
        HINTERNET hInternet = InternetOpenW(L"Artist Bio Viewer/12.0", 
            INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        
        if (!hInternet) {
            console::print("Artist Bio: InternetOpen failed for Spotify");
            return "";
        }
        
        HINTERNET hConnect = InternetConnectW(hInternet, L"accounts.spotify.com", INTERNET_DEFAULT_HTTPS_PORT, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (!hConnect) {
            console::print("Artist Bio: InternetConnect failed for Spotify");
            InternetCloseHandle(hInternet);
            return "";
        }
        
        DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | 
                       INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | 
                       INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        
        HINTERNET hRequest = HttpOpenRequestW(hConnect, L"POST", L"/api/token", 
            NULL, NULL, NULL, dwFlags, 0);
        
        if (!hRequest) {
            console::print("Artist Bio: HttpOpenRequest failed for Spotify");
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }
        
        // Add headers manually
        std::wstring auth_header = L"Authorization: Basic " + string_to_wstring(auth_encoded);
        std::wstring content_header = L"Content-Type: application/x-www-form-urlencoded";
        
        HttpAddRequestHeadersW(hRequest, auth_header.c_str(), -1, HTTP_ADDREQ_FLAG_ADD);
        HttpAddRequestHeadersW(hRequest, content_header.c_str(), -1, HTTP_ADDREQ_FLAG_ADD);
        
        if (!HttpSendRequestW(hRequest, NULL, 0, (LPVOID)auth_data.c_str(), auth_data.length())) {
            DWORD error = GetLastError();
            console::formatter() << "Artist Bio: HttpSendRequest failed for Spotify with error: " << error;
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }
        
        console::print("Artist Bio: Spotify auth request sent successfully");
        
        // Read response
        char buffer[4096];
        DWORD bytesRead;
        
        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = 0;
            response_data.append(buffer, bytesRead);
        }
        
        console::formatter() << "Artist Bio: Spotify auth response length: " << response_data.length();
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        if (response_data.empty()) {
            console::print("Artist Bio: Empty response from Spotify auth");
            return "";
        }
        
        // Extract access token from JSON response
        std::string token = extract_json_value(response_data, "access_token");
        if (token.empty()) {
            console::print("Artist Bio: Failed to extract access token from Spotify response");
            console::formatter() << "Artist Bio: Response was: " << response_data.substr(0, 200).c_str();
        } else {
            console::print("Artist Bio: Successfully got Spotify access token");
        }
        return token;
    }
    
    void get_spotify_data(const std::string& artist_name, const std::string& access_token, artist_info& result) {
        console::formatter() << "Artist Bio: Getting Spotify data for: " << artist_name.c_str();
        
        std::string response_data;
        std::string encoded_artist = url_encode(artist_name);
        std::string search_path = "/v1/search?q=" + encoded_artist + "&type=artist&limit=1";
        
        console::formatter() << "Artist Bio: Spotify search path: " << search_path.c_str();
        
        HINTERNET hInternet = InternetOpenW(L"Artist Bio Viewer/12.0", 
            INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        
        if (!hInternet) {
            console::print("Artist Bio: InternetOpen failed for Spotify search");
            return;
        }
        
        HINTERNET hConnect = InternetConnectW(hInternet, L"api.spotify.com", INTERNET_DEFAULT_HTTPS_PORT, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (!hConnect) {
            console::print("Artist Bio: InternetConnect failed for Spotify search");
            InternetCloseHandle(hInternet);
            return;
        }
        
        DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | 
                       INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | 
                       INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        
        std::wstring wide_path = string_to_wstring(search_path);
        HINTERNET hRequest = HttpOpenRequestW(hConnect, L"GET", wide_path.c_str(), 
            NULL, NULL, NULL, dwFlags, 0);
        
        if (!hRequest) {
            console::print("Artist Bio: HttpOpenRequest failed for Spotify search");
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return;
        }
        
        // Add authorization header
        std::wstring auth_header = L"Authorization: Bearer " + string_to_wstring(access_token);
        HttpAddRequestHeadersW(hRequest, auth_header.c_str(), -1, HTTP_ADDREQ_FLAG_ADD);
        
        if (!HttpSendRequestW(hRequest, NULL, 0, NULL, 0)) {
            DWORD error = GetLastError();
            console::formatter() << "Artist Bio: HttpSendRequest failed for Spotify search with error: " << error;
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return;
        }
        
        console::print("Artist Bio: Spotify search request sent successfully");
        
        // Read response
        char buffer[4096];
        DWORD bytesRead;
        
        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = 0;
            response_data.append(buffer, bytesRead);
            console::formatter() << "Artist Bio: Read " << bytesRead << " bytes from Spotify";
        }
        
        console::formatter() << "Artist Bio: Spotify search response length: " << response_data.length();
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        if (!response_data.empty()) {
            parse_spotify_response(response_data, result);
        } else {
            console::print("Artist Bio: Empty response from Spotify API");
        }
    }
    
    void get_lastfm_data(const std::string& artist_name, artist_info& result) {
        std::wstring host = L"ws.audioscrobbler.com";
        std::string api_key = "b25b959554ed76058ac220b7b2e0a026";
        std::string encoded_artist = url_encode(artist_name);
        std::wstring path = string_to_wstring("/2.0/?method=artist.getinfo&artist=" + encoded_artist + "&api_key=" + api_key + "&format=json");
        
        std::string response = http_get_wininet(host, path);
        
        if (!response.empty()) {
            parse_lastfm_response(response, result);
        }
    }
    
    std::string base64_encode(const std::string& input) {
        static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        int val = 0, valb = -6;
        
        for (char c : input) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back('=');
        return result;
    }
    
    std::string extract_json_value(const std::string& json, const std::string& key) {
        std::string search_key = "\"" + key + "\":\"";
        size_t pos = json.find(search_key);
        if (pos == std::string::npos) return "";
        
        pos += search_key.length();
        
        // Find the end of the value string, handling escaped quotes
        size_t end = pos;
        bool in_escape = false;
        while (end < json.length()) {
            if (json[end] == '\\' && !in_escape) {
                in_escape = true;
            } else if (json[end] == '"' && !in_escape) {
                // Found the closing quote
                break;
            } else {
                in_escape = false;
            }
            end++;
        }
        
        if (end >= json.length()) return "";
        
        return json.substr(pos, end - pos);
    }
    
    void parse_spotify_response(const std::string& json, artist_info& result) {
        // Extract first artist from artists.items array
        size_t images_pos = json.find("\"images\":[");
        if (images_pos != std::string::npos) {
            // Get the highest quality image (first in array)
            size_t url_pos = json.find("\"url\":\"", images_pos);
            if (url_pos != std::string::npos) {
                url_pos += 7;
                size_t url_end = json.find("\"", url_pos);
                if (url_end != std::string::npos) {
                    result.image_extralarge = json.substr(url_pos, url_end - url_pos);
                    result.image_large = result.image_extralarge; // Use same high-quality image
                }
            }
        }
        
        // Extract followers and popularity for additional metadata
        std::string followers = extract_json_value(json, "total");
        std::string popularity = extract_json_value(json, "popularity");
        
        if (!followers.empty() && !popularity.empty()) {
            result.listeners = "Spotify: " + format_number(followers) + " followers";
            result.playcount = "Popularity: " + popularity + "/100";
        }
        
        result.found = true;
    }
    
    void parse_lastfm_response(const std::string& json, artist_info& result) {
        // Extract artist name and apply encoding fixes
        result.name = fix_double_utf8_encoding(decode_html_entities(extract_json_value(json, "name")));
        
        // Extract biography
        size_t bio_pos = json.find("\"bio\":{");
        if (bio_pos != std::string::npos) {
            size_t content_pos = json.find("\"content\":\"", bio_pos);
            if (content_pos != std::string::npos) {
                content_pos += 11;
                
                // Find the end of the content string, handling escaped quotes
                size_t content_end = content_pos;
                bool in_escape = false;
                while (content_end < json.length()) {
                    if (json[content_end] == '\\' && !in_escape) {
                        in_escape = true;
                    } else if (json[content_end] == '"' && !in_escape) {
                        // Found the closing quote
                        break;
                    } else {
                        in_escape = false;
                    }
                    content_end++;
                }
                
                if (content_end < json.length()) {
                    std::string bio = json.substr(content_pos, content_end - content_pos);
                    result.biography_full = clean_biography_text(bio);
                    
                    // Create summary from cleaned text
                    if (result.biography_full.length() > 500) {
                        result.biography_summary = result.biography_full.substr(0, 500) + "...";
                    } else {
                        result.biography_summary = result.biography_full;
                    }
                }
            }
        }
        
        // Extract Last.fm stats
        std::string lastfm_listeners = extract_json_value(json, "listeners");
        std::string lastfm_playcount = extract_json_value(json, "playcount");
        
        if (!lastfm_listeners.empty()) {
            if (!result.listeners.empty()) {
                result.listeners += " | Last.fm: " + format_number(lastfm_listeners) + " listeners";
            } else {
                result.listeners = "Last.fm: " + format_number(lastfm_listeners) + " listeners";
            }
        }
        
        if (!lastfm_playcount.empty()) {
            if (!result.playcount.empty()) {
                result.playcount += " | " + format_number(lastfm_playcount) + " plays";
            } else {
                result.playcount = format_number(lastfm_playcount) + " plays";
            }
        }
        
        result.found = true;
    }
    
    std::string clean_biography_text(const std::string& text) {
        std::string result = text;
        
        // Remove HTML tags
        size_t link_pos;
        while ((link_pos = result.find("<a href=")) != std::string::npos) {
            size_t link_end = result.find("</a>", link_pos);
            if (link_end != std::string::npos) {
                // Extract link text before removing the whole tag
                size_t text_start = result.find(">", link_pos) + 1;
                if (text_start < link_end) {
                    std::string link_text = result.substr(text_start, link_end - text_start);
                    result.replace(link_pos, link_end - link_pos + 4, link_text);
                } else {
                    result.erase(link_pos, link_end - link_pos + 4);
                }
            } else {
                break;
            }
        }
        
        // Replace escape sequences - order matters!
        // Handle escaped backslash first
        size_t pos = 0;
        while ((pos = result.find("\\\\", pos)) != std::string::npos) {
            result.replace(pos, 2, "\\");
            pos += 1;
        }
        
        // Handle newlines
        pos = 0;
        while ((pos = result.find("\\n", pos)) != std::string::npos) {
            result.replace(pos, 2, "\n");
            pos += 1;
        }
        
        // Handle quotes
        pos = 0;
        while ((pos = result.find("\\\"", pos)) != std::string::npos) {
            result.replace(pos, 2, "\"");
            pos += 1;
        }
        
        // Handle forward slashes
        pos = 0;
        while ((pos = result.find("\\/", pos)) != std::string::npos) {
            result.replace(pos, 2, "/");
            pos += 1;
        }
        
        // Handle tabs
        pos = 0;
        while ((pos = result.find("\\t", pos)) != std::string::npos) {
            result.replace(pos, 2, "\t");
            pos += 1;
        }
        
        // Handle carriage returns
        pos = 0;
        while ((pos = result.find("\\r", pos)) != std::string::npos) {
            result.replace(pos, 2, "\r");
            pos += 1;
        }
        
        // Clean up any remaining backslashes at the end (truncation artifacts)
        if (!result.empty() && result.back() == '\\') {
            result.pop_back();
        }
        
        // Apply HTML entity decoding to fix weird characters
        result = decode_html_entities(result);
        
        // Fix double UTF-8 encoding issues from API responses
        result = fix_double_utf8_encoding(result);
        
        return result;
    }
    
    std::string format_number(const std::string& num_str) {
        try {
            long long num = std::stoll(num_str);
            if (num >= 1000000) {
                double millions = num / 1000000.0;
                char buffer[32];
                sprintf_s(buffer, "%.1fM", millions);
                return buffer;
            } else if (num >= 1000) {
                double thousands = num / 1000.0;
                char buffer[32];
                sprintf_s(buffer, "%.1fK", thousands);
                return buffer;
            }
            return num_str;
        } catch (...) {
            return num_str;
        }
    }

    // Legacy function - now unused, kept for compatibility
    artist_info get_artist_info_lastfm(const std::string& artist_name) {
        artist_info result;
        result.found = false;
        return result;
    }
    
    void get_top_tracks(const std::string& artist_name, artist_info& info) {
        std::string api_key = "b25b959554ed76058ac220b7b2e0a026";
        std::string encoded_artist = url_encode(artist_name);
        std::string path = "/2.0/?method=artist.gettoptracks&artist=" + encoded_artist + 
                          "&api_key=" + api_key + "&format=json&limit=5";
        
        std::wstring wide_path = string_to_wstring(path);
        std::string response = http_get(L"ws.audioscrobbler.com", wide_path, false);
        
        if (!response.empty()) {
            parse_top_tracks(response, info);
        }
    }
    
    void get_top_albums(const std::string& artist_name, artist_info& info) {
        std::string api_key = "b25b959554ed76058ac220b7b2e0a026";
        std::string encoded_artist = url_encode(artist_name);
        std::string path = "/2.0/?method=artist.gettopalbums&artist=" + encoded_artist + 
                          "&api_key=" + api_key + "&format=json&limit=5";
        
        std::wstring wide_path = string_to_wstring(path);
        std::string response = http_get(L"ws.audioscrobbler.com", wide_path, false);
        
        if (!response.empty()) {
            parse_top_albums(response, info);
        }
    }
    
    artist_info parse_lastfm_full_response(const std::string& json) {
        artist_info result;
        
        // Check if artist exists
        if (json.find("\"error\"") != std::string::npos) {
            return result;
        }
        
        // Extract artist name
        size_t name_pos = json.find("\"name\":\"");
        if (name_pos != std::string::npos) {
            name_pos += 8;
            size_t name_end = json.find("\"", name_pos);
            if (name_end != std::string::npos) {
                result.name = json.substr(name_pos, name_end - name_pos);
                result.found = true;
            }
        }
        
        // Extract MBID
        size_t mbid_pos = json.find("\"mbid\":\"");
        if (mbid_pos != std::string::npos) {
            mbid_pos += 8;
            size_t mbid_end = json.find("\"", mbid_pos);
            if (mbid_end != std::string::npos) {
                result.mbid = json.substr(mbid_pos, mbid_end - mbid_pos);
            }
        }
        
        // Extract URL
        size_t url_pos = json.find("\"url\":\"");
        if (url_pos != std::string::npos) {
            url_pos += 7;
            size_t url_end = json.find("\"", url_pos);
            if (url_end != std::string::npos) {
                result.url = json.substr(url_pos, url_end - url_pos);
            }
        }
        
        // Extract images (Last.fm uses #text field for URLs)
        size_t img_pos = json.find("\"image\":[");
        if (img_pos != std::string::npos) {
            size_t img_end = json.find("]", img_pos);
            if (img_end != std::string::npos) {
                std::string img_section = json.substr(img_pos, img_end - img_pos);
                
                // Parse each image object
                size_t obj_pos = 0;
                while ((obj_pos = img_section.find("{", obj_pos)) != std::string::npos) {
                    size_t obj_end = img_section.find("}", obj_pos);
                    if (obj_end == std::string::npos) break;
                    
                    std::string img_obj = img_section.substr(obj_pos, obj_end - obj_pos + 1);
                    
                    // Get size
                    std::string size;
                    size_t size_pos = img_obj.find("\"size\":\"");
                    if (size_pos != std::string::npos) {
                        size_pos += 8;
                        size_t size_end = img_obj.find("\"", size_pos);
                        if (size_end != std::string::npos) {
                            size = img_obj.substr(size_pos, size_end - size_pos);
                        }
                    }
                    
                    // Get URL from #text field
                    size_t url_pos = img_obj.find("\"#text\":\"");
                    if (url_pos != std::string::npos) {
                        url_pos += 9;
                        size_t url_end = img_obj.find("\"", url_pos);
                        if (url_end != std::string::npos) {
                            std::string url = img_obj.substr(url_pos, url_end - url_pos);
                            
                            // Assign to appropriate size
                            if (size == "small") result.image_small = url;
                            else if (size == "medium") result.image_medium = url;
                            else if (size == "large") result.image_large = url;
                            else if (size == "extralarge") result.image_extralarge = url;
                            else if (size == "mega") result.image_mega = url;
                        }
                    }
                    
                    obj_pos = obj_end + 1;
                }
            }
        }
        
        // Extract bio summary
        size_t bio_summary_pos = json.find("\"summary\":\"");
        if (bio_summary_pos != std::string::npos) {
            bio_summary_pos += 11;
            size_t bio_end = json.find("\",", bio_summary_pos);
            if (bio_end != std::string::npos) {
                std::string bio = json.substr(bio_summary_pos, bio_end - bio_summary_pos);
                
                // Remove HTML tags
                std::regex html_tags("<[^>]*>");
                bio = std::regex_replace(bio, html_tags, "");
                
                // Remove Last.fm attribution
                size_t link_pos = bio.find("Read more on Last.fm");
                if (link_pos != std::string::npos) {
                    bio = bio.substr(0, link_pos);
                }
                
                result.biography_summary = decode_html_entities(bio);
            }
        }
        
        // Extract full bio content
        size_t bio_content_pos = json.find("\"content\":\"");
        if (bio_content_pos != std::string::npos) {
            bio_content_pos += 11;
            size_t bio_end = json.find("\",", bio_content_pos);
            if (bio_end != std::string::npos) {
                std::string bio = json.substr(bio_content_pos, bio_end - bio_content_pos);
                
                // Remove HTML tags
                std::regex html_tags("<[^>]*>");
                bio = std::regex_replace(bio, html_tags, "");
                
                // Remove Last.fm attribution
                size_t link_pos = bio.find("Read more on Last.fm");
                if (link_pos != std::string::npos) {
                    bio = bio.substr(0, link_pos);
                }
                
                result.biography_full = decode_html_entities(bio);
            }
        }
        
        // Extract published date
        size_t published_pos = json.find("\"published\":\"");
        if (published_pos != std::string::npos) {
            published_pos += 13;
            size_t published_end = json.find("\"", published_pos);
            if (published_end != std::string::npos) {
                result.published_date = json.substr(published_pos, published_end - published_pos);
            }
        }
        
        // Extract stats
        size_t stats_pos = json.find("\"stats\":{");
        if (stats_pos != std::string::npos) {
            // Listeners
            size_t listeners_pos = json.find("\"listeners\":\"", stats_pos);
            if (listeners_pos != std::string::npos) {
                listeners_pos += 13;
                size_t listeners_end = json.find("\"", listeners_pos);
                if (listeners_end != std::string::npos) {
                    result.listeners = json.substr(listeners_pos, listeners_end - listeners_pos);
                }
            }
            
            // Playcount
            size_t playcount_pos = json.find("\"playcount\":\"", stats_pos);
            if (playcount_pos != std::string::npos) {
                playcount_pos += 13;
                size_t playcount_end = json.find("\"", playcount_pos);
                if (playcount_end != std::string::npos) {
                    result.playcount = json.substr(playcount_pos, playcount_end - playcount_pos);
                }
            }
        }
        
        // Extract tags with counts
        size_t tags_pos = json.find("\"tags\":{\"tag\":[");
        if (tags_pos != std::string::npos) {
            tags_pos += 15;
            size_t tags_end = json.find("]", tags_pos);
            if (tags_end != std::string::npos) {
                std::string tags_section = json.substr(tags_pos, tags_end - tags_pos);
                size_t tag_pos = 0;
                while ((tag_pos = tags_section.find("{\"", tag_pos)) != std::string::npos) {
                    // Get tag name
                    size_t name_pos = tags_section.find("\"name\":\"", tag_pos);
                    size_t count_pos = tags_section.find("\"count\":", tag_pos);
                    
                    if (name_pos != std::string::npos && count_pos != std::string::npos) {
                        name_pos += 8;
                        size_t name_end = tags_section.find("\"", name_pos);
                        
                        count_pos += 8;
                        size_t count_end = tags_section.find(",", count_pos);
                        if (count_end == std::string::npos) {
                            count_end = tags_section.find("}", count_pos);
                        }
                        
                        if (name_end != std::string::npos && count_end != std::string::npos) {
                            std::string tag_name = tags_section.substr(name_pos, name_end - name_pos);
                            std::string tag_count = tags_section.substr(count_pos, count_end - count_pos);
                            result.tags.push_back({tag_name, tag_count});
                        }
                    }
                    tag_pos = tags_section.find("}", tag_pos) + 1;
                }
            }
        }
        
        // Extract similar artists with match percentage
        size_t similar_pos = json.find("\"similar\":{\"artist\":[");
        if (similar_pos != std::string::npos) {
            similar_pos += 21;
            size_t similar_end = json.find("]", similar_pos);
            if (similar_end != std::string::npos) {
                std::string similar_section = json.substr(similar_pos, similar_end - similar_pos);
                size_t artist_pos = 0;
                while ((artist_pos = similar_section.find("{\"", artist_pos)) != std::string::npos) {
                    // Get artist name and match
                    size_t name_pos = similar_section.find("\"name\":\"", artist_pos);
                    size_t match_pos = similar_section.find("\"match\":\"", artist_pos);
                    
                    if (name_pos != std::string::npos) {
                        name_pos += 8;
                        size_t name_end = similar_section.find("\"", name_pos);
                        
                        std::string artist_name = similar_section.substr(name_pos, name_end - name_pos);
                        std::string match = "100";
                        
                        if (match_pos != std::string::npos && match_pos < similar_section.find("}", artist_pos)) {
                            match_pos += 9;
                            size_t match_end = similar_section.find("\"", match_pos);
                            if (match_end != std::string::npos) {
                                // Convert match to percentage
                                float match_val = std::stof(similar_section.substr(match_pos, match_end - match_pos));
                                match = std::to_string((int)(match_val * 100));
                            }
                        }
                        
                        result.similar_artists.push_back({artist_name, match + "%"});
                    }
                    artist_pos = similar_section.find("}", artist_pos) + 1;
                }
            }
        }
        
        // Extract on tour status
        size_t tour_pos = json.find("\"ontour\":\"");
        if (tour_pos != std::string::npos) {
            tour_pos += 10;
            size_t tour_end = json.find("\"", tour_pos);
            if (tour_end != std::string::npos) {
                result.on_tour = json.substr(tour_pos, tour_end - tour_pos);
            }
        }
        
        return result;
    }
    
    artist_info parse_audiodb_response(const std::string& json) {
        artist_info result;
        
        // Log response for debugging
        console::formatter() << "Artist Bio: API Response (first 500 chars): " << json.substr(0, 500).c_str();
        
        // Check if artist exists
        if (json.find("\"artists\":null") != std::string::npos || json.find("\"artists\":[]") != std::string::npos) {
            console::print("Artist Bio: No artist found in response");
            return result;
        }
        
        // TheAudioDB returns array of artists, get first one
        size_t artist_start = json.find("\"artists\":[{");
        if (artist_start == std::string::npos) {
            console::print("Artist Bio: Could not find artists array in response");
            return result;
        }
        
        result.found = true;
        
        // Extract artist name
        size_t name_pos = json.find("\"strArtist\":\"", artist_start);
        if (name_pos != std::string::npos) {
            name_pos += 13;
            size_t name_end = json.find("\"", name_pos);
            if (name_end != std::string::npos) {
                result.name = json.substr(name_pos, name_end - name_pos);
            }
        }
        
        // Extract biography
        size_t bio_pos = json.find("\"strBiographyEN\":\"", artist_start);
        if (bio_pos != std::string::npos) {
            bio_pos += 18;
            size_t bio_end = json.find("\"", bio_pos);
            while (bio_end != std::string::npos && bio_end > 0 && json[bio_end - 1] == '\\') {
                bio_end = json.find("\"", bio_end + 1);
            }
            if (bio_end != std::string::npos) {
                std::string bio = json.substr(bio_pos, bio_end - bio_pos);
                // Replace \n with actual newlines
                size_t pos = 0;
                while ((pos = bio.find("\\n", pos)) != std::string::npos) {
                    bio.replace(pos, 2, "\n");
                    pos += 1;
                }
                result.biography_full = bio;
                result.biography_summary = bio.substr(0, min(bio.length(), (size_t)500)) + "...";
            }
        }
        
        // Extract artist thumb/image
        size_t thumb_pos = json.find("\"strArtistThumb\":\"", artist_start);
        if (thumb_pos != std::string::npos) {
            thumb_pos += 18;
            size_t thumb_end = json.find("\"", thumb_pos);
            if (thumb_end != std::string::npos) {
                std::string thumb_url = json.substr(thumb_pos, thumb_end - thumb_pos);
                if (!thumb_url.empty() && thumb_url != "null") {
                    console::formatter() << "Artist Bio: Found image URL: " << thumb_url.c_str();
                    result.image_large = thumb_url;
                    result.image_extralarge = thumb_url;
                    result.image_mega = thumb_url;
                } else {
                    console::print("Artist Bio: Image URL is empty or null");
                }
            } else {
                console::print("Artist Bio: Could not find end of strArtistThumb");
            }
        } else {
            console::print("Artist Bio: No strArtistThumb field found in response");
        }
        
        // Extract genre
        size_t genre_pos = json.find("\"strGenre\":\"", artist_start);
        if (genre_pos != std::string::npos) {
            genre_pos += 12;
            size_t genre_end = json.find("\"", genre_pos);
            if (genre_end != std::string::npos) {
                std::string genre = json.substr(genre_pos, genre_end - genre_pos);
                if (!genre.empty() && genre != "null") {
                    result.tags.push_back(std::make_pair(genre, "100"));
                }
            }
        }
        
        // Extract style
        size_t style_pos = json.find("\"strStyle\":\"", artist_start);
        if (style_pos != std::string::npos) {
            style_pos += 12;
            size_t style_end = json.find("\"", style_pos);
            if (style_end != std::string::npos) {
                std::string style = json.substr(style_pos, style_end - style_pos);
                if (!style.empty() && style != "null") {
                    result.tags.push_back(std::make_pair(style, "90"));
                }
            }
        }
        
        // Extract country
        size_t country_pos = json.find("\"strCountry\":\"", artist_start);
        if (country_pos != std::string::npos) {
            country_pos += 14;
            size_t country_end = json.find("\"", country_pos);
            if (country_end != std::string::npos) {
                std::string country = json.substr(country_pos, country_end - country_pos);
                if (!country.empty() && country != "null") {
                    result.links["Country"] = country;
                }
            }
        }
        
        // Extract formation year
        size_t year_pos = json.find("\"intFormedYear\":\"", artist_start);
        if (year_pos != std::string::npos) {
            year_pos += 17;
            size_t year_end = json.find("\"", year_pos);
            if (year_end != std::string::npos) {
                std::string year = json.substr(year_pos, year_end - year_pos);
                if (!year.empty() && year != "null") {
                    result.links["Formed"] = year;
                }
            }
        }
        
        // Extract website
        size_t web_pos = json.find("\"strWebsite\":\"", artist_start);
        if (web_pos != std::string::npos) {
            web_pos += 14;
            size_t web_end = json.find("\"", web_pos);
            if (web_end != std::string::npos) {
                std::string website = json.substr(web_pos, web_end - web_pos);
                if (!website.empty() && website != "null") {
                    result.url = website;
                }
            }
        }
        
        return result;
    }
    
    void parse_top_tracks(const std::string& json, artist_info& info) {
        size_t tracks_pos = json.find("\"track\":[");
        if (tracks_pos != std::string::npos) {
            tracks_pos += 9;
            size_t tracks_end = json.find("]", tracks_pos);
            if (tracks_end != std::string::npos) {
                std::string tracks_section = json.substr(tracks_pos, tracks_end - tracks_pos);
                size_t track_pos = 0;
                while ((track_pos = tracks_section.find("{\"", track_pos)) != std::string::npos) {
                    track_info track;
                    
                    // Get track name
                    size_t name_pos = tracks_section.find("\"name\":\"", track_pos);
                    if (name_pos != std::string::npos) {
                        name_pos += 8;
                        size_t name_end = tracks_section.find("\"", name_pos);
                        if (name_end != std::string::npos) {
                            track.name = tracks_section.substr(name_pos, name_end - name_pos);
                        }
                    }
                    
                    // Get playcount
                    size_t play_pos = tracks_section.find("\"playcount\":\"", track_pos);
                    if (play_pos != std::string::npos) {
                        play_pos += 13;
                        size_t play_end = tracks_section.find("\"", play_pos);
                        if (play_end != std::string::npos) {
                            track.playcount = tracks_section.substr(play_pos, play_end - play_pos);
                        }
                    }
                    
                    // Get listeners
                    size_t list_pos = tracks_section.find("\"listeners\":\"", track_pos);
                    if (list_pos != std::string::npos) {
                        list_pos += 13;
                        size_t list_end = tracks_section.find("\"", list_pos);
                        if (list_end != std::string::npos) {
                            track.listeners = tracks_section.substr(list_pos, list_end - list_pos);
                        }
                    }
                    
                    if (!track.name.empty()) {
                        info.top_tracks.push_back(track);
                    }
                    
                    track_pos = tracks_section.find("}", track_pos) + 1;
                }
            }
        }
    }
    
    void parse_top_albums(const std::string& json, artist_info& info) {
        size_t albums_pos = json.find("\"album\":[");
        if (albums_pos != std::string::npos) {
            albums_pos += 9;
            size_t albums_end = json.find("]", albums_pos);
            if (albums_end != std::string::npos) {
                std::string albums_section = json.substr(albums_pos, albums_end - albums_pos);
                size_t album_pos = 0;
                while ((album_pos = albums_section.find("{\"", album_pos)) != std::string::npos) {
                    album_info album;
                    
                    // Get album name
                    size_t name_pos = albums_section.find("\"name\":\"", album_pos);
                    if (name_pos != std::string::npos) {
                        name_pos += 8;
                        size_t name_end = albums_section.find("\"", name_pos);
                        if (name_end != std::string::npos) {
                            album.name = albums_section.substr(name_pos, name_end - name_pos);
                        }
                    }
                    
                    // Get playcount
                    size_t play_pos = albums_section.find("\"playcount\":", album_pos);
                    if (play_pos != std::string::npos) {
                        play_pos += 12;
                        size_t play_end = albums_section.find(",", play_pos);
                        if (play_end == std::string::npos) {
                            play_end = albums_section.find("}", play_pos);
                        }
                        if (play_end != std::string::npos) {
                            album.playcount = albums_section.substr(play_pos, play_end - play_pos);
                        }
                    }
                    
                    if (!album.name.empty()) {
                        info.top_albums.push_back(album);
                    }
                    
                    album_pos = albums_section.find("}", album_pos) + 1;
                }
            }
        }
    }
    
public:
    bool download_image(const std::string& url, HBITMAP& out_bitmap, int max_width = 300, int max_height = 300) {
        if (url.empty()) return false;
        
        console::printf("Artist Bio: Attempting download using WinINet from: %s", url.c_str());
        
        // Convert URL to wide string
        std::wstring wide_url = string_to_wstring(url);
        
        // Use WinINet for better HTTPS handling
        HINTERNET hInternet = InternetOpenW(
            L"Artist Bio/1.0",
            INTERNET_OPEN_TYPE_PRECONFIG,
            NULL,
            NULL,
            0
        );
        
        if (!hInternet) {
            console::printf("Artist Bio: Failed to open Internet handle");
            return false;
        }
        
        // Open URL with flags to ignore SSL errors
        DWORD dwFlags = INTERNET_FLAG_RELOAD | 
                       INTERNET_FLAG_NO_CACHE_WRITE |
                       INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                       INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        
        if (url.find("https://") == 0) {
            dwFlags |= INTERNET_FLAG_SECURE;
        }
        
        HINTERNET hUrl = InternetOpenUrlW(
            hInternet,
            wide_url.c_str(),
            NULL,
            0,
            dwFlags,
            0
        );
        
        if (!hUrl) {
            DWORD error = GetLastError();
            console::printf("Artist Bio: Failed to open URL, error: %d", error);
            InternetCloseHandle(hInternet);
            return false;
        }
        
        // Read image data
        std::vector<BYTE> image_data;
        BYTE buffer[4096];
        DWORD dwBytesRead = 0;
        
        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &dwBytesRead) && dwBytesRead > 0) {
            image_data.insert(image_data.end(), buffer, buffer + dwBytesRead);
        }
        
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        
        if (image_data.empty()) {
            console::printf("Artist Bio: No data downloaded");
            return false;
        }
        
        console::printf("Artist Bio: Downloaded %d bytes", image_data.size());
        
        // Initialize GDI+ if not already done
        static bool gdiplus_initialized = false;
        static ULONG_PTR gdiplusToken = 0;
        if (!gdiplus_initialized) {
            Gdiplus::GdiplusStartupInput gdiplusStartupInput;
            Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
            gdiplus_initialized = true;
        }
        
        // Create stream from memory
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, image_data.size());
        if (!hMem) {
            console::printf("Artist Bio: Failed to allocate memory");
            return false;
        }
        
        void* pMem = GlobalLock(hMem);
        if (!pMem) {
            GlobalFree(hMem);
            return false;
        }
        
        memcpy(pMem, image_data.data(), image_data.size());
        GlobalUnlock(hMem);
        
        IStream* pStream = nullptr;
        HRESULT hr = CreateStreamOnHGlobal(hMem, TRUE, &pStream);
        if (FAILED(hr)) {
            GlobalFree(hMem);
            console::printf("Artist Bio: Failed to create stream");
            return false;
        }
        
        // Use GDI+ to load the image
        Gdiplus::Bitmap* pBitmap = Gdiplus::Bitmap::FromStream(pStream);
        pStream->Release();
        
        if (!pBitmap || pBitmap->GetLastStatus() != Gdiplus::Ok) {
            console::printf("Artist Bio: GDI+ failed to load image");
            if (pBitmap) delete pBitmap;
            return false;
        }
        
        console::printf("Artist Bio: GDI+ loaded image successfully");
        
        // Get dimensions
        int width = pBitmap->GetWidth();
        int height = pBitmap->GetHeight();
        
        // Scale if needed
        int targetWidth = width;
        int targetHeight = height;
        if (targetWidth > max_width || targetHeight > max_height) {
            float scale = min((float)max_width / targetWidth, (float)max_height / targetHeight);
            targetWidth = (int)(targetWidth * scale);
            targetHeight = (int)(targetHeight * scale);
        }
        
        // Scale if needed
        Gdiplus::Bitmap* pScaledBitmap = pBitmap;
        if (targetWidth != width || targetHeight != height) {
            pScaledBitmap = new Gdiplus::Bitmap(targetWidth, targetHeight);
            Gdiplus::Graphics graphics(pScaledBitmap);
            graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQuality);
            graphics.DrawImage(pBitmap, 0, 0, targetWidth, targetHeight);
        }
        
        // Convert to HBITMAP using GDI+ GetHBITMAP
        Gdiplus::Color bgColor(255, 255, 255, 255); // White background
        Gdiplus::Status status = pScaledBitmap->GetHBITMAP(bgColor, &out_bitmap);
        
        if (status != Gdiplus::Ok) {
            console::printf("Artist Bio: Failed to convert to HBITMAP, status: %d", status);
            if (pScaledBitmap != pBitmap) delete pScaledBitmap;
            delete pBitmap;
            return false;
        }
        
        if (pScaledBitmap != pBitmap) delete pScaledBitmap;
        delete pBitmap;
        console::printf("Artist Bio: Image converted to HBITMAP successfully");
        
        
        return out_bitmap != NULL;
    }
};

// End of download_image function


// Custom scrollbar info
struct ScrollbarInfo {
    bool visible;
    int thumb_pos;
    int thumb_height;
    bool thumb_hover;
    bool thumb_pressed;
    int mouse_offset;
};

// Artist bio display window with sections
// Layout modes
enum class LayoutMode {
    HORIZONTAL = 0,  // Image left, text right
    VERTICAL = 1      // Image top, text bottom
};

class artist_bio_window : public ui_element_instance, private play_callback_impl_base {
private:
    HWND m_hwnd;
    service_ptr_t<ui_element_instance_callback> m_callback;
    std::string m_current_artist;
    music_api_client::artist_info m_artist_info;
    bool m_loading;
    bool m_dark_mode;
    int m_scroll_pos;
    int m_content_height;
    LayoutMode m_layout_mode;  // Add layout mode
    HMENU m_context_menu;       // Add context menu
    
    music_api_client m_api_client;
    
    // Image data
    HBITMAP m_artist_image;
    int m_image_width;
    int m_image_height;
    
    // Resizable divider
    int m_divider_pos;  // Position of divider (pixels from left in horizontal mode)
    int m_vertical_divider_pos;  // Position of divider (pixels from top) in vertical mode
    bool m_dragging_divider;
    static const int DIVIDER_WIDTH = 6;
    static const int MIN_PANEL_WIDTH = 100;
    static const int MIN_IMAGE_HEIGHT = 100;
    
    // Custom scrollbar
    ScrollbarInfo m_scrollbar;
    static const int SCROLLBAR_WIDTH = 12;
    static const int IMAGE_WIDTH = 300;
    static const int IMAGE_HEIGHT = 300;
    
    // Theme colors (from foobar2000)
    COLORREF m_bg_color;
    COLORREF m_text_color;
    COLORREF m_heading_color;
    COLORREF m_subheading_color;
    COLORREF m_section_bg;
    COLORREF m_scrollbar_track;
    COLORREF m_scrollbar_thumb;
    COLORREF m_scrollbar_thumb_hover;
    HFONT m_font_normal;
    HFONT m_font_heading;
    HFONT m_font_section;
    HFONT m_font_small;
    HBRUSH m_bg_brush;
    HBRUSH m_section_brush;
    
    static const int PADDING = 15;
    static const int SECTION_PADDING = 10;
    static const int LINE_HEIGHT = 22;
    static const int HEADING_HEIGHT = 32;
    static const int SECTION_HEIGHT = 26;
    
public:
    artist_bio_window() : m_hwnd(NULL), m_loading(false),
                          m_scroll_pos(0), m_content_height(0),
                          m_font_normal(NULL), m_font_heading(NULL), 
                          m_font_section(NULL), m_font_small(NULL),
                          m_bg_brush(NULL), m_section_brush(NULL), m_dark_mode(false),
                          m_artist_image(NULL), m_image_width(0), m_image_height(0),
                          m_layout_mode(LayoutMode::HORIZONTAL), m_context_menu(NULL),
                          m_divider_pos(320), m_vertical_divider_pos(300), m_dragging_divider(false) {
        m_scrollbar = {false, 0, 0, false, false, 0};
        
        // Initialize COM for WIC
        HRESULT hr = CoInitialize(NULL);
        if (FAILED(hr)) {
            console::print("Artist Bio: Failed to initialize COM");
        }
        
        try {
            static_api_ptr_t<play_callback_manager>()->register_callback(
                this,
                play_callback::flag_on_playback_new_track | play_callback::flag_on_playback_stop,
                false
            );
        } catch (...) {
            console::print("Artist Bio: Failed to register play callback");
        }
    }
    
    void set_callback(ui_element_instance_callback::ptr callback) {
        m_callback = callback;
    }
    
    ~artist_bio_window() {
        try {
            static_api_ptr_t<play_callback_manager>()->unregister_callback(this);
        } catch (...) {
            // Ignore errors during cleanup
        }
        
        if (m_font_normal) { DeleteObject(m_font_normal); m_font_normal = NULL; }
        if (m_font_heading) { DeleteObject(m_font_heading); m_font_heading = NULL; }
        if (m_font_section) { DeleteObject(m_font_section); m_font_section = NULL; }
        if (m_font_small) { DeleteObject(m_font_small); m_font_small = NULL; }
        if (m_bg_brush) { DeleteObject(m_bg_brush); m_bg_brush = NULL; }
        if (m_section_brush) { DeleteObject(m_section_brush); m_section_brush = NULL; }
        if (m_artist_image) { DeleteObject(m_artist_image); m_artist_image = NULL; }
        if (m_context_menu) { DestroyMenu(m_context_menu); m_context_menu = NULL; }
        
        CoUninitialize();
    }
    
    void initialize_window(HWND parent) {
        // Create main window
        m_hwnd = CreateWindowEx(
            0,
            L"Static",
            L"Artist Biography",
            WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
            0, 0, 100, 100,
            parent,
            NULL,
            core_api::get_my_instance(),
            NULL
        );
        
        if (m_hwnd) {
            SetWindowLongPtr(m_hwnd, GWLP_USERDATA, (LONG_PTR)this);
            SetWindowLongPtr(m_hwnd, GWLP_WNDPROC, (LONG_PTR)WindowProc);
            
            // Update theme and create fonts
            update_theme();
            create_fonts();
            
            // Load initial artist if playing
            update_current_artist();
        }
    }
    
    HWND get_wnd() override {
        return m_hwnd;
    }
    
    void set_configuration(ui_element_config::ptr config) override {
    }
    
    ui_element_config::ptr get_configuration() override {
        return ui_element_config::g_create_empty(g_get_guid());
    }
    
    GUID get_guid() override {
        return g_get_guid();
    }
    
    GUID get_subclass() override {
        return g_get_subclass();
    }
    
    static GUID g_get_guid() {
        // {C0D1E2F3-A4B5-6789-0123-456789012345}
        static const GUID guid = 
        { 0xc0d1e2f3, 0xa4b5, 0x6789, { 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45 } };
        return guid;
    }
    
    static void g_get_name(pfc::string_base& out) {
        out = "Artist Biography";
    }
    
    static ui_element_config::ptr g_get_default_configuration() {
        return ui_element_config::g_create_empty(g_get_guid());
    }
    
    static const char* g_get_description() {
        return "Complete artist information from Last.fm with sections";
    }
    
    static GUID g_get_subclass() {
        return ui_element_subclass_utility;
    }
    
    void on_playback_new_track(metadb_handle_ptr p_track) override {
        update_current_artist();
    }
    
    void on_playback_stop(play_control::t_stop_reason p_reason) override {
        if (p_reason != play_control::stop_reason_starting_another) {
            clear_biography();
        }
    }
    
private:
    void create_fonts() {
        // Create normal font (12pt Segoe UI)
        m_font_normal = CreateFont(
            -16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
            L"Segoe UI"
        );
        
        // Create heading font (16pt bold)
        m_font_heading = CreateFont(
            -21, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
            L"Segoe UI"
        );
        
        // Create section font (13pt semibold)
        m_font_section = CreateFont(
            -17, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
            L"Segoe UI"
        );
        
        // Create small font (10pt)
        m_font_small = CreateFont(
            -13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
            L"Segoe UI"
        );
    }
    
    void update_theme() {
        // Get UI colors from foobar2000
        COLORREF bg = GetSysColor(COLOR_WINDOW);
        COLORREF fg = GetSysColor(COLOR_WINDOWTEXT);
        
        if (m_callback.is_valid()) {
            bg = m_callback->query_std_color(ui_color_background);
            fg = m_callback->query_std_color(ui_color_text);
        }
        
        // Detect dark mode based on background brightness
        int brightness = (GetRValue(bg) + GetGValue(bg) + GetBValue(bg)) / 3;
        m_dark_mode = (brightness < 128);
        
        // Set colors based on actual foobar2000 colors
        m_bg_color = bg;
        m_text_color = fg;
        
        // Create color variations
        if (m_dark_mode) {
            m_heading_color = RGB(
                min(255, GetRValue(fg) + 40),
                min(255, GetGValue(fg) + 40),
                min(255, GetBValue(fg) + 40)
            );
            m_subheading_color = RGB(
                max(0, GetRValue(fg) - 40),
                max(0, GetGValue(fg) - 40),
                max(0, GetBValue(fg) - 40)
            );
            m_section_bg = RGB(
                min(255, GetRValue(bg) + 10),
                min(255, GetGValue(bg) + 10),
                min(255, GetBValue(bg) + 10)
            );
            
            // Custom scrollbar colors matching theme
            m_scrollbar_track = RGB(
                GetRValue(bg) + 15,
                GetGValue(bg) + 15,
                GetBValue(bg) + 15
            );
            m_scrollbar_thumb = RGB(
                GetRValue(bg) + 40,
                GetGValue(bg) + 40,
                GetBValue(bg) + 40
            );
            m_scrollbar_thumb_hover = RGB(
                GetRValue(bg) + 60,
                GetGValue(bg) + 60,
                GetBValue(bg) + 60
            );
        } else {
            m_heading_color = RGB(
                max(0, GetRValue(fg) - 40),
                max(0, GetGValue(fg) - 40),
                max(0, GetBValue(fg) - 40)
            );
            m_subheading_color = RGB(
                min(255, GetRValue(fg) + 40),
                min(255, GetGValue(fg) + 40),
                min(255, GetBValue(fg) + 40)
            );
            m_section_bg = RGB(
                max(0, GetRValue(bg) - 10),
                max(0, GetGValue(bg) - 10),
                max(0, GetBValue(bg) - 10)
            );
            
            // Light theme scrollbar
            m_scrollbar_track = RGB(
                max(0, GetRValue(bg) - 15),
                max(0, GetGValue(bg) - 15),
                max(0, GetBValue(bg) - 15)
            );
            m_scrollbar_thumb = RGB(
                max(0, GetRValue(bg) - 40),
                max(0, GetGValue(bg) - 40),
                max(0, GetBValue(bg) - 40)
            );
            m_scrollbar_thumb_hover = RGB(
                max(0, GetRValue(bg) - 60),
                max(0, GetGValue(bg) - 60),
                max(0, GetBValue(bg) - 60)
            );
        }
        
        // Update brushes
        if (m_bg_brush) DeleteObject(m_bg_brush);
        m_bg_brush = CreateSolidBrush(m_bg_color);
        
        if (m_section_brush) DeleteObject(m_section_brush);
        m_section_brush = CreateSolidBrush(m_section_bg);
    }
    
    void update_current_artist() {
        static_api_ptr_t<playback_control> pc;
        if (!pc->is_playing()) {
            clear_biography();
            return;
        }
        
        metadb_handle_ptr track;
        if (!pc->get_now_playing(track)) return;
        
        file_info_impl info;
        if (!track->get_info(info)) return;
        
        const char* artist = info.meta_get("ARTIST", 0);
        if (!artist) return;
        
        std::string new_artist(artist);
        if (new_artist != m_current_artist) {
            m_current_artist = new_artist;
            fetch_artist_biography();
        }
    }
    
    void fetch_artist_biography() {
        if (m_current_artist.empty()) return;
        
        m_loading = true;
        m_artist_info = music_api_client::artist_info();
        m_artist_info.name = m_current_artist;
        m_artist_info.biography_summary = "Loading information for " + m_current_artist + "...";
        
        // Clear old image
        if (m_artist_image) {
            DeleteObject(m_artist_image);
            m_artist_image = NULL;
        }
        
        calculate_content_height();
        update_scrollbar();
        InvalidateRect(m_hwnd, NULL, TRUE);
        
        // Fetch complete info from Last.fm
        m_artist_info = m_api_client.get_artist_info_complete(m_current_artist);
        
        if (!m_artist_info.found) {
            m_artist_info.name = m_current_artist;
            m_artist_info.biography_summary = "No information found for this artist.";
        }
        
        // Download and load image (skip placeholder images)
        std::string image_url;
        if (!m_artist_info.image_extralarge.empty()) {
            image_url = m_artist_info.image_extralarge;
        } else if (!m_artist_info.image_large.empty()) {
            image_url = m_artist_info.image_large;
        }
        
        // Check if it's the placeholder image
        if (!image_url.empty()) {
            if (image_url.find("2a96cbd8b46e442fc41c2b86b821562f") != std::string::npos) {
                console::printf("Artist Bio: Skipping placeholder image for %s", m_current_artist.c_str());
                console::printf("Artist Bio: API returned default star image, artist may not have a photo on Last.fm");
            } else {
                console::printf("Artist Bio: Downloading image from: %s", image_url.c_str());
                if (m_api_client.download_image(image_url, m_artist_image, IMAGE_WIDTH, IMAGE_HEIGHT)) {
                    console::printf("Artist Bio: Image downloaded successfully");
                } else {
                    console::printf("Artist Bio: Failed to download image");
                }
            }
        } else {
            console::printf("Artist Bio: No image URL found in API response for %s", m_current_artist.c_str());
        }
        
        if (m_artist_image) {
            BITMAP bm;
            GetObject(m_artist_image, sizeof(bm), &bm);
            m_image_width = bm.bmWidth;
            m_image_height = bm.bmHeight;
        }
        
        m_loading = false;
        m_scroll_pos = 0; // Reset scroll on new artist
        calculate_content_height();
        update_scrollbar();
        InvalidateRect(m_hwnd, NULL, TRUE);
    }
    
    void calculate_content_height() {
        // This is a rough estimate - actual height calculated during painting
        m_content_height = PADDING * 2;
        
        // Image area height
        m_content_height = max(m_content_height, IMAGE_HEIGHT + PADDING * 2);
        
        // Add heights for each section
        if (!m_artist_info.biography_summary.empty()) m_content_height += 200;
        if (!m_artist_info.biography_full.empty()) m_content_height += 400;
        if (!m_artist_info.tags.empty()) m_content_height += 100;
        if (!m_artist_info.similar_artists.empty()) m_content_height += 200;
        if (!m_artist_info.top_tracks.empty()) m_content_height += 200;
        if (!m_artist_info.top_albums.empty()) m_content_height += 200;
        
        m_content_height += PADDING * 10; // Extra padding between sections
    }
    
    void update_scrollbar() {
        RECT rc;
        GetClientRect(m_hwnd, &rc);
        
        // Check if scrollbar is needed
        m_scrollbar.visible = m_content_height > rc.bottom;
        
        if (m_scrollbar.visible) {
            // Calculate thumb size and position
            float view_ratio = (float)rc.bottom / m_content_height;
            m_scrollbar.thumb_height = max(30, (int)(rc.bottom * view_ratio));
            
            float scroll_ratio = (float)m_scroll_pos / (m_content_height - rc.bottom);
            int max_thumb_pos = rc.bottom - m_scrollbar.thumb_height;
            m_scrollbar.thumb_pos = (int)(max_thumb_pos * scroll_ratio);
        } else {
            m_scroll_pos = 0;
        }
    }
    
    void clear_biography() {
        m_current_artist.clear();
        m_artist_info = music_api_client::artist_info();
        m_artist_info.biography_summary = "No track playing";
        
        if (m_artist_image) {
            DeleteObject(m_artist_image);
            m_artist_image = NULL;
        }
        
        m_scroll_pos = 0;
        calculate_content_height();
        update_scrollbar();
        InvalidateRect(m_hwnd, NULL, TRUE);
    }
    
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        artist_bio_window* self = reinterpret_cast<artist_bio_window*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        if (!self || !IsWindow(hwnd)) return DefWindowProc(hwnd, msg, wParam, lParam);
        
        switch (msg) {
            case WM_PAINT: return self->on_paint();
            case WM_SIZE: return self->on_size();
            case WM_MOUSEWHEEL: return self->on_mousewheel(GET_WHEEL_DELTA_WPARAM(wParam));
            case WM_LBUTTONDOWN: return self->on_lbuttondown(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            case WM_LBUTTONUP: return self->on_lbuttonup();
            case WM_LBUTTONDBLCLK: return self->on_lbuttondblclk(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            case WM_RBUTTONUP: return self->on_rbuttonup(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            case WM_COMMAND: return self->on_command(LOWORD(wParam));
            case WM_MOUSEMOVE: return self->on_mousemove(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            case WM_ERASEBKGND: return 1;
        }
        
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    
    LRESULT on_paint() {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(m_hwnd, &ps);
        
        RECT rc;
        GetClientRect(m_hwnd, &rc);
        
        // Create memory DC for double buffering
        HDC memdc = CreateCompatibleDC(hdc);
        HBITMAP membmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
        HBITMAP oldbmp = (HBITMAP)SelectObject(memdc, membmp);
        
        // Fill background
        FillRect(memdc, &rc, m_bg_brush);
        
        // Set text mode
        SetBkMode(memdc, TRANSPARENT);
        
        // Draw based on layout mode
        if (m_layout_mode == LayoutMode::VERTICAL) {
            // Vertical layout: image at top, text below
            draw_vertical_layout(memdc, rc);
        } else {
            // Horizontal layout: image on left, text on right
            draw_horizontal_layout(memdc, rc);
        }
        
        // Draw custom scrollbar
        if (m_scrollbar.visible) {
            draw_scrollbar(memdc, rc);
        }
        
        // Copy to screen
        BitBlt(hdc, 0, 0, rc.right, rc.bottom, memdc, 0, 0, SRCCOPY);
        
        // Cleanup
        SelectObject(memdc, oldbmp);
        DeleteObject(membmp);
        DeleteDC(memdc);
        
        EndPaint(m_hwnd, &ps);
        return 0;
    }
    
    void draw_horizontal_layout(HDC memdc, const RECT& rc) {
        // Draw content in sections
        int y = PADDING - m_scroll_pos;
        
        // Left panel - Image and basic info (use divider position)
        draw_image_panel(memdc, rc, y);
        
        // Draw the divider
        RECT divider_rect = {m_divider_pos - DIVIDER_WIDTH/2, 0, m_divider_pos + DIVIDER_WIDTH/2, rc.bottom};
        HBRUSH divider_brush = CreateSolidBrush(m_dark_mode ? RGB(60, 60, 60) : RGB(200, 200, 200));
        FillRect(memdc, &divider_rect, divider_brush);
        DeleteObject(divider_brush);
        
        // Right panel - All sections (adjust for divider position)
        int text_left = m_divider_pos + DIVIDER_WIDTH/2 + PADDING;
        int section_width = rc.right - text_left - PADDING - SCROLLBAR_WIDTH;
        
        // Artist name and stats
        y = draw_header_section(memdc, text_left, y, section_width);
        
        // Biography section
        if (!m_artist_info.biography_full.empty() || !m_artist_info.biography_summary.empty()) {
            y = draw_section(memdc, "Biography", text_left, y, section_width,
                             m_artist_info.biography_full.empty() ? m_artist_info.biography_summary : m_artist_info.biography_full);
        }
        
        // Tags section
        if (!m_artist_info.tags.empty()) {
            y = draw_tags_section(memdc, text_left, y, section_width);
        }
        
        // Top Tracks section
        if (!m_artist_info.top_tracks.empty()) {
            y = draw_top_tracks_section(memdc, text_left, y, section_width);
        }
        
        // Top Albums section
        if (!m_artist_info.top_albums.empty()) {
            y = draw_top_albums_section(memdc, text_left, y, section_width);
        }
        
        // Similar Artists section
        if (!m_artist_info.similar_artists.empty()) {
            y = draw_similar_artists_section(memdc, text_left, y, section_width);
        }
        
        // Additional Info section
        if (!m_artist_info.url.empty() || !m_artist_info.mbid.empty()) {
            y = draw_additional_info_section(memdc, text_left, y, section_width);
        }
        
        // Update actual content height
        m_content_height = y + m_scroll_pos + PADDING;
    }
    
    void draw_vertical_layout(HDC memdc, const RECT& rc) {
        int y = PADDING - m_scroll_pos;
        
        // Use vertical divider position to determine image area height
        int image_area_height = m_vertical_divider_pos;
        
        // Draw image at top (centered) within the allocated area
        if (m_artist_image && image_area_height > MIN_IMAGE_HEIGHT) {
            HDC img_dc = CreateCompatibleDC(memdc);
            HBITMAP old_img = (HBITMAP)SelectObject(img_dc, m_artist_image);
            
            // Calculate available area
            int available_height = image_area_height - PADDING * 2;
            int available_width = rc.right - PADDING * 2;
            
            // Calculate scaling to fit within available area while maintaining aspect ratio
            float scale_h = (float)available_height / m_image_height;
            float scale_w = (float)available_width / m_image_width;
            float scale = min(scale_h, scale_w);
            
            // Calculate display dimensions
            int display_width = (int)(m_image_width * scale);
            int display_height = (int)(m_image_height * scale);
            
            // Center the image both horizontally and vertically
            int img_x = (rc.right - display_width) / 2;
            int img_y = PADDING + (available_height - display_height) / 2 - m_scroll_pos;
            
            // Draw with proper scaling
            SetStretchBltMode(memdc, HALFTONE);
            StretchBlt(memdc, img_x, img_y, display_width, display_height,
                      img_dc, 0, 0, m_image_width, m_image_height, SRCCOPY);
            
            SelectObject(img_dc, old_img);
            DeleteDC(img_dc);
        }
        
        // Draw horizontal divider at the divider position
        y = m_vertical_divider_pos - m_scroll_pos;
        RECT divider_rect = {0, y - DIVIDER_WIDTH/2, rc.right - SCROLLBAR_WIDTH, y + DIVIDER_WIDTH/2};
        HBRUSH divider_brush = CreateSolidBrush(m_dark_mode ? RGB(60, 60, 60) : RGB(200, 200, 200));
        FillRect(memdc, &divider_rect, divider_brush);
        DeleteObject(divider_brush);
        
        y += DIVIDER_WIDTH/2 + PADDING;
        
        // Draw all text sections below the divider
        int text_left = PADDING;
        int section_width = rc.right - PADDING * 2 - SCROLLBAR_WIDTH;
        
        // Artist name and stats
        y = draw_header_section(memdc, text_left, y, section_width);
        
        // Biography section
        if (!m_artist_info.biography_full.empty() || !m_artist_info.biography_summary.empty()) {
            y = draw_section(memdc, "Biography", text_left, y, section_width,
                             m_artist_info.biography_full.empty() ? m_artist_info.biography_summary : m_artist_info.biography_full);
        }
        
        // Tags section
        if (!m_artist_info.tags.empty()) {
            y = draw_tags_section(memdc, text_left, y, section_width);
        }
        
        // Top Tracks section
        if (!m_artist_info.top_tracks.empty()) {
            y = draw_top_tracks_section(memdc, text_left, y, section_width);
        }
        
        // Top Albums section
        if (!m_artist_info.top_albums.empty()) {
            y = draw_top_albums_section(memdc, text_left, y, section_width);
        }
        
        // Similar Artists section
        if (!m_artist_info.similar_artists.empty()) {
            y = draw_similar_artists_section(memdc, text_left, y, section_width);
        }
        
        // Additional Info section
        if (!m_artist_info.url.empty() || !m_artist_info.mbid.empty()) {
            y = draw_additional_info_section(memdc, text_left, y, section_width);
        }
        
        // Update actual content height
        m_content_height = y + m_scroll_pos + PADDING;
    }
    
    void draw_image_panel(HDC hdc, const RECT& client_rect, int y_offset) {
        // Use dynamic divider position for panel width
        int panel_width = m_divider_pos - DIVIDER_WIDTH/2;
        
        // Draw artist image
        if (m_artist_image) {
            HDC img_dc = CreateCompatibleDC(hdc);
            HBITMAP old_img = (HBITMAP)SelectObject(img_dc, m_artist_image);
            
            // Calculate available space for image
            int max_width = panel_width - PADDING * 2;
            int max_height = min(client_rect.bottom - y_offset - PADDING, 600); // Allow larger images
            
            int display_width = m_image_width;
            int display_height = m_image_height;
            
            // Calculate scale to fit the image optimally (scale UP or down)
            float scale_width = (float)max_width / m_image_width;
            float scale_height = (float)max_height / m_image_height;
            float scale = min(scale_width, scale_height);
            
            // Allow scaling up to fill space (not just scaling down)
            display_width = (int)(m_image_width * scale);
            display_height = (int)(m_image_height * scale);
            
            // Center image horizontally
            int x = (panel_width - display_width) / 2;
            int y = y_offset;
            
            // Use StretchBlt to scale image
            SetStretchBltMode(hdc, HALFTONE);
            StretchBlt(hdc, x, y, display_width, display_height, 
                      img_dc, 0, 0, m_image_width, m_image_height, SRCCOPY);
            
            SelectObject(img_dc, old_img);
            DeleteDC(img_dc);
        } else {
            // Draw placeholder - scale to available space
            int max_size = min(panel_width - PADDING * 2, 400);
            int placeholder_size = max_size;
            int x = (panel_width - placeholder_size) / 2;
            RECT img_rect = {x, y_offset, x + placeholder_size, y_offset + placeholder_size};
            FillRect(hdc, &img_rect, m_section_brush);
            
            // Draw "No Image" text
            SelectObject(hdc, m_font_normal);
            SetTextColor(hdc, m_subheading_color);
            DrawTextA(hdc, "No Image Available", -1, &img_rect, 
                     DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
    }
    
    int draw_header_section(HDC hdc, int x, int y, int width) {
        // Artist name - convert to UTF-16 for proper display
        SelectObject(hdc, m_font_heading);
        SetTextColor(hdc, m_heading_color);
        
        // Convert UTF-8 to UTF-16
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, m_artist_info.name.c_str(), -1, NULL, 0);
        if (size_needed > 0) {
            std::wstring wname(size_needed, 0);
            MultiByteToWideChar(CP_UTF8, 0, m_artist_info.name.c_str(), -1, &wname[0], size_needed);
            
            RECT heading_rect = {x, y, x + width, y + HEADING_HEIGHT};
            DrawTextW(hdc, wname.c_str(), -1, &heading_rect, DT_LEFT | DT_TOP | DT_SINGLELINE);
        }
        y += HEADING_HEIGHT;
        
        // Stats
        if (!m_artist_info.listeners.empty() || !m_artist_info.playcount.empty()) {
            SelectObject(hdc, m_font_small);
            SetTextColor(hdc, m_subheading_color);
            
            std::string stats_text;
            if (!m_artist_info.listeners.empty()) {
                // listeners already contains formatted text like "Last.fm: 60.1K listeners"
                stats_text = m_artist_info.listeners;
            }
            if (!m_artist_info.playcount.empty()) {
                if (!stats_text.empty()) stats_text += " • ";
                // playcount already contains formatted text like "835.9K plays"
                stats_text += m_artist_info.playcount;
            }
            if (m_artist_info.on_tour == "1") {
                if (!stats_text.empty()) stats_text += " • ";
                stats_text += "Currently on tour";
            }
            
            // Convert stats text to UTF-16
            int stats_size = MultiByteToWideChar(CP_UTF8, 0, stats_text.c_str(), -1, NULL, 0);
            if (stats_size > 0) {
                std::wstring wstats(stats_size, 0);
                MultiByteToWideChar(CP_UTF8, 0, stats_text.c_str(), -1, &wstats[0], stats_size);
                
                RECT stats_rect = {x, y, x + width, y + LINE_HEIGHT};
                DrawTextW(hdc, wstats.c_str(), -1, &stats_rect, DT_LEFT | DT_TOP | DT_SINGLELINE);
            }
            y += LINE_HEIGHT + PADDING;
        }
        
        return y;
    }
    
    int draw_section(HDC hdc, const char* title, int x, int y, int width, const std::string& content) {
        // Section header
        RECT section_rect = {x - SECTION_PADDING, y, x + width + SECTION_PADDING, y + SECTION_HEIGHT};
        FillRect(hdc, &section_rect, m_section_brush);
        
        SelectObject(hdc, m_font_section);
        SetTextColor(hdc, m_heading_color);
        section_rect.left = x;
        DrawTextA(hdc, title, -1, &section_rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += SECTION_HEIGHT + SECTION_PADDING;
        
        // Section content - Convert UTF-8 to UTF-16 for proper display
        SelectObject(hdc, m_font_normal);
        SetTextColor(hdc, m_text_color);
        
        // Convert UTF-8 string to wide string for Windows
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, content.c_str(), -1, NULL, 0);
        if (size_needed > 0) {
            std::wstring wcontent(size_needed, 0);
            MultiByteToWideChar(CP_UTF8, 0, content.c_str(), -1, &wcontent[0], size_needed);
            
            // First, calculate the required height with a large rect
            RECT calc_rect = {x, y, x + width, y + 10000};  // Use larger height for calculation
            DrawTextW(hdc, wcontent.c_str(), -1, &calc_rect, 
                     DT_LEFT | DT_TOP | DT_WORDBREAK | DT_CALCRECT | DT_NOPREFIX);
            
            // Now draw the text with the actual calculated rectangle
            RECT text_rect = {x, y, x + width, calc_rect.bottom};
            DrawTextW(hdc, wcontent.c_str(), -1, &text_rect, 
                     DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
            
            y = calc_rect.bottom + PADDING;
        }
        
        return y;
    }
    
    int draw_tags_section(HDC hdc, int x, int y, int width) {
        // Section header
        RECT section_rect = {x - SECTION_PADDING, y, x + width + SECTION_PADDING, y + SECTION_HEIGHT};
        FillRect(hdc, &section_rect, m_section_brush);
        
        SelectObject(hdc, m_font_section);
        SetTextColor(hdc, m_heading_color);
        section_rect.left = x;
        DrawTextA(hdc, "Tags & Genres", -1, &section_rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += SECTION_HEIGHT + SECTION_PADDING;
        
        // Tags
        SelectObject(hdc, m_font_normal);
        SetTextColor(hdc, m_text_color);
        
        std::string tags_text;
        for (size_t i = 0; i < m_artist_info.tags.size() && i < 10; ++i) {
            if (i > 0) tags_text += " • ";
            tags_text += m_artist_info.tags[i].first;
        }
        
        RECT text_rect = {x, y, x + width, y + 100};
        DrawTextA(hdc, tags_text.c_str(), -1, &text_rect, DT_LEFT | DT_TOP | DT_WORDBREAK);
        y += LINE_HEIGHT * 2 + PADDING;
        
        return y;
    }
    
    int draw_top_tracks_section(HDC hdc, int x, int y, int width) {
        // Section header
        RECT section_rect = {x - SECTION_PADDING, y, x + width + SECTION_PADDING, y + SECTION_HEIGHT};
        FillRect(hdc, &section_rect, m_section_brush);
        
        SelectObject(hdc, m_font_section);
        SetTextColor(hdc, m_heading_color);
        section_rect.left = x;
        DrawTextA(hdc, "Top Tracks", -1, &section_rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += SECTION_HEIGHT + SECTION_PADDING;
        
        // Tracks
        SelectObject(hdc, m_font_normal);
        
        for (size_t i = 0; i < m_artist_info.top_tracks.size() && i < 5; ++i) {
            SetTextColor(hdc, m_text_color);
            std::string track_text = std::to_string(i + 1) + ". " + m_artist_info.top_tracks[i].name;
            
            RECT track_rect = {x, y, x + width - 100, y + LINE_HEIGHT};
            DrawTextA(hdc, track_text.c_str(), -1, &track_rect, DT_LEFT | DT_TOP | DT_END_ELLIPSIS);
            
            // Play count
            SetTextColor(hdc, m_subheading_color);
            SelectObject(hdc, m_font_small);
            std::string plays = format_number(m_artist_info.top_tracks[i].playcount) + " plays";
            RECT plays_rect = {x + width - 100, y, x + width, y + LINE_HEIGHT};
            DrawTextA(hdc, plays.c_str(), -1, &plays_rect, DT_RIGHT | DT_TOP);
            SelectObject(hdc, m_font_normal);
            
            y += LINE_HEIGHT;
        }
        
        y += PADDING;
        return y;
    }
    
    int draw_top_albums_section(HDC hdc, int x, int y, int width) {
        // Section header
        RECT section_rect = {x - SECTION_PADDING, y, x + width + SECTION_PADDING, y + SECTION_HEIGHT};
        FillRect(hdc, &section_rect, m_section_brush);
        
        SelectObject(hdc, m_font_section);
        SetTextColor(hdc, m_heading_color);
        section_rect.left = x;
        DrawTextA(hdc, "Top Albums", -1, &section_rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += SECTION_HEIGHT + SECTION_PADDING;
        
        // Albums
        SelectObject(hdc, m_font_normal);
        
        for (size_t i = 0; i < m_artist_info.top_albums.size() && i < 5; ++i) {
            SetTextColor(hdc, m_text_color);
            std::string album_text = std::to_string(i + 1) + ". " + m_artist_info.top_albums[i].name;
            
            RECT album_rect = {x, y, x + width - 100, y + LINE_HEIGHT};
            DrawTextA(hdc, album_text.c_str(), -1, &album_rect, DT_LEFT | DT_TOP | DT_END_ELLIPSIS);
            
            // Play count
            if (!m_artist_info.top_albums[i].playcount.empty()) {
                SetTextColor(hdc, m_subheading_color);
                SelectObject(hdc, m_font_small);
                std::string plays = format_number(m_artist_info.top_albums[i].playcount) + " plays";
                RECT plays_rect = {x + width - 100, y, x + width, y + LINE_HEIGHT};
                DrawTextA(hdc, plays.c_str(), -1, &plays_rect, DT_RIGHT | DT_TOP);
                SelectObject(hdc, m_font_normal);
            }
            
            y += LINE_HEIGHT;
        }
        
        y += PADDING;
        return y;
    }
    
    int draw_similar_artists_section(HDC hdc, int x, int y, int width) {
        // Section header
        RECT section_rect = {x - SECTION_PADDING, y, x + width + SECTION_PADDING, y + SECTION_HEIGHT};
        FillRect(hdc, &section_rect, m_section_brush);
        
        SelectObject(hdc, m_font_section);
        SetTextColor(hdc, m_heading_color);
        section_rect.left = x;
        DrawTextA(hdc, "Similar Artists", -1, &section_rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += SECTION_HEIGHT + SECTION_PADDING;
        
        // Artists
        SelectObject(hdc, m_font_normal);
        
        for (size_t i = 0; i < m_artist_info.similar_artists.size() && i < 8; ++i) {
            SetTextColor(hdc, m_text_color);
            std::string artist_text = "• " + m_artist_info.similar_artists[i].first;
            
            RECT artist_rect = {x, y, x + width - 60, y + LINE_HEIGHT};
            DrawTextA(hdc, artist_text.c_str(), -1, &artist_rect, DT_LEFT | DT_TOP | DT_END_ELLIPSIS);
            
            // Match percentage
            SetTextColor(hdc, m_subheading_color);
            SelectObject(hdc, m_font_small);
            RECT match_rect = {x + width - 60, y, x + width, y + LINE_HEIGHT};
            DrawTextA(hdc, m_artist_info.similar_artists[i].second.c_str(), -1, &match_rect, DT_RIGHT | DT_TOP);
            SelectObject(hdc, m_font_normal);
            
            y += LINE_HEIGHT;
        }
        
        y += PADDING;
        return y;
    }
    
    int draw_additional_info_section(HDC hdc, int x, int y, int width) {
        // Section header
        RECT section_rect = {x - SECTION_PADDING, y, x + width + SECTION_PADDING, y + SECTION_HEIGHT};
        FillRect(hdc, &section_rect, m_section_brush);
        
        SelectObject(hdc, m_font_section);
        SetTextColor(hdc, m_heading_color);
        section_rect.left = x;
        DrawTextA(hdc, "Additional Information", -1, &section_rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += SECTION_HEIGHT + SECTION_PADDING;
        
        // Info
        SelectObject(hdc, m_font_small);
        SetTextColor(hdc, m_subheading_color);
        
        if (!m_artist_info.url.empty()) {
            std::string url_text = "Last.fm: " + m_artist_info.url;
            RECT url_rect = {x, y, x + width, y + LINE_HEIGHT};
            DrawTextA(hdc, url_text.c_str(), -1, &url_rect, DT_LEFT | DT_TOP | DT_END_ELLIPSIS);
            y += LINE_HEIGHT;
        }
        
        if (!m_artist_info.mbid.empty()) {
            std::string mbid_text = "MusicBrainz ID: " + m_artist_info.mbid;
            RECT mbid_rect = {x, y, x + width, y + LINE_HEIGHT};
            DrawTextA(hdc, mbid_text.c_str(), -1, &mbid_rect, DT_LEFT | DT_TOP | DT_END_ELLIPSIS);
            y += LINE_HEIGHT;
        }
        
        if (!m_artist_info.published_date.empty()) {
            std::string date_text = "Bio updated: " + m_artist_info.published_date;
            RECT date_rect = {x, y, x + width, y + LINE_HEIGHT};
            DrawTextA(hdc, date_text.c_str(), -1, &date_rect, DT_LEFT | DT_TOP | DT_END_ELLIPSIS);
            y += LINE_HEIGHT;
        }
        
        y += PADDING;
        return y;
    }
    
    void draw_scrollbar(HDC hdc, const RECT& client_rect) {
        // Scrollbar track
        RECT track_rect = {
            client_rect.right - SCROLLBAR_WIDTH,
            0,
            client_rect.right,
            client_rect.bottom
        };
        
        HBRUSH track_brush = CreateSolidBrush(m_scrollbar_track);
        FillRect(hdc, &track_rect, track_brush);
        DeleteObject(track_brush);
        
        // Scrollbar thumb
        RECT thumb_rect = {
            client_rect.right - SCROLLBAR_WIDTH + 2,
            m_scrollbar.thumb_pos,
            client_rect.right - 2,
            m_scrollbar.thumb_pos + m_scrollbar.thumb_height
        };
        
        COLORREF thumb_color = m_scrollbar.thumb_hover ? m_scrollbar_thumb_hover : m_scrollbar_thumb;
        HBRUSH thumb_brush = CreateSolidBrush(thumb_color);
        FillRect(hdc, &thumb_rect, thumb_brush);
        DeleteObject(thumb_brush);
    }
    
    LRESULT on_size() {
        calculate_content_height();
        update_scrollbar();
        InvalidateRect(m_hwnd, NULL, FALSE);
        return 0;
    }
    
    LRESULT on_mousewheel(int delta) {
        if (!m_scrollbar.visible) return 0;
        
        RECT rc;
        GetClientRect(m_hwnd, &rc);
        
        // Scroll 3 lines at a time
        int scroll_amount = (delta > 0 ? -1 : 1) * LINE_HEIGHT * 3;
        m_scroll_pos += scroll_amount;
        
        // Clamp scroll position
        m_scroll_pos = max(0, min(m_scroll_pos, max(0, m_content_height - rc.bottom)));
        
        update_scrollbar();
        InvalidateRect(m_hwnd, NULL, FALSE);
        return 0;
    }
    
    LRESULT on_lbuttondown(int x, int y) {
        RECT rc;
        GetClientRect(m_hwnd, &rc);
        
        // Check if click is on divider
        if (m_layout_mode == LayoutMode::HORIZONTAL) {
            // Vertical divider in horizontal mode
            if (x >= m_divider_pos - DIVIDER_WIDTH/2 && x <= m_divider_pos + DIVIDER_WIDTH/2) {
                m_dragging_divider = true;
                SetCapture(m_hwnd);
                SetCursor(LoadCursor(NULL, IDC_SIZEWE));
                return 0;
            }
        } else {
            // Horizontal divider in vertical mode - make it draggable
            int divider_y = m_vertical_divider_pos - m_scroll_pos;
            if (y >= divider_y - DIVIDER_WIDTH/2 && y <= divider_y + DIVIDER_WIDTH/2) {
                m_dragging_divider = true;
                SetCapture(m_hwnd);
                SetCursor(LoadCursor(NULL, IDC_SIZENS));
                return 0;
            }
        }
        
        // Check if click is on scrollbar
        if (m_scrollbar.visible && x >= rc.right - SCROLLBAR_WIDTH) {
            // Check if on thumb
            if (y >= m_scrollbar.thumb_pos && y <= m_scrollbar.thumb_pos + m_scrollbar.thumb_height) {
                m_scrollbar.thumb_pressed = true;
                m_scrollbar.mouse_offset = y - m_scrollbar.thumb_pos;
                SetCapture(m_hwnd);
            } else {
                // Page up/down
                if (y < m_scrollbar.thumb_pos) {
                    m_scroll_pos -= rc.bottom;
                } else {
                    m_scroll_pos += rc.bottom;
                }
                m_scroll_pos = max(0, min(m_scroll_pos, max(0, m_content_height - rc.bottom)));
                update_scrollbar();
                InvalidateRect(m_hwnd, NULL, FALSE);
            }
        }
        
        return 0;
    }
    
    LRESULT on_lbuttonup() {
        if (m_dragging_divider) {
            m_dragging_divider = false;
            ReleaseCapture();
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            return 0;
        }
        
        if (m_scrollbar.thumb_pressed) {
            m_scrollbar.thumb_pressed = false;
            ReleaseCapture();
            InvalidateRect(m_hwnd, NULL, FALSE);
        }
        return 0;
    }
    
    LRESULT on_mousemove(int x, int y) {
        RECT rc;
        GetClientRect(m_hwnd, &rc);
        
        // Handle divider dragging
        if (m_dragging_divider) {
            if (m_layout_mode == LayoutMode::HORIZONTAL) {
                // Vertical divider
                int new_pos = x;
                new_pos = max(MIN_PANEL_WIDTH, min(new_pos, rc.right - MIN_PANEL_WIDTH - SCROLLBAR_WIDTH));
                
                if (new_pos != m_divider_pos) {
                    m_divider_pos = new_pos;
                    InvalidateRect(m_hwnd, NULL, FALSE);
                }
            } else {
                // Horizontal divider
                int new_pos = y + m_scroll_pos;
                new_pos = max(MIN_IMAGE_HEIGHT, min(new_pos, rc.bottom - MIN_IMAGE_HEIGHT));
                
                if (new_pos != m_vertical_divider_pos) {
                    m_vertical_divider_pos = new_pos;
                    InvalidateRect(m_hwnd, NULL, FALSE);
                }
            }
            return 0;
        }
        
        // Check if hovering over divider
        if (!m_dragging_divider && !m_scrollbar.thumb_pressed) {
            if (m_layout_mode == LayoutMode::HORIZONTAL) {
                if (x >= m_divider_pos - DIVIDER_WIDTH/2 && x <= m_divider_pos + DIVIDER_WIDTH/2) {
                    SetCursor(LoadCursor(NULL, IDC_SIZEWE));
                } else {
                    SetCursor(LoadCursor(NULL, IDC_ARROW));
                }
            } else {
                int divider_y = m_vertical_divider_pos - m_scroll_pos;
                if (y >= divider_y - DIVIDER_WIDTH/2 && y <= divider_y + DIVIDER_WIDTH/2) {
                    SetCursor(LoadCursor(NULL, IDC_SIZENS));
                } else {
                    SetCursor(LoadCursor(NULL, IDC_ARROW));
                }
            }
        }
        
        // Update hover state for scrollbar
        bool was_hover = m_scrollbar.thumb_hover;
        m_scrollbar.thumb_hover = false;
        
        if (m_scrollbar.visible && x >= rc.right - SCROLLBAR_WIDTH) {
            if (y >= m_scrollbar.thumb_pos && y <= m_scrollbar.thumb_pos + m_scrollbar.thumb_height) {
                m_scrollbar.thumb_hover = true;
            }
        }
        
        // Handle thumb dragging
        if (m_scrollbar.thumb_pressed) {
            int new_thumb_pos = y - m_scrollbar.mouse_offset;
            int max_thumb_pos = rc.bottom - m_scrollbar.thumb_height;
            new_thumb_pos = max(0, min(new_thumb_pos, max_thumb_pos));
            
            // Calculate scroll position from thumb position
            float scroll_ratio = (float)new_thumb_pos / max_thumb_pos;
            m_scroll_pos = (int)(scroll_ratio * (m_content_height - rc.bottom));
            
            update_scrollbar();
            InvalidateRect(m_hwnd, NULL, FALSE);
        } else if (was_hover != m_scrollbar.thumb_hover) {
            // Redraw if hover state changed
            InvalidateRect(m_hwnd, NULL, FALSE);
        }
        
        return 0;
    }
    
    LRESULT on_lbuttondblclk(int x, int y) {
        // Switch layout on double-click
        switch_layout(m_layout_mode == LayoutMode::HORIZONTAL ? 
                     LayoutMode::VERTICAL : LayoutMode::HORIZONTAL);
        return 0;
    }
    
    // UI Element menu support for layout edit mode - these will be called via the regular context menu
    
    LRESULT on_rbuttonup(int x, int y) {
        // Check if we're in edit mode
        bool edit_mode = false;
        if (m_callback.is_valid()) {
            edit_mode = m_callback->is_edit_mode_enabled();
        }
        
        // In edit mode, let the host handle the context menu with our additions
        if (edit_mode) {
            // The edit_mode_context_menu_* methods should be called by the host
            // We need to pass the message to the parent
            return DefWindowProc(m_hwnd, WM_RBUTTONUP, 0, MAKELPARAM(x, y));
        }
        
        // Normal mode - show our custom context menu
        if (!m_context_menu) {
            m_context_menu = CreatePopupMenu();
            AppendMenu(m_context_menu, MF_STRING, 1001, L"Horizontal Layout (Image Left)");
            AppendMenu(m_context_menu, MF_STRING, 1002, L"Vertical Layout (Image Top)");
            AppendMenu(m_context_menu, MF_SEPARATOR, 0, NULL);
            AppendMenu(m_context_menu, MF_STRING, 1003, L"Refresh Artist Info");
        }
        
        // Update checkmarks
        CheckMenuItem(m_context_menu, 1001, m_layout_mode == LayoutMode::HORIZONTAL ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(m_context_menu, 1002, m_layout_mode == LayoutMode::VERTICAL ? MF_CHECKED : MF_UNCHECKED);
        
        // Show menu
        POINT pt = {x, y};
        ClientToScreen(m_hwnd, &pt);
        TrackPopupMenu(m_context_menu, TPM_LEFTALIGN | TPM_TOPALIGN,
                      pt.x, pt.y, 0, m_hwnd, NULL);
        
        return 0;
    }
    
    LRESULT on_command(int id) {
        switch (id) {
            case 1001: // Horizontal layout
                switch_layout(LayoutMode::HORIZONTAL);
                break;
            case 1002: // Vertical layout
                switch_layout(LayoutMode::VERTICAL);
                break;
            case 1003: // Refresh
                fetch_artist_biography();
                break;
        }
        return 0;
    }
    
    void switch_layout(LayoutMode new_mode) {
        if (m_layout_mode != new_mode) {
            m_layout_mode = new_mode;
            m_scroll_pos = 0;
            calculate_content_height();
            update_scrollbar();
            InvalidateRect(m_hwnd, NULL, TRUE);
        }
    }
    
    // UI Element edit mode context menu support
    bool edit_mode_context_menu_test(const POINT& p_point, bool p_fromkeyboard) override {
        // Always return true to indicate we can provide a context menu
        return true;
    }
    
    void edit_mode_context_menu_build(const POINT& p_point, bool p_fromkeyboard, HMENU p_menu, unsigned p_id_base) override {
        // Add our menu items to the provided menu
        AppendMenu(p_menu, MF_SEPARATOR, 0, NULL);
        AppendMenu(p_menu, MF_STRING, p_id_base + 0, L"Horizontal Layout (Image Left)");
        AppendMenu(p_menu, MF_STRING, p_id_base + 1, L"Vertical Layout (Image Top)");
        AppendMenu(p_menu, MF_SEPARATOR, 0, NULL);
        AppendMenu(p_menu, MF_STRING, p_id_base + 2, L"Refresh Artist Info");
        
        // Update checkmarks
        CheckMenuItem(p_menu, p_id_base + 0, m_layout_mode == LayoutMode::HORIZONTAL ? MF_CHECKED : MF_UNCHECKED);
        CheckMenuItem(p_menu, p_id_base + 1, m_layout_mode == LayoutMode::VERTICAL ? MF_CHECKED : MF_UNCHECKED);
    }
    
    void edit_mode_context_menu_command(const POINT& p_point, bool p_fromkeyboard, unsigned p_id, unsigned p_id_base) override {
        // Handle menu commands
        unsigned cmd = p_id - p_id_base;
        switch (cmd) {
            case 0: // Horizontal layout
                switch_layout(LayoutMode::HORIZONTAL);
                break;
            case 1: // Vertical layout
                switch_layout(LayoutMode::VERTICAL);
                break;
            case 2: // Refresh
                fetch_artist_biography();
                break;
        }
    }
    
    bool edit_mode_context_menu_get_description(unsigned p_id, unsigned p_id_base, pfc::string_base& p_out) override {
        unsigned cmd = p_id - p_id_base;
        switch (cmd) {
            case 0:
                p_out = "Switch to horizontal layout with image on the left";
                return true;
            case 1:
                p_out = "Switch to vertical layout with image on top";
                return true;
            case 2:
                p_out = "Refresh the artist biography and image";
                return true;
        }
        return false;
    }
};

// Context menu item for layout switching
class contextmenu_artist_bio : public contextmenu_item_simple {
public:
    enum {
        cmd_horizontal = 0,
        cmd_vertical,
        cmd_refresh,
        cmd_total
    };
    
    unsigned get_num_items() override { return cmd_total; }
    
    void get_item_name(unsigned p_index, pfc::string_base& p_out) override {
        switch(p_index) {
            case cmd_horizontal: p_out = "Horizontal Layout (Image Left)"; break;
            case cmd_vertical: p_out = "Vertical Layout (Image Top)"; break;
            case cmd_refresh: p_out = "Refresh Artist Info"; break;
        }
    }
    
    void get_item_default_path(unsigned p_index, pfc::string_base& p_out) override {
        p_out = "Artist Bio";
    }
    
    void context_command(unsigned p_index, metadb_handle_list_cref p_data, const GUID& p_caller) override {
        // Find all artist bio windows and update them
        if (p_index == cmd_horizontal || p_index == cmd_vertical) {
            // We need a way to communicate with the window instances
            // For now, let's store the preference
            cfg_int g_layout_mode(GUID{0x12345678, 0x9abc, 0xdef0, {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}}, 0);
            g_layout_mode = (p_index == cmd_horizontal) ? 0 : 1;
        }
    }
    
    GUID get_item_guid(unsigned p_index) override {
        static const GUID guid_horizontal = { 0x5f4b3d1a, 0x2c3e, 0x4a5b, { 0x9c, 0x8d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d } };
        static const GUID guid_vertical = { 0x7a8b9c0d, 0xe1f2, 0x3456, { 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56 } };
        static const GUID guid_refresh = { 0x9e8d7c6b, 0x5a4f, 0x3e2d, { 0x1c, 0x0b, 0xa9, 0x87, 0x65, 0x43, 0x21, 0xfe } };
        
        switch(p_index) {
            case cmd_horizontal: return guid_horizontal;
            case cmd_vertical: return guid_vertical;
            case cmd_refresh: return guid_refresh;
            default: return pfc::guid_null;
        }
    }
    
    bool get_item_description(unsigned p_index, pfc::string_base& p_out) override {
        switch(p_index) {
            case cmd_horizontal: p_out = "Switch to horizontal layout with image on the left"; return true;
            case cmd_vertical: p_out = "Switch to vertical layout with image on top"; return true;
            case cmd_refresh: p_out = "Refresh the artist biography and image"; return true;
        }
        return false;
    }
};

static contextmenu_item_factory_t<contextmenu_artist_bio> g_contextmenu_artist_bio;

// UI element factory
class ui_element_artist_bio : public ui_element {
public:
    GUID get_guid() override {
        return artist_bio_window::g_get_guid();
    }
    
    void get_name(pfc::string_base& out) override {
        artist_bio_window::g_get_name(out);
    }
    
    ui_element_config::ptr get_default_configuration() override {
        return artist_bio_window::g_get_default_configuration();
    }
    
    const char* get_description() {
        return artist_bio_window::g_get_description();
    }
    
    GUID get_subclass() override {
        return artist_bio_window::g_get_subclass();
    }
    
    ui_element_children_enumerator_ptr enumerate_children(ui_element_config::ptr) override {
        return NULL;
    }
    
    ui_element_instance::ptr instantiate(HWND parent, ui_element_config::ptr cfg, ui_element_instance_callback::ptr callback) override {
        PFC_ASSERT(cfg->get_guid() == get_guid());
        service_nnptr_t<artist_bio_window> instance = new service_impl_t<artist_bio_window>();
        instance->set_callback(callback);
        instance->initialize_window(parent);
        return instance;
    }
};

static service_factory_single_t<ui_element_artist_bio> g_artist_bio_factory;