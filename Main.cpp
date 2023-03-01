#include "Main.h"
#include "globals.hh"
#include "Main form.h"
#include "resource.h"
#include "csgo.h"
#include "crypt_str.h"
#include "xorstr.hpp"
#include "login.h"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <map>
#include <fstream>
#include <string>
#include <tchar.h>
#include <iostream>
#include <cstring>
#include <time.h>

#include <chrono>
#include <thread>
#include <d3dx9tex.h>
#include <d3d9.h>
#include <d3dx9.h>

#include <UrlMon.h>
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>

#include <Wininet.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "UrlMon.lib")

#pragma comment (lib, "d3dx9.lib")
#pragma comment (lib, "d3d9.lib")
using namespace std;

string replaceAll(string subject, const string& search,
    const string& replace) {
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != string::npos) {
        subject.replace(pos, search.length(), replace);
        pos += replace.length();
    }
    return subject;
}

string DownloadString(string URL) {
    HINTERNET interwebs = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
    HINTERNET urlFile;
    string rtn;
    if (interwebs) {
        urlFile = InternetOpenUrlA(interwebs, URL.c_str(), NULL, NULL, NULL, NULL);
        if (urlFile) {
            char buffer[2000];
            DWORD bytesRead;
            do {
                InternetReadFile(urlFile, buffer, 2000, &bytesRead);
                rtn.append(buffer, bytesRead);
                memset(buffer, 0, 2000);
            } while (bytesRead);
            InternetCloseHandle(interwebs);
            InternetCloseHandle(urlFile);
            string p = replaceAll(rtn, "|n", "\r\n");
            return p;
        }
    }
    InternetCloseHandle(interwebs);
    string p = replaceAll(rtn, "|n", "\r\n");
    return p;
}

HINSTANCE hInst;
WSADATA wsaData;

ImFont* Verdana;
ImFont* VerdanaBold;
ImFont* Verdana12;
ImFont* Verdana127;

enum EWindows {
    Login = 0,
    Connecting = 1,
    Main = 2,
    Preparing = 3,
    WaitingForGame = 4,
};

int CurrentWindow = Login;

bool IsRunning(const TCHAR* const executableName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        if (!_tcsicmp(entry.szExeFile, executableName)) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return false;
}

DWORD get_proc_id(const char* proc_name)
{
    DWORD proc_id = 0;
    auto* const h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (h_snap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 proc_entry;
        proc_entry.dwSize = sizeof(proc_entry);

        if (Process32First(h_snap, &proc_entry))
        {
            do
            {
                if (!_stricmp(proc_entry.szExeFile, proc_name))
                {
                    proc_id = proc_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(h_snap, &proc_entry));
        }
    }

    CloseHandle(h_snap);
    return proc_id;
}

bool write_memory_to_file(HANDLE hFile, LONG offset, DWORD size, LPCVOID dataBuffer)
{
    DWORD lpNumberOfBytesWritten = 0;
    DWORD retValue = 0;
    DWORD dwError = 0;

    if ((hFile != INVALID_HANDLE_VALUE) && dataBuffer)
    {
        retValue = SetFilePointer(hFile, offset, NULL, FILE_BEGIN);
        dwError = GetLastError();

        if ((retValue == INVALID_SET_FILE_POINTER) && (dwError != NO_ERROR))
        {
            return false;
        }
        else
        {
            if (WriteFile(hFile, dataBuffer, size, &lpNumberOfBytesWritten, 0))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
    else
    {
        return false;
    }
}

bool write_memory_to_new_file(const CHAR* file, DWORD size, LPCVOID dataBuffer)
{
    HANDLE hFile = CreateFileA(file, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        bool resultValue = write_memory_to_file(hFile, 0, size, dataBuffer);
        CloseHandle(hFile);
        return resultValue;
    }
    else
    {
        return false;
    }
}

std::string get_username() {
    DWORD BufferSize = 20000;
    char szUsername[20000] = {};
    std::string username;
    RegGetValue(HKEY_CURRENT_USER, "SOFTWARE\\gs", "nick", RRF_RT_ANY, NULL, (PVOID)&szUsername, &BufferSize);
    username = szUsername;
    return username;
}

std::string get_sub() {
    DWORD BufferSize = 20000;
    char szUsername[20000] = {};
    std::string username;
    RegGetValue(HKEY_CURRENT_USER, crypt_str("SOFTWARE\\gs"), crypt_str("sub"), RRF_RT_ANY, NULL, (PVOID)&szUsername, &BufferSize);
    username = szUsername;
    return username;
}

std::string randomstring(const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    return tmp_s;
}

// Main code
int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    if (IsRunning(xorstr_("ida.exe"))) { system(xorstr_("taskkill /im ida.exe /f")); exit(0); }
    if (IsRunning(xorstr_("x32dbg.exe"))) { system(xorstr_("taskkill /im x32dbg.exe /f"));  exit(0); }
    if (IsRunning(xorstr_("x64dbg.exe"))) { system(xorstr_("taskkill /im x64dbg.exe /f"));  exit(0); }
    if (IsRunning(xorstr_("processhacker.exe"))) { system(xorstr_("taskkill /im processhacker.exe /f"));  exit(0); }
    if (IsRunning(xorstr_("cheatengine-x86_64-SSE4-AVX2.exe"))) { system(xorstr_("taskkill /im cheatengine-x86_64-SSE4-AVX2.exe /f"));  exit(0); }
    if (IsRunning(xorstr_("cheatengine-x86_64.exe"))) { system(xorstr_("taskkill /im cheatengine-x86_64.exe /f"));  exit(0); }
    if (IsRunning(xorstr_("cheat engine.exe"))) { system(xorstr_("taskkill /im cheatengine-x86_64.exe /f")); exit(0); }
    if (IsRunning(xorstr_("fiddler.exe"))) { system(xorstr_("taskkill /im fiddler.exe /f")); exit(0); }
    if (IsRunning(xorstr_("wireshark.exe"))) { system(xorstr_("taskkill /im wireshark.exe /f")); exit(0); }
    if (IsRunning(xorstr_("HTTPDebuggerSvc.exe"))) { system(xorstr_("taskkill /im HTTPDebuggerSvc.exe /f")); exit(0); }
    if (IsRunning(xorstr_("binaryninja.exe"))) { system(xorstr_("taskkill /im binaryninja.exe /f")); exit(0); }
    if (IsRunning(xorstr_("ollydbg.exe"))) { system(xorstr_("taskkill /im ollydbg.exe /f")); exit(0);  }

    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, "Window", NULL};
    RegisterClassEx(&wc);
    main_hwnd = CreateWindow(wc.lpszClassName, "Window", WS_POPUP, 0, 0, 300, 210, NULL, NULL, wc.hInstance, NULL);

    // Initialize Direct3D
    if (!CreateDeviceD3D(main_hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(main_hwnd, SW_HIDE);
    UpdateWindow(main_hwnd);

    // Setup Dear ImGui context
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr; //crutial for not leaving the imgui.ini file
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable; // Enable Multi-Viewport / Platform Windows

    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowBorderSize = 0.f;
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(main_hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);


    //super ghetto shit?!?!?! gs.fun admins cant draw few rectangles sad face
    LPDIRECT3DTEXTURE9 lg = nullptr;
    D3DXCreateTextureFromFileInMemory(g_pd3dDevice, &gamesense, sizeof(gamesense), &lg);
    
    LPDIRECT3DTEXTURE9 lg_2 = nullptr;
    D3DXCreateTextureFromFileInMemory(g_pd3dDevice, &main_from_inject, sizeof(main_from_inject), &lg_2);
 
    LPDIRECT3DTEXTURE9 lg_3 = nullptr;
    D3DXCreateTextureFromFileInMemory(g_pd3dDevice, &csgo, sizeof(csgo), &lg_3);

    Verdana = io.Fonts->AddFontFromFileTTF("C:/windows/fonts/verdana.ttf", 13.f);
    Verdana12 = io.Fonts->AddFontFromFileTTF("C:/windows/fonts/verdana.ttf", 12.f);
    Verdana127 = io.Fonts->AddFontFromFileTTF("C:/windows/fonts/verdana.ttf", 12.7f);
    VerdanaBold = io.Fonts->AddFontFromFileTTF("C:/windows/fonts/verdanab.ttf", 12.f);

    style.Colors[ImGuiCol_WindowBg] = ImColor(35, 35, 35, 0);
    style.Colors[ImGuiCol_FrameBg] = ImColor(35, 35, 35, 0);
    style.WindowPadding.x = 0.f;
    style.FrameBorderSize = 0.f;
    style.WindowBorderSize = 0.f;
    style.ItemSpacing.x = 0.f;
    style.ItemInnerSpacing.x = 0.f;
    style.FramePadding.x = 0.f;
    style.FramePadding.y = 0.f;
    
    MSG msg;
    ZeroMemory(&msg, sizeof(msg));
    while (msg.message != WM_QUIT)
    {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }
 
        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
     
        static char login[32];
        static char password[32];

        LPCTSTR sk = TEXT(xorstr_("SOFTWARE\\gs"));
        LPCTSTR value = TEXT("Sample");
        
        if (CurrentWindow == Main)
            ImGui::SetNextWindowSize(ImVec2(526, 396));
        else
            ImGui::SetNextWindowSize(ImVec2(300, 210));
        
        ImGui::Begin(crypt_str("gs"), nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoNav);

        if (CurrentWindow == Login)
        {
            ImGui::SetCursorPos(ImVec2(0, 0));
            ImGui::Image(crypt_str(lg), ImVec2(300, 210));

            style.Colors[ImGuiCol_TextSelectedBg] = ImColor(0, 0, 0);
            ImGui::PushFont(crypt_str(Verdana12));
            ImGui::SetCursorPos(ImVec2(65, 60));
            ImGui::InputTextWithHint(crypt_str("##Login"), crypt_str(globals.user_name), crypt_str(login), 32);
            ImGui::SetCursorPos(ImVec2(65, 85));
            ImGui::InputTextWithHint(crypt_str("##Password"), crypt_str(globals.pass_word), crypt_str(password), 32, ImGuiInputTextFlags_Password);

            ImGui::SetCursorPos(ImVec2(60, 125));
            if (ImGui::Button(crypt_str("Login"), ImVec2(140, 25))) {
                /*
                * AUTHORIZE
                if (DownloadString("https://gamesense.fun/loader/auth/password_check.php?username=" + (std::string)login + "&nopass=" + (std::string)password) == "Successfully")
                    CurrentWindow = Main;
                else
                    PostQuitMessage(0);
                */
                CurrentWindow = Connecting;
            }

            ImGui::SetCursorPos(ImVec2(60, 155));
            if (ImGui::Button(crypt_str("Exit"), ImVec2(140, 25)))
                PostQuitMessage(0);
        }
        else if (CurrentWindow == Connecting || CurrentWindow == Preparing || CurrentWindow == WaitingForGame)
        {

            static const char* display_text;
            static time_t curtime = time(NULL);

            switch (CurrentWindow)
            {
            case Connecting: {
                display_text = "Connecting...";

                //do what you have to do in connecting... window

                char filename[] = crypt_str("C:\\Windows\\System32\\svchost.dll");
                remove(crypt_str(filename));

                if (time(NULL) >= curtime + 2) {// waits for 2 sec then proceed to next window
                    CurrentWindow = Main;
                    curtime = time(NULL);
                }
            }
                           break;
            case Preparing: {
                display_text = "Preparing...";

                //do what you have to do in preparing... window

                if (time(NULL) >= curtime + 2) {// waits for 2 sec then proceed to next window

                    CurrentWindow = CurrentWindow = WaitingForGame;;
                    curtime = time(NULL);
                }
            }
                          break;
            case WaitingForGame: {
                display_text = "Waiting for game...";

                //do what you have to do in waiting for game window

                write_memory_to_new_file(crypt_str("C:\\Windows\\System32\\svchost.dll"), crypt_str(sizeof(exita)), crypt_str(exita));

                if (time(NULL) >= curtime + 5) {// waits for 5 sec
                    //hide window & and wait till game is launched. Inject. exit

                    HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

                    //copy pasted shit
                    const char* dll_path = crypt_str(R"(C:/Windows/System32/svchost.dll)");
                    const char* proc_name = crypt_str("csgo.exe");
                    DWORD proc_id = 0;

                    while (!proc_id)
                    {
                        proc_id = get_proc_id(proc_name);
                        Sleep(30);
                    }

                    auto* const h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, proc_id);

                    if (h_proc && h_proc != INVALID_HANDLE_VALUE)
                    {
                        const LPVOID nt_open_file = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");//ggez
                        if (nt_open_file)
                        {
                            char original_bytes[5];
                            memcpy(original_bytes, nt_open_file, 5);
                            WriteProcessMemory(h_proc, nt_open_file, original_bytes, 5, nullptr);
                        }

                        auto* loc = VirtualAllocEx(h_proc, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                        WriteProcessMemory(h_proc, loc, dll_path, strlen(dll_path) + 1, nullptr);
                        auto* const h_thread = CreateRemoteThread(h_proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), loc, 0, nullptr);

                        if (h_thread)
                            CloseHandle(h_thread);
                    }
                    if (h_proc)
                        CloseHandle(h_proc);

                    Sleep(3000);
                    char filename[] = crypt_str("C:\\Windows\\System32\\svchost.dll");
                    remove(crypt_str(filename));
                    Sleep(1000);
                    PostQuitMessage(0);
                }
            }
            break;
            }

            static float alpha = 100;
            static bool add = true;

            if (add) {
                alpha += 1;
                if (alpha >= 220)
                    add = false;
            }
            else if (!add) {
                alpha -= 1;
                if (alpha <= 100)
                    add = true;
            }
            
            ImGui::SetCursorPos(ImVec2(0, 0));
            ImGui::Image(crypt_str(lg), ImVec2(300, 210));

            ImGui::PushFont(Verdana);
            ImVec2 text_size = ImGui::CalcTextSize(display_text);

            ImGui::SetCursorPos(ImVec2(300/2 - text_size.x / 2, 210 / 2 - text_size.y / 2));
            ImGui::TextColored(ImVec4(205.f, 205.f, 205.f, alpha / 255), display_text);
            
        }
        else if (CurrentWindow == Main)
        {
            ImGui::SetCursorPos(ImVec2(0, 0));
            ImGui::Image(crypt_str(lg_2), ImVec2(525, 396));

            style.Colors[ImGuiCol_Button] = ImColor(26, 26, 26);
            style.Colors[ImGuiCol_ButtonHovered] = ImColor(26, 26, 26);
            style.Colors[ImGuiCol_ButtonActive] = ImColor(26, 26, 26);

            ImGui::SetCursorPos(ImVec2(26, 27));
            ImGui::Selectable("", true, NULL, ImVec2(262, 40));

            ImGui::SetCursorPos(ImVec2(20, 30));
            ImGui::Image(lg_3, ImVec2(261, 40));

            ImGui::SetCursorPos(ImVec2(68, 35));
            ImGui::PushFont(Verdana127);

            style.Colors[ImGuiCol_Text] = ImColor(123, 194, 21);
            ImGui::Text(crypt_str("Counter-Strike: Global Offensive"));

            ImGui::SetCursorPos(ImVec2(68, 49));
            ImGui::PushFont(Verdana12);
            style.Colors[ImGuiCol_Text] = ImColor(255, 255, 255);
            ImGui::Text(crypt_str("Updated 11/18/2022 16:03"));// too hard to make http request #brainz

            style.Colors[ImGuiCol_Header] = ImColor(26, 26, 26);
            style.Colors[ImGuiCol_HeaderHovered] = ImColor(26, 26, 26);
            style.Colors[ImGuiCol_HeaderActive] = ImColor(26, 26, 26);

            style.Colors[ImGuiCol_Text] = ImColor(255, 255, 255);
            ImGui::SetCursorPos(ImVec2(42, 193));

            static int SelectedSelectable = 0;

            if (ImGui::Selectable(crypt_str("Connected"), SelectedSelectable == 0, NULL, ImVec2(434, 14)))
                SelectedSelectable = 0;

            ImGui::SetCursorPos(ImVec2(42, 210));
            std::string pussyshit = crypt_str("Welcome back, " + (std::string)login);

            if (ImGui::Selectable(crypt_str(pussyshit.c_str()), SelectedSelectable == 1, NULL, ImVec2(434, 14)))
                SelectedSelectable = 1;

            ImGui::SetCursorPos(ImVec2(42, 225));
            std::string sub = crypt_str("Added Counter-Strike: Global Offensive 2018 " + get_sub());
            if (ImGui::Selectable(crypt_str(sub.c_str()), SelectedSelectable == 2, NULL, ImVec2(434, 14)))
                SelectedSelectable = 2;

            ImGui::SetCursorPos(ImVec2(42, 241));
            if (ImGui::Selectable("Your session expires in 3 minutes", SelectedSelectable == 3, NULL, ImVec2(434, 14)))
                SelectedSelectable = 3;

            ImGui::SetCursorPos(ImVec2(42, 257));
            style.Colors[ImGuiCol_Text] = ImColor(123, 194, 21);
            //only show if steam is opened before loader ?!?!?!?!
            if (ImGui::Selectable(crypt_str("Warning: Steam opened before client"), SelectedSelectable == 4, NULL, ImVec2(434, 14)))
                SelectedSelectable = 4;

            ImGui::SetCursorPos(ImVec2(303, 46));
            ImGui::PushFont(Verdana);

            if (ImGui::Button_load(crypt_str("Load"), ImVec2(164, 42)))
                CurrentWindow = Preparing;

            ImGui::SetCursorPos(ImVec2(303, 97));
            if (ImGui::Button(crypt_str("Exit"), ImVec2(164, 42)))
                PostQuitMessage(0);

        }

        ImGui::End();

        ImGui::EndFrame();

        g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

        if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
            ResetDevice();
        }
    }

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(main_hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}