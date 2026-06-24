#include "trusted.hpp"

#include <taskschd.h>
#include <comdef.h>
#include <cstdio>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "comsuppw.lib")

namespace trusted
{
  // Enable prvileges
  //
  bool enable_privilege(std::string privilege)
  {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
      return false;

    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, privilege.c_str(), &luid))
    {
      CloseHandle(hToken);
      return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
      CloseHandle(hToken);
      return false;
    }

    CloseHandle(hToken);
    return true;
  }

  // Give system permissions
  //
  bool impersonate_system()
  {
    auto systemPid = util::get_pid("winlogon.exe");
    HANDLE hSystemProcess;
    if ((hSystemProcess = OpenProcess(
      PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
      FALSE,
      systemPid)) == nullptr)
    {
      return false;
    }

    HANDLE hSystemToken;
    if (!OpenProcessToken(
      hSystemProcess,
      MAXIMUM_ALLOWED,
      &hSystemToken))
    {
      CloseHandle(hSystemProcess);
      return false;
    }

    HANDLE hDupToken;
    SECURITY_ATTRIBUTES tokenAttributes;
    tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    tokenAttributes.lpSecurityDescriptor = nullptr;
    tokenAttributes.bInheritHandle = FALSE;
    if (!DuplicateTokenEx(
      hSystemToken,
      MAXIMUM_ALLOWED,
      &tokenAttributes,
      SecurityImpersonation,
      TokenImpersonation,
      &hDupToken))
    {
      CloseHandle(hSystemToken);
      return false;
    }

    if (!ImpersonateLoggedOnUser(hDupToken))
    {
      CloseHandle(hDupToken);
      CloseHandle(hSystemToken);
      return false;
    }

    // Optional
    //
    if (!SetThreadToken(0, hDupToken))
      return false;

    CloseHandle(hDupToken);
    CloseHandle(hSystemToken);

    return true;
  }

  // Start the trusted installer service
  //
  DWORD start_trusted()
  {
    auto sc_manager = OpenSCManagerA(
      nullptr,
      SERVICES_ACTIVE_DATABASE,
      GENERIC_EXECUTE
    );

    if (!sc_manager)
      return -1;

    auto service = OpenServiceA(
      sc_manager,
      "TrustedInstaller",
      GENERIC_READ | GENERIC_EXECUTE
    );

    if (!service)
    {
      CloseServiceHandle(sc_manager);
      return -1;
    }

    SERVICE_STATUS_PROCESS statusBuffer;
    DWORD bytesNeeded;
    while (QueryServiceStatusEx(
      service,
      SC_STATUS_PROCESS_INFO,
      reinterpret_cast<LPBYTE>(&statusBuffer),
      sizeof(SERVICE_STATUS_PROCESS),
      &bytesNeeded))
    {
      if (statusBuffer.dwCurrentState == SERVICE_STOPPED)
      {
        if (!StartServiceW(service, 0, nullptr))
        {
          CloseServiceHandle(service);
          CloseServiceHandle(sc_manager);
          return -1;
        }
      }
      if (statusBuffer.dwCurrentState == SERVICE_START_PENDING ||
        statusBuffer.dwCurrentState == SERVICE_STOP_PENDING)
      {
        Sleep(statusBuffer.dwWaitHint);
        continue;
      }
      if (statusBuffer.dwCurrentState == SERVICE_RUNNING)
      {
        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
        return statusBuffer.dwProcessId;
      }
    }
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);

    return -1;
  }

  // Being a process as TrustedInstaller
  //
  // ARCHIVED / FALLBACK launcher. This duplicates the running TrustedInstaller.exe
  // service token (which runs as LocalSystem, so the resulting process user is
  // S-1-5-18) and uses CreateProcessWithTokenW. Superseded by
  // run_as_ti_scheduled() below, but kept as a fallback.
  //
  bool create_process(std::string commandLine)
  {
    auto pid = start_trusted();

    enable_privilege(SE_DEBUG_NAME);
    enable_privilege(SE_IMPERSONATE_NAME);
    impersonate_system();

    auto hTIProcess = OpenProcess(
      PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
      FALSE, pid
    );

    if (!hTIProcess)
      return false;

    HANDLE hTIToken;
    if (!OpenProcessToken(hTIProcess, MAXIMUM_ALLOWED, &hTIToken))
    {
      CloseHandle(hTIProcess);
      return false;
    }

    HANDLE hDupToken;
    SECURITY_ATTRIBUTES tokenAttributes;
    tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    tokenAttributes.lpSecurityDescriptor = nullptr;
    tokenAttributes.bInheritHandle = FALSE;

    if (!DuplicateTokenEx(
      hTIToken,
      MAXIMUM_ALLOWED,
      &tokenAttributes,
      SecurityImpersonation,
      TokenImpersonation,
      &hDupToken
    ))
    {
      CloseHandle(hTIToken);
      return false;
    }

    STARTUPINFOW startupInfo;
    ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
    startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";
    PROCESS_INFORMATION processInfo;
    ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessWithTokenW(
      hDupToken,
      LOGON_WITH_PROFILE,
      nullptr,
      const_cast<LPWSTR>(util::string_to_wide(commandLine).c_str()),
      CREATE_UNICODE_ENVIRONMENT,
      nullptr,
      nullptr,
      &startupInfo,
      &processInfo
    ))
      return false;

    return true;
  }

  // ----------------------------------------------------------------------------
  // Preferred TrustedInstaller launcher: Task Scheduler "RunEx" technique.
  // The Task Scheduler service (running as SYSTEM) spawns the worker under the
  // TrustedInstaller service account, producing a clean primary token instead of
  // a duplicated/stolen one.
  // ----------------------------------------------------------------------------

  // Absolute path of the log file the session-0 TI worker writes its output to.
  //
  std::wstring ti_log_path()
  {
    wchar_t buf[MAX_PATH];
    DWORD n = ExpandEnvironmentStringsW(L"%ProgramData%\\defender-control", buf, MAX_PATH);
    std::wstring dir = (n > 0 && n <= MAX_PATH)
      ? std::wstring(buf)
      : std::wstring(L"C:\\ProgramData\\defender-control");

    CreateDirectoryW(dir.c_str(), nullptr); // best-effort; ignore "already exists"
    return dir + L"\\last-run.log";
  }

  // Truncate/clear the TI log file (call in the parent before launching).
  //
  void reset_ti_log()
  {
    auto path = ti_log_path();
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, path.c_str(), L"wb") == 0 && fp)
      fclose(fp);
  }

  // Redirect this process's stdout to the TI log file (call in the worker child).
  //
  void redirect_output_to_ti_log()
  {
    auto path = ti_log_path();
    FILE* fp = nullptr;
    if (_wfreopen_s(&fp, path.c_str(), L"w", stdout) == 0 && fp)
      setvbuf(stdout, nullptr, _IONBF, 0); // unbuffered so output survives a crash
  }

  // Print the TI log file to the console (call in the parent after the worker ends).
  //
  void print_ti_log()
  {
    auto path = ti_log_path();
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, path.c_str(), L"rb") != 0 || !fp)
    {
      printf("[no TrustedInstaller worker output captured]\n");
      return;
    }

    char chunk[4096];
    size_t r;
    bool any = false;
    while ((r = fread(chunk, 1, sizeof(chunk), fp)) > 0)
    {
      fwrite(chunk, 1, r, stdout);
      any = true;
    }
    fclose(fp);

    if (!any)
      printf("[TrustedInstaller worker produced no output]\n");
  }

  // Launch a command line as NT SERVICE\TrustedInstaller via the Task Scheduler
  // service and wait for completion. Returns true if the task ran.
  //
  bool run_as_ti_scheduled(const std::wstring& exe_path,
                           const std::wstring& arguments,
                           LONG* out_exit_code,
                           DWORD timeout_ms)
  {
    const wchar_t* TASK_NAME = L"defender-control-ti";

    // Resolve "NT SERVICE\TrustedInstaller" from its well-known SID (locale-safe).
    std::wstring ti_account = L"NT SERVICE\\TrustedInstaller";
    {
      PSID sid = nullptr;
      if (ConvertStringSidToSidW(
            L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &sid))
      {
        wchar_t name[256], dom[256];
        DWORD nl = 256, dl = 256;
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, sid, name, &nl, dom, &dl, &use))
          ti_account = std::wstring(dom) + L"\\" + name;
        LocalFree(sid);
      }
    }

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool did_coinit = SUCCEEDED(hr);

    ITaskService* svc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
          IID_ITaskService, (void**)&svc)))
    {
      if (did_coinit) CoUninitialize();
      return false;
    }

    bool ok = false;
    ITaskFolder*     root = nullptr;
    ITaskDefinition* def  = nullptr;
    IRegisteredTask* reg  = nullptr;

    do
    {
      if (FAILED(svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t())))
        break;
      if (FAILED(svc->GetFolder(_bstr_t(L"\\"), &root)))
        break;

      root->DeleteTask(_bstr_t(TASK_NAME), 0); // clear any stale task

      if (FAILED(svc->NewTask(0, &def)))
        break;

      // Settings: run regardless of power state, no execution time limit.
      ITaskSettings* set = nullptr;
      if (SUCCEEDED(def->get_Settings(&set)) && set)
      {
        set->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        set->put_StopIfGoingOnBatteries(VARIANT_FALSE);
        set->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));
        set->Release();
      }

      // Action: our exe + args.
      IActionCollection* acts = nullptr;
      if (FAILED(def->get_Actions(&acts)) || !acts)
        break;

      IAction* act = nullptr;
      if (FAILED(acts->Create(TASK_ACTION_EXEC, &act)) || !act)
      {
        acts->Release();
        break;
      }

      IExecAction* exec = nullptr;
      if (SUCCEEDED(act->QueryInterface(IID_IExecAction, (void**)&exec)) && exec)
      {
        exec->put_Path(_bstr_t(exe_path.c_str()));
        if (!arguments.empty())
          exec->put_Arguments(_bstr_t(arguments.c_str()));
        exec->Release();
      }
      act->Release();
      acts->Release();

      // Register with LOGON_NONE; the run-as user is supplied at RunEx time.
      if (FAILED(root->RegisterTaskDefinition(
            _bstr_t(TASK_NAME), def, TASK_CREATE_OR_UPDATE,
            _variant_t(), _variant_t(), TASK_LOGON_NONE,
            _variant_t(), &reg)))
        break;

      // *** Launch AS TrustedInstaller ***
      IRunningTask* running = nullptr;
      if (FAILED(reg->RunEx(_variant_t(), 0, 0, _bstr_t(ti_account.c_str()), &running)))
        break;
      if (running) running->Release();

      // Wait for completion (state returns to READY when the worker exits).
      DWORD waited = 0;
      for (;;)
      {
        TASK_STATE st = TASK_STATE_UNKNOWN;
        reg->get_State(&st);
        if (st == TASK_STATE_READY || st == TASK_STATE_DISABLED)
          break;
        if (waited >= timeout_ms)
          break;
        Sleep(200);
        waited += 200;
      }

      LONG result = 0;
      reg->get_LastTaskResult(&result);
      if (out_exit_code) *out_exit_code = result;
      ok = true;
    } while (false);

    if (def) def->Release();
    if (reg) reg->Release();
    if (root)
    {
      root->DeleteTask(_bstr_t(TASK_NAME), 0); // cleanup
      root->Release();
    }
    if (svc) svc->Release();
    if (did_coinit) CoUninitialize();

    return ok;
  }

  // Check current permissions for SYSTEM
  //
  bool is_system_group()
  {
    DWORD dw_size = 0;
    DWORD dw_result = 0;
    HANDLE token;
    PTOKEN_USER token_user;
    LPWSTR SID = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
      return false;

    if (!GetTokenInformation(token, TokenUser, NULL, dw_size, &dw_size))
    {
      dw_result = GetLastError();
      if (dw_result != ERROR_INSUFFICIENT_BUFFER)
        return false;
    }

    token_user = (PTOKEN_USER)GlobalAlloc(GPTR, dw_size);

    if (!GetTokenInformation(token, TokenUser, token_user, dw_size, &dw_size))
      return false;

    if (!token_user)
      return false;

    if (!ConvertSidToStringSidW(token_user->User.Sid, &SID))
      return false;

    // All SID can be found here:
    // https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
    // S-1-5-18	Local System	A service account that is used by the operating system.
    //
    if (_wcsicmp(L"S-1-5-18", SID) == 0)
      return true;

    if (token_user)
      GlobalFree(token_user);

    return false;
  }

  // Checks if the current process is elevated
  //
  bool has_admin()
  {
    BOOL ret = FALSE;
    HANDLE token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
      TOKEN_ELEVATION elevation;
      DWORD rlen = sizeof(TOKEN_ELEVATION);

      if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &rlen))
        ret = elevation.TokenIsElevated;
    }

    if (token)
      CloseHandle(token);

    return ret;
  }
}