#include "reg.hpp"
#include <aclapi.h>
#include <sddl.h>
#include <string>

#pragma comment(lib, "advapi32.lib")

namespace reg
{
  // Enable a privilege on the current process token (best-effort)
  //
  static bool enable_privilege(const wchar_t* name)
  {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(),
      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
      return false;

    LUID luid;
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, name, &luid))
    {
      TOKEN_PRIVILEGES tp{};
      tp.PrivilegeCount = 1;
      tp.Privileges[0].Luid = luid;
      tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
      ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr)
        && GetLastError() == ERROR_SUCCESS;
    }

    CloseHandle(token);
    return ok;
  }

  // Build the SE_REGISTRY_KEY object name for a (root, sub_key) pair
  //
  static std::wstring registry_object_name(HKEY root, const wchar_t* sub_key)
  {
    std::wstring name;
    if (root == HKEY_LOCAL_MACHINE)      name = L"MACHINE\\";
    else if (root == HKEY_CURRENT_USER)  name = L"CURRENT_USER\\";
    else if (root == HKEY_CLASSES_ROOT)  name = L"CLASSES_ROOT\\";
    else if (root == HKEY_USERS)         name = L"USERS\\";
    name += sub_key;
    return name;
  }

  // Take ownership of a key as Administrators and grant full control.
  //
  bool take_ownership(HKEY root, const wchar_t* sub_key)
  {
    enable_privilege(L"SeTakeOwnershipPrivilege");
    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeBackupPrivilege");

    auto name = registry_object_name(root, sub_key);

    // Build the Administrators SID
    BYTE sid_buffer[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(sid_buffer);
    PSID admins = reinterpret_cast<PSID>(sid_buffer);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins, &sid_size))
      return false;

    // 1. Seize ownership (uses SeTakeOwnershipPrivilege, bypasses DACL)
    DWORD rc = SetNamedSecurityInfoW(
      const_cast<LPWSTR>(name.c_str()),
      SE_REGISTRY_KEY,
      OWNER_SECURITY_INFORMATION,
      admins, nullptr, nullptr, nullptr);

    if (rc != ERROR_SUCCESS)
      return false;

    // 2. Merge a full-control ACE for Administrators into the existing DACL
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL old_dacl = nullptr;
    GetNamedSecurityInfoW(
      const_cast<LPWSTR>(name.c_str()),
      SE_REGISTRY_KEY,
      DACL_SECURITY_INFORMATION,
      nullptr, nullptr, &old_dacl, nullptr, &sd);

    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = KEY_ALL_ACCESS;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = CONTAINER_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(admins);

    PACL new_dacl = nullptr;
    bool ok = false;
    if (SetEntriesInAclW(1, &ea, old_dacl, &new_dacl) == ERROR_SUCCESS)
    {
      rc = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(name.c_str()),
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr, new_dacl, nullptr);
      ok = (rc == ERROR_SUCCESS);
    }

    if (new_dacl) LocalFree(new_dacl);
    if (sd) LocalFree(sd);

    return ok;
  }

  // Hand ownership of a key back to NT SERVICE\TrustedInstaller.
  //
  // disable/take_ownership reassigns the owner to Administrators so we can write the
  // Defender keys; on enable we must restore the original TrustedInstaller owner,
  // otherwise the PPL engine can fail to initialise (WinDefend start timeout) and
  // SFC/DISM later flag the keys as tampered. Setting the owner to another account
  // requires SeRestorePrivilege (held by SYSTEM). Best-effort.
  //
  bool restore_owner_trustedinstaller(HKEY root, const wchar_t* sub_key)
  {
    enable_privilege(L"SeTakeOwnershipPrivilege");
    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeBackupPrivilege");

    auto name = registry_object_name(root, sub_key);

    // Fixed well-known SID for NT SERVICE\TrustedInstaller (same on every machine)
    PSID ti_sid = nullptr;
    if (!ConvertStringSidToSidW(
          L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
          &ti_sid))
      return false;

    DWORD rc = SetNamedSecurityInfoW(
      const_cast<LPWSTR>(name.c_str()),
      SE_REGISTRY_KEY,
      OWNER_SECURITY_INFORMATION,
      ti_sid, nullptr, nullptr, nullptr);

    LocalFree(ti_sid);
    return rc == ERROR_SUCCESS;
  }

  // File equivalent of take_ownership: seize a file as Administrators and grant full
  // control. Used before renaming TrustedInstaller-owned Defender binaries.
  //
  bool file_take_ownership(const wchar_t* path)
  {
    enable_privilege(L"SeTakeOwnershipPrivilege");
    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeBackupPrivilege");

    BYTE sid_buffer[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(sid_buffer);
    PSID admins = reinterpret_cast<PSID>(sid_buffer);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins, &sid_size))
      return false;

    // 1. Seize ownership (SeTakeOwnershipPrivilege bypasses the DACL).
    DWORD rc = SetNamedSecurityInfoW(
      const_cast<LPWSTR>(path), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
      admins, nullptr, nullptr, nullptr);
    if (rc != ERROR_SUCCESS)
      return false;

    // 2. Merge a full-control ACE for Administrators into the DACL.
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL old_dacl = nullptr;
    GetNamedSecurityInfoW(
      const_cast<LPWSTR>(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
      nullptr, nullptr, &old_dacl, nullptr, &sd);

    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(admins);

    PACL new_dacl = nullptr;
    bool ok = false;
    if (SetEntriesInAclW(1, &ea, old_dacl, &new_dacl) == ERROR_SUCCESS)
    {
      rc = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, new_dacl, nullptr);
      ok = (rc == ERROR_SUCCESS);
    }

    if (new_dacl) LocalFree(new_dacl);
    if (sd) LocalFree(sd);
    return ok;
  }

  // Hand a file's owner back to NT SERVICE\TrustedInstaller (undoes file_take_ownership)
  // so SFC/DISM/WU do not later flag the restored binary as tampered.
  //
  bool file_restore_owner_trustedinstaller(const wchar_t* path)
  {
    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeTakeOwnershipPrivilege");
    enable_privilege(L"SeBackupPrivilege");

    PSID ti_sid = nullptr;
    if (!ConvertStringSidToSidW(
          L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
          &ti_sid))
      return false;

    DWORD rc = SetNamedSecurityInfoW(
      const_cast<LPWSTR>(path), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
      ti_sid, nullptr, nullptr, nullptr);

    LocalFree(ti_sid);
    return rc == ERROR_SUCCESS;
  }

  // reads a key from HKEY_LOCAL_MACHINE
  //
  DWORD read_key(const wchar_t* root_name, const wchar_t* value_name, uint32_t flags)
  {
    LSTATUS status;
    HKEY hkey;
    DWORD result{};
    DWORD buff_sz = sizeof(DWORD);

    // https://docs.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view
    status = RegOpenKeyExW(
      HKEY_LOCAL_MACHINE,
      root_name,
      0,
      KEY_READ | KEY_WOW64_64KEY,
      &hkey
    );

    if (status)
    {
      if (flags & DBG_MSG)
        wprintf(L"Error opening %ls key \n", root_name);
      return -1;
    }

    status = RegQueryValueExW(
      hkey,
      value_name,
      0, NULL,
      reinterpret_cast<LPBYTE>(&result),
      &buff_sz
    );

    if (status)
    {
      if (flags & DBG_MSG)
        wprintf(L"Failed to read %d\n", result);

      return -1;
    }

    RegCloseKey(hkey);

    return result;
  }

  // creates a registry in HKEY_LOCAL_MACHINE with KEY_ALL_ACCESS permissions
  //
  bool create_registry(const wchar_t* root_name, HKEY& hkey)
  {
    LSTATUS status;

    DWORD dwDisposition;

    status = RegCreateKeyExW(
      HKEY_LOCAL_MACHINE,
      root_name,
      0, 0, 0,
      131334,
      0,
      &hkey,
      &dwDisposition
    );

    // If the key is owned/locked by TrustedInstaller, seize it and retry
    if (status == ERROR_ACCESS_DENIED && take_ownership(HKEY_LOCAL_MACHINE, root_name))
    {
      status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        root_name,
        0, 0, 0,
        131334,
        0,
        &hkey,
        &dwDisposition
      );
    }

    if (status)
    {
      wprintf(L"Could not find or create %ls error %d\n", root_name, status);
      return false;
    }

    return true;
  }

  // Set value in registry as a DWORD
  //
  bool set_keyval(HKEY& hkey, const wchar_t* value_name, DWORD value)
  {
    auto ret = RegSetValueExW(hkey, value_name, 0, REG_DWORD,
      reinterpret_cast<LPBYTE>(&value), 4);

    if (ret)
    {
      // wprintf(L"Set error: %d\n", ret);
      return false;
    }

    return true;
  }

  // Set value in registry as binary mode
  //
  bool set_keyval_bin(HKEY& hkey, const wchar_t* value_name, DWORD value)
  {
    auto ret = RegSetValueExW(hkey, value_name, 0, REG_BINARY,
      reinterpret_cast<LPBYTE>(&value), 12);

    if (ret)
    {
      // wprintf(L"Set error: %d\n", ret);
      return false;
    }
    return true;
  }

  // Set value in registry as a string (REG_SZ)
  //
  bool set_keyval_sz(HKEY& hkey, const wchar_t* value_name, const wchar_t* value)
  {
    auto ret = RegSetValueExW(hkey, value_name, 0, REG_SZ,
      reinterpret_cast<const BYTE*>(value),
      (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));

    if (ret)
      return false;

    return true;
  }

  // Set value in registry as an expandable string (REG_EXPAND_SZ)
  //
  bool set_keyval_expand_sz(HKEY& hkey, const wchar_t* value_name, const wchar_t* value)
  {
    auto ret = RegSetValueExW(hkey, value_name, 0, REG_EXPAND_SZ,
      reinterpret_cast<const BYTE*>(value),
      (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));

    if (ret)
      return false;

    return true;
  }

  // Read a REG_SZ / REG_EXPAND_SZ value from HKEY_LOCAL_MACHINE.
  //
  bool read_string(const wchar_t* root_name, const wchar_t* value_name, std::wstring& out)
  {
    HKEY hkey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, root_name, 0,
          KEY_READ | KEY_WOW64_64KEY, &hkey) != ERROR_SUCCESS)
      return false;

    DWORD type = 0, size = 0;
    bool ok = false;
    if (RegQueryValueExW(hkey, value_name, nullptr, &type, nullptr, &size) == ERROR_SUCCESS
        && (type == REG_SZ || type == REG_EXPAND_SZ) && size >= sizeof(wchar_t))
    {
      std::wstring buf(size / sizeof(wchar_t), L'\0');
      if (RegQueryValueExW(hkey, value_name, nullptr, nullptr,
            reinterpret_cast<LPBYTE>(&buf[0]), &size) == ERROR_SUCCESS)
      {
        // Trim the trailing NUL(s)
        size_t nul = buf.find(L'\0');
        if (nul != std::wstring::npos)
          buf.resize(nul);
        out = buf;
        ok = true;
      }
    }

    RegCloseKey(hkey);
    return ok;
  }

  // Creates a registry key in HKEY_CURRENT_USER with KEY_ALL_ACCESS permissions
  //
  bool create_registry_hkcu(const wchar_t* root_name, HKEY& hkey)
  {
    LSTATUS status;
    DWORD dwDisposition;

    status = RegCreateKeyExW(
      HKEY_CURRENT_USER,
      root_name,
      0, 0, 0,
      131334,
      0,
      &hkey,
      &dwDisposition
    );

    if (status == ERROR_ACCESS_DENIED && take_ownership(HKEY_CURRENT_USER, root_name))
    {
      status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        root_name,
        0, 0, 0,
        131334,
        0,
        &hkey,
        &dwDisposition
      );
    }

    if (status)
    {
      wprintf(L"Could not find or create HKCU\\%ls error %d\n", root_name, status);
      return false;
    }

    return true;
  }

  // Delete a registry key
  //
  bool delete_key(HKEY root, const wchar_t* sub_key)
  {
    auto status = RegDeleteKeyW(root, sub_key);
    return (status == ERROR_SUCCESS);
  }

  // Delete a value from an open registry key
  //
  bool delete_value(HKEY& hkey, const wchar_t* value_name)
  {
    auto status = RegDeleteValueW(hkey, value_name);
    return (status == ERROR_SUCCESS);
  }
}
