#pragma once
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <string>
#include "settings.hpp"

namespace reg
{
  DWORD read_key(const wchar_t* root_name, const wchar_t* value_name, uint32_t flags = 0);

  // Read a REG_SZ / REG_EXPAND_SZ value from HKLM into out. Returns false if missing.
  bool read_string(const wchar_t* root_name, const wchar_t* value_name, std::wstring& out);

  bool create_registry(const wchar_t* root_name, HKEY& hkey);
  bool create_registry_hkcu(const wchar_t* root_name, HKEY& hkey);
  bool set_keyval(HKEY& hkey, const wchar_t* value_name, DWORD value);
  bool set_keyval_bin(HKEY& hkey, const wchar_t* value_name, DWORD value);
  bool set_keyval_sz(HKEY& hkey, const wchar_t* value_name, const wchar_t* value);

  // Set a REG_EXPAND_SZ value (used for service ImagePath).
  bool set_keyval_expand_sz(HKEY& hkey, const wchar_t* value_name, const wchar_t* value);
  bool delete_key(HKEY root, const wchar_t* sub_key);
  bool delete_value(HKEY& hkey, const wchar_t* value_name);

  // Take ownership of a registry key (as Administrators) and grant full control.
  // Used to break TrustedInstaller-owned/locked Defender keys when Tamper
  // Protection is off. Requires SeTakeOwnershipPrivilege (held by admin/SYSTEM).
  bool take_ownership(HKEY root, const wchar_t* sub_key);

  // Restore a key's owner to NT SERVICE\TrustedInstaller (undoes take_ownership).
  // Required on enable so the PPL Defender engine can initialise and SFC/DISM do
  // not flag the keys as tampered.
  bool restore_owner_trustedinstaller(HKEY root, const wchar_t* sub_key);

  // File-level (SE_FILE_OBJECT) equivalents of the registry ownership helpers.
  // Used by the binary soft-deletion path to seize Defender's TrustedInstaller-owned
  // files before renaming them, and to hand ownership back on restore.
  bool file_take_ownership(const wchar_t* path);
  bool file_restore_owner_trustedinstaller(const wchar_t* path);
}
