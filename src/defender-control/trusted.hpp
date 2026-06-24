#pragma once
#include <Windows.h>
#include <string>
#include <sddl.h>
#include <iostream>
#include "util.hpp"

namespace trusted
{
  // Enable prvileges
  //
  bool enable_privilege(std::string privilege);

  // Give system permissions
  //
  bool impersonate_system();

  // Start the trusted installer service
  //
  DWORD start_trusted();

  // Being a process as TrustedInstaller
  //
  // ARCHIVED / FALLBACK: the original token-theft launcher (duplicates the
  // running TrustedInstaller.exe token and CreateProcessWithTokenW). Kept as a
  // fallback for when the Task Scheduler "RunEx" launcher below is unavailable.
  //
  bool create_process(std::string commandLine);

  // --- Preferred TrustedInstaller launcher: Task Scheduler "RunEx" technique ---
  // (the Task Scheduler service spawns the process under the TI service account,
  //  yielding a clean PRIMARY token).

  // Absolute path of the log file the session-0 TI worker writes its output to.
  //
  std::wstring ti_log_path();

  // Truncate/clear the TI log file (call in the parent before launching).
  //
  void reset_ti_log();

  // Redirect this process's stdout to the TI log file (call in the worker child;
  // the scheduler launches it in session 0 with no console).
  //
  void redirect_output_to_ti_log();

  // Print the TI log file to the console (call in the parent after the worker ends).
  //
  void print_ti_log();

  // Launch a command line as NT SERVICE\TrustedInstaller via the Task Scheduler
  // service and wait for completion. Returns true if the task ran; *out_exit_code
  // receives the worker process's exit code.
  //
  bool run_as_ti_scheduled(const std::wstring& exe_path,
                           const std::wstring& arguments,
                           LONG* out_exit_code = nullptr,
                           DWORD timeout_ms = 300000);

  // Check current permissions for SYSTEM
  //
  bool is_system_group();

  // Checks if the current process is elevated
  //
  bool has_admin();
}
