/* Supply an actual console control event to a Windows test child. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static HANDLE control_input, control_child;
static DWORD WINAPI control_thread(void *unused) {
    char action; DWORD amount;
    (void)unused;
    while (ReadFile(control_input, &action, 1, &amount, NULL) && amount) {
        if (action == 'q') GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
        else if (action == 'k') { TerminateProcess(control_child, 6); return 0; }
    }
    return 0;
}

int main(void) {
    STARTUPINFOA startup;
    PROCESS_INFORMATION child;
    char *command = GetCommandLineA();
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE error = GetStdHandle(STD_ERROR_HANDLE);
    DWORD result = 1;
    int quoted = 0;
    /* Preserve the already quoted child command line verbatim. */
    while (*command) {
        if (*command == '"') quoted = !quoted;
        if (*command == ' ' && !quoted) break;
        ++command;
    }
    while (*command == ' ') ++command;
    if (!*command) return 2;
    {
        HANDLE process = GetCurrentProcess(), duplicate;
        if (!DuplicateHandle(process, input, process, &duplicate, 0, TRUE, DUPLICATE_SAME_ACCESS)) return 7;
        input = duplicate;
        if (!DuplicateHandle(process, output, process, &duplicate, 0, TRUE, DUPLICATE_SAME_ACCESS)) return 8;
        output = duplicate;
        if (!DuplicateHandle(process, error, process, &duplicate, 0, TRUE, DUPLICATE_SAME_ACCESS)) return 9;
        error = duplicate;
    }
    FreeConsole();
    if (!AllocConsole()) return 3;
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input;
    startup.hStdOutput = output;
    startup.hStdError = error;
    if (!CreateProcessA(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL,
                        &startup, &child)) return 4;
    SetConsoleCtrlHandler(NULL, TRUE);
    CloseHandle(child.hThread);
    control_input = input;
    control_child = child.hProcess;
    if (!CreateThread(NULL, 0, control_thread, NULL, 0, NULL)) return 10;
    WaitForSingleObject(child.hProcess, INFINITE);
    GetExitCodeProcess(child.hProcess, &result);
    CloseHandle(child.hProcess);
    return (int)result;
}
