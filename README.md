# Mini Shell — A Lightweight Unix-Like Shell in C

**Mini Shell** is a fully functional command-line shell written in **C**, built from scratch to explore **Unix system programming**, **process management**, and **signal handling**.  
It provides core shell functionalities including **command execution**, **I/O redirection**, **pipelines**, **background jobs**, and **command history navigation** — all implemented at a low level using POSIX APIs.

---

## 🚀 Features

✅ **Command Execution**
- Execute system commands just like in bash (e.g., `ls`, `cat`, `grep`, etc.)

✅ **Built-in Commands**
- `cd` — Change directory  
- `help` — List built-in commands  
- `exit` — Exit the shell  
- `jobs` — List background jobs  
- `fg` — Bring a background job to the foreground  
- `bg` — Resume a stopped job in the background  
- `history` — View command history  

✅ **Input/Output Redirection**
- Output redirection: `>` and `>>`  
- Input redirection: `<`  
- Error redirection: `2>`  
- Combined redirection: `&>` and `&>>`  
- File descriptor duplication: `2>&1`  

✅ **Pipelines**
- Chain commands using pipes, e.g.: cat file.txt | grep "hello" | wc -l

✅ **Background & Foreground Jobs**

Run commands in background using &
sleep 10 &
Manage and resume jobs with fg and bg

✅ **Command History**

Navigate through previous commands using the Up/Down arrow keys

Persistent history saved in ~/.mini_shell_history

✅ **Signal Handling**

Graceful handling of Ctrl+C and Ctrl+D

Proper process reaping with SIGCHLD handler

🧠 **Learning Objectives**
This project was designed to deeply understand:

Process creation and management (fork, execvp, waitpid)

Inter-process communication via pipes

Terminal control with termios

Signal handling (SIGCHLD, SIGINT)

Dynamic memory management in C

Building REPL (Read–Eval–Print Loop) systems

🧩 **Build**
make mini-shell

▶️ **Run**
./mini-shell

⚙️ **Requirements**
GCC or Clang compiler
POSIX-compatible environment (Linux, macOS, WSL)

🏁 **License**
This project is licensed under the MIT License — feel free to use, modify, and distribute it with attribution.