#include <unistd.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <sys/wait.h>

#include <iomanip>
#include "Commands.h"





using namespace std;

const std::string WHITESPACE = " \n\r\t\f\v";

#if 0
#define FUNC_ENTRY()  \
  cout << __PRETTY_FUNCTION__ << " --> " << endl;

#define FUNC_EXIT()  \
  cout << __PRETTY_FUNCTION__ << " <-- " << endl;
#else
#define FUNC_ENTRY()
#define FUNC_EXIT()
#endif

string _ltrim(const std::string &s) {
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == std::string::npos) ? "" : s.substr(start);
}

string _rtrim(const std::string &s) {
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

string _trim(const std::string &s) {
    return _rtrim(_ltrim(s));
}

int _parseCommandLine(const char *cmd_line, char **args) {
    FUNC_ENTRY()
    int i = 0;
    std::istringstream iss(_trim(string(cmd_line)).c_str());
    for (std::string s; iss >> s;) {
        args[i] = (char *) malloc(s.length() + 1);
        memset(args[i], 0, s.length() + 1);
        strcpy(args[i], s.c_str());
        args[++i] = NULL;
    }
    return i;

    FUNC_EXIT()
}

bool _isBackgroundComamnd(const char *cmd_line) {
    const string str(cmd_line);
    return str[str.find_last_not_of(WHITESPACE)] == '&';
}

void _removeBackgroundSign(char *cmd_line) {
    const string str(cmd_line);
    // find last character other than spaces
    unsigned int idx = str.find_last_not_of(WHITESPACE);
    // if all characters are spaces then return
    if (idx == string::npos) {
        return;
    }
    // if the command line does not end with & then return
    if (cmd_line[idx] != '&') {
        return;
    }
    // replace the & (background sign) with space and then remove all tailing spaces.
    cmd_line[idx] = ' ';
    // truncate the command line string up to the last non-space character
    cmd_line[str.find_last_not_of(WHITESPACE, idx) + 1] = 0;
}

// our helper functions

void freeArgs(char** args) {
    for (int i = 0; args[i]; i++) {
        if(args[i] != nullptr) {
            free(args[i]);
            args[i] = nullptr;
        }
    }
}




	
void writeErr(const char* msg) {
    syscall(SYS_write, STDERR_FILENO, msg, strlen(msg));
}

bool readAll(const char *path, std::string &out) {
    int fd = syscall(SYS_open, path, O_RDONLY, 0);
    if (fd < 0) {
        writeErr("smash error: open failed\n");
        return false;
    }
    out.clear();
    char buf[4096];
    ssize_t n;
    while ((n = syscall(SYS_read, fd, buf, sizeof(buf))) > 0) {
        out.append(buf, n);
    }
    if (n < 0) {
        writeErr("smash error: read failed\n");
        syscall(SYS_close, fd);
        return false;
    }
    syscall(SYS_close, fd);
    return true;
}




//end of our helper functions

// TODO: Add your implementation for classes in Commands.h

////////////////////////// chprompt /////////////////////////
void chpromptCommand::execute() {
    SmallShell& shell = SmallShell::getInstance();
    char *args[COMMAND_MAX_ARGS];
    int i=0;
    while (i < COMMAND_MAX_ARGS){
        args[i] = nullptr;
        i++;
    }
    int numOfArgs = _parseCommandLine(getCommandLine(), args);

    if(numOfArgs <= 1) {
        shell.setPrompt("smash");
    }else {
        shell.setPrompt((args[1]));
    }
    freeArgs(args);
}
//////////////////////////////////////////////////////////////////////////////
////////////////////////// showPid //////////////////////////
void ShowPidCommand::execute() {
    pid_t pid = getpid();
    cout << "smash pid is " << pid << endl;
}
//////////////////////////////////////////////////////////////////////////////
////////////////////////// PWD //////////////////////////
void GetCurrDirCommand::execute() {
    char currentWD[COMMAND_MAX_LENGTH] ;
    if(getcwd( currentWD , COMMAND_MAX_LENGTH) !=nullptr) {
        cout <<  currentWD << endl;
    }
}
//////////////////////////////////////////////////////////////////////////////
////////////////////////// CD //////////////////////////
void ChangeDirCommand::execute() {
    SmallShell &shell = SmallShell::getInstance();

    char *args[COMMAND_MAX_ARGS] = {nullptr};
    int argc = _parseCommandLine(m_cmndLine, args);
    if (argc > 2) {
        writeErr("smash error: cd: too many arguments\n");
        freeArgs(args);
        return;
    }

    string old = shell.getCurrDir();
    string target;

    if (argc == 2 && std::strcmp(args[1], "-") == 0) {
        if (shell.getPrevDir().empty()) {
            writeErr("smash error: cd: OLDPWD not set\n");
            freeArgs(args);
            return;
        }
        target = shell.getPrevDir();    
    }
    else if (argc == 2) {
        target = args[1];
    }

    if (::chdir(target.c_str()) != 0) {
        perror("smash error: chdir failed");
        freeArgs(args);
        return;
    }

    shell.setPrevDir(old);
    char buf[COMMAND_MAX_LENGTH];
    if (getcwd(buf, sizeof(buf))) {
        shell.setCurrDir(buf);
    } else {
        shell.setCurrDir(target);
    }

    freeArgs(args);
}
//////////////////////////////////////////////////////////////////////////////
////////////////////////// Jobs Command //////////////////////////
void JobsCommand::execute() {
    SmallShell& shell = SmallShell::getInstance();
    if(shell.getJobs()->getJobsList().empty()){
        return;
    }
    shell.getJobs()->printJobsList();
}
//////////////////////////////////////////////////////////////////////////////
////////////////////////// Fg Command //////////////////////////
void ForegroundCommand::execute() {
    char *args[COMMAND_MAX_ARGS];
    int i=0;
    while (i < COMMAND_MAX_ARGS){
        args[i] = nullptr;
        i++;
    }
    int numOfArgs = _parseCommandLine(getCommandLine(), args);
    SmallShell& shell = SmallShell::getInstance();
    if(numOfArgs == 1) {
		
        if (shell.getJobs()->getJobsList().empty()) {
            std::cerr << "smash error: fg: jobs list is empty" << std::endl;
            freeArgs(args);
            return;
        }
        int *lastJobId = new int();
       
        shared_ptr<JobsList::JobEntry> maxIdJob = shell.getJobs()->getLastJob(lastJobId);
        if(maxIdJob == nullptr)return;
        pid_t pid = maxIdJob->m_pid;
        int jId = maxIdJob->m_jId;
        std::cout << maxIdJob->m_cmnd << " " << pid << std::endl;
        shell.setCurrCmndLine(maxIdJob->m_cmnd);
        shell.setCurrJobId(jId);
        shell.setCurrJobPid(pid);
        int jobStatus;
        int waitResult = waitpid(pid, &jobStatus, WUNTRACED);
        if (waitResult != -1) {
            shell.getJobs()->removeJobById(maxIdJob->m_jId);
        } else {
            perror("smash error: waitpid failed");
        }
    }else if(numOfArgs >= 3){
        std::cerr << "smash error: fg: invalid arguments" << std::endl;
        freeArgs(args);
        return;
    }else if (args[1]) {
        int jId = atoi(args[1]);

        if (jId <= 0) {
            std::cerr << "smash error: fg: invalid arguments" << std::endl;
            freeArgs(args);
            return;
        }
        else if(!shell.getJobs()->getJobById(jId)){
            std::cerr << "smash error: fg: job-id " << jId << " does not exist" << std::endl;
            freeArgs(args);
            return;
        }
        shared_ptr<JobsList::JobEntry> job = shell.getJobs()->getJobById(jId);
        int jobId = job->m_jId;
        pid_t pid = job->m_pid;
        std::cout << job->m_cmnd << " " << pid << std::endl;
        shell.setCurrCmndLine(job->m_cmnd);
        shell.setCurrJobId(jobId);
        shell.setCurrJobPid(pid);
        int jobStatus;
        int waitResult = waitpid(pid, &jobStatus, WUNTRACED);
        if (waitResult != -1) {
            shell.getJobs()->removeJobById(job->m_jId);
        } else {
            perror("smash error: waitpid failed");
        }
        if (waitResult > 0 && WIFSTOPPED(jobStatus)) {
            if(kill (pid, SIGCONT)<0){
                perror("smash error: kill failed");
                return;
            }
        }
    }
    shell.setCurrCmndLine("");
    shell.setCurrJobId(-1);
    shell.setCurrJobPid(-1);
}
//////////////////////////////////////////////////////////////////////////////
////////////////////////// Quit Command //////////////////////////
void QuitCommand::execute() {
    char *args[COMMAND_MAX_ARGS];
    int i=0;
    while (i < COMMAND_MAX_ARGS){
        args[i] = nullptr;
        i++;
    }
    int numOfArgs = _parseCommandLine(getCommandLine(), args);
    if (args[1] && strcmp(args[1], "kill") == 0 && numOfArgs>= 2) {
        SmallShell& shell = SmallShell::getInstance();
        shell.getJobs()->killAllJobs();
    }
    freeArgs(args);
    exit(0);
}
//////////////////////////////////////////////////////////////////////////////
////////////////////////// Kill Command //////////////////////////
void KillCommand::execute(){
    SmallShell& shell = SmallShell::getInstance();
    shell.getJobs()->removeFinishedJobs();
    char *args[COMMAND_MAX_ARGS];
    int i=0;
    while (i < COMMAND_MAX_ARGS){
        args[i] = nullptr;
        i++;
    }
    int numOfArgs = _parseCommandLine(getCommandLine(), args);
    if(numOfArgs != 3 || isdigit(args[1][1]) == 0 || args[1][0] != '-' || isdigit(args[2][0]) == 0){
        writeErr("smash error: kill: invalid arguments\n");
        freeArgs(args);
        return;
    }
    int jId = atoi(args[2]);

    if(shell.getJobs() == nullptr){
        fprintf(stderr, "smash error: kill: job-id %d does not exist\n", jId);
        freeArgs(args);
        return;
    }

    shared_ptr<JobsList::JobEntry> job = shell.getJobs()->getJobById(jId);

    if(job == nullptr){
        fprintf(stderr, "smash error: kill: job-id %d does not exist\n", jId);
        freeArgs(args);
        return;
    }

    int signum = atoi(args[1] + 1);
    pid_t jPid = job->m_pid;

    if(kill(jPid, signum) == -1){
		cout << "signal number " << signum << " was sent to pid " << jPid << endl;
        perror("smash error: kill failed");
        return;
    }else {
		
        cout << "signal number " << signum << " was sent to pid " << jPid << endl;
    }
    freeArgs(args);
}
//////////////////////////////////////////////////////////////////////////////
////////////////////////// JobsList Methods //////////////////////////

void JobsList::addJob(Command* cmd, pid_t pid ,bool isBackground) {
    JobsList::update_max();
    shared_ptr<JobEntry> newJob = make_shared<JobEntry>(pid,this->m_maxJId,cmd->getCommandLine(),isBackground);
    this->jobs.push_back(newJob);
}
bool JobsList::jobIsTerminated(const shared_ptr<JobEntry> &job) {
    int jobStatus;
    if(waitpid(job->m_pid, &jobStatus , WNOHANG) >= 1) {
        return true;
    }
    return false;
}

void JobsList::removeFinishedJobs() {
    vector<shared_ptr<JobEntry>> newJobsList;
    int counter = 0;
    for(auto& job : this->jobs){
		
        if(!JobsList::jobIsTerminated(job) && job != nullptr) {
            newJobsList.push_back(job);
            counter = job->m_jId;
        }
    }
    
    this->jobs = newJobsList;
    this->m_maxJId = counter;

}

void JobsList::removeJobById(int jobId){
    int max = 0;
    std::vector<shared_ptr<JobEntry>>::iterator it = this->jobs.begin();
    while(it != this->jobs.end()) {


        if(it->get()->m_jId == jobId){
            this->jobs.erase(it);
            return;
        }else{
            if(it->get()->m_jId > max){
                max = it->get()->m_jId;
            }
        }
        it++;
    }
    this->m_maxJId = max;
}

shared_ptr<JobsList::JobEntry> JobsList::getJobById(int jobId) const {
    for(auto& job : this->jobs)
    {
        if(jobId == job->m_jId){
            return job;
        }
    }
    return nullptr;
}


void JobsList::printJobsList() {
    removeFinishedJobs();
    for(const auto& job : this->jobs) {
        std::cout << "[" <<job->m_jId << "]" << " " <<job->m_cmnd <<std::endl;
    }
}

shared_ptr<JobsList::JobEntry> JobsList::getLastJob(int *lastJobId){
    if(this->jobs.empty()) {
        *lastJobId = 0;
        return nullptr;
    }
    *lastJobId = this->jobs.back()->m_jId;
    return this->jobs.back();
}

void JobsList::killAllJobs(){
    removeFinishedJobs();
    cout << "smash: sending SIGKILL signal to " << this->jobs.size() << " jobs:" << endl;
    for(auto& job : jobs){
        cout << job->m_pid << ": " << job->m_cmnd << endl;
        if(kill(job->m_pid, SIGKILL)<0) {
			cerr << "smash error: kill failed" << endl;
		}
    }
}
//////////////////////////////////////////////////////////////////////////
////////////////////////// Alias ////////////////////////////////////////
void AliasCommand::execute() {
    SmallShell& shell = SmallShell::getInstance();
    char *args[COMMAND_MAX_ARGS];
    int i=0;
    while (i < COMMAND_MAX_ARGS){
        args[i] = nullptr;
        i++;
    }
     _parseCommandLine(getCommandLine(), args);
     

    if(args[1] == nullptr){
        if(shell.getAliases()->getMap().empty()){
            return;
        }else{
            const auto& map = shell.getAliases()->getMap();
            const auto& addedVec = shell.getAliases()->getAdded();
            for (const auto& key : addedVec) {
                auto it = map.find(key); // Use find() to ensure the key exists in dic.
                if (it != map.end()) {
                    cout << key << "='" << it->second << "'" << endl;
                }
            } return;
        }
    }
    string full_cmd = _trim(string(getCommandLine()));
    size_t cmd_start = full_cmd.find_first_not_of(WHITESPACE, 5); // 5 is the length of "alias"
    
    


    if(full_cmd.back()=='&') {
        full_cmd.pop_back();
    }
    full_cmd = full_cmd.substr(cmd_start);
    size_t eq_index = full_cmd.find('=');
    
    
 

    if (eq_index == string::npos || eq_index == 0 || eq_index == full_cmd.length() - 1) {
        cerr << "smash error: alias: invalid alias format" << endl;
        return;
    }
    string alias_name = _trim(full_cmd.substr(0, eq_index));
    string alias_command = _trim(full_cmd.substr(eq_index + 1));


    Alias_system* Alias = shell.getAliases();

    if (!regex_match(alias_name, std::regex("^[a-zA-Z0-9_]+$"))) {
        cerr << "smash error: alias: invalid alias format" << endl;
        return;
    }
 
    if (alias_command.back() == '\'' && alias_command.front() == '\'') {
        alias_command = alias_command.substr(1, alias_command.length() - 2);
    }
    Alias->addAlias(alias_name,alias_command);
    
}
////////////////////////////////////////////////////////////
//////////////////// UnAlias Command ///////////////////////
void UnAliasCommand::execute() {

   
    Alias_system* Alias = SmallShell::getInstance().getAliases();

    char* args[COMMAND_MAX_ARGS];
    int numOfArgs = _parseCommandLine(getCommandLine(), args);


    if (numOfArgs <= 1) {
        std::cerr << "smash error: unalias: not enough arguments" << std::endl;
        freeArgs(args);
        return;
    }

    for (int i = 1; i < numOfArgs; i++) {
        if (Alias->removeAlias(args[i])==0) {
            freeArgs(args);
            return;
        }
    }
    freeArgs(args);
}
//////////////////////////////// watchproc command///////////
bool WatchProcCommand::readFile(const std::string &path, std::string &out) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("smash error: open failed");
        return false;
    }
    out.clear();
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        out.append(buf, n);
    }
    if (n < 0) {
        perror("smash error: read failed");
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

bool WatchProcCommand::getTotalJiffies(unsigned long long &total) {
    std::string data;
    if (!readFile("/proc/stat", data)) return false;
    std::istringstream iss(data);
    std::string label;
    iss >> label;
    total = 0;
    unsigned long long x;
    while (iss >> x) total += x;
    return true;
}

bool WatchProcCommand::getUptimeSeconds(double &uptime) {
    std::string data;
    if (!readFile("/proc/uptime", data)) return false;
    std::istringstream iss(data);
    iss >> uptime;
    return true;
}

bool WatchProcCommand::getProcTimes(pid_t pid,
                                    unsigned long &utime,
                                    unsigned long &stime,
                                    unsigned long long &starttime)
{
    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::string data;
    if (!readFile(path, data)) return false;

    size_t p1 = data.find('('),
            p2 = data.rfind(')');
    if (p1 == std::string::npos || p2 == std::string::npos) return false;
    std::string rest = data.substr(p2 + 2);
    std::istringstream iss(rest);
    std::vector<std::string> fields;
    for (std::string f; iss >> f; )
        fields.push_back(f);
    if (fields.size() < 20) return false;

    utime     = std::stoul(fields[11]);
    stime     = std::stoul(fields[12]);
    starttime = std::stoull(fields[19]);
    return true;
}


bool WatchProcCommand::getProcRSS(pid_t pid, unsigned long &rss_kb) {
    std::string path = "/proc/" + std::to_string(pid) + "/status";
    std::string data;
    if (!readFile(path, data)) return false;

    std::istringstream iss(data);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            std::istringstream ls(line.substr(6));
            ls >> rss_kb;
            return true;
        }
    }
    rss_kb = 0;
    return true;
}

void WatchProcCommand::execute() {

    char *argv[COMMAND_MAX_ARGS] = { nullptr };
    int argc = _parseCommandLine(m_cmndLine, argv);

    if (argc != 2) {
        std::cerr << "smash error: watchproc: invalid arguments\n";
        freeArgs(argv);
        return;
    }


    std::string pidStr = argv[1];
    for (char c : pidStr) {
        if (!std::isdigit(c)) {
            std::cerr << "smash error: watchproc: invalid arguments\n";
            freeArgs(argv);
            return;
        }
    }
    pid_t pid = std::stoi(pidStr);

    struct stat sb;
    std::string procDir = "/proc/" + pidStr;
    if (stat(procDir.c_str(), &sb) < 0) {
        std::cerr << "smash error: watchproc: pid "
                  << pidStr << " does not exist\n";
        freeArgs(argv);
        return;
    }

    unsigned long long totalJ0;
    double uptimeSecs;
    unsigned long utime, stime;
    unsigned long long startJ;
    if (!getTotalJiffies(totalJ0) ||
        !getUptimeSeconds(uptimeSecs) ||
        !getProcTimes(pid, utime, stime, startJ))
    {
        std::cerr << "smash error: watchproc: pid "
                  << pidStr << " does not exist\n";
        freeArgs(argv);
        return;
    }

    long ticksPerSec = sysconf(_SC_CLK_TCK);
    double procTimeSec = double(utime + stime) / ticksPerSec;
    double startSec    = double(startJ) / ticksPerSec;
    double elapsed     = uptimeSecs - startSec;
    double cpuPct      = (elapsed > 0.0)
                         ? (100.0 * procTimeSec / elapsed)
                         : 0.0;

    unsigned long rss_kb;
    if (!getProcRSS(pid, rss_kb)) {
        std::cerr << "smash error: watchproc: pid "
                  << pidStr << " does not exist\n";
        freeArgs(argv);
        return;
    }
    double memMb = double(rss_kb) / 1024.0;


    std::cout << "PID: " << pidStr
              << " | CPU Usage: "
              << std::fixed << std::setprecision(1) << cpuPct << "%"
              << " | Memory Usage: "
              << std::fixed << std::setprecision(1) << memMb << " MB\n";

    freeArgs(argv);
}

////////////////////////////////////////////////////////////
//////////////////// UnSetEnv Command //////////////////////

void UnSetEnvCommand::execute() {
    char *argv[COMMAND_MAX_ARGS] = {nullptr};
    int argc = _parseCommandLine(m_cmndLine, argv);

    if (argc < 2) {
        writeErr("smash error: unsetenv: not enough arguments\n");
        freeArgs(argv);
        return;
    }

    for (int i = 1; i < argc; ++i) {
        const char *name = argv[i];
        size_t nlen = strlen(name);
        bool found = false;

        
        for (char **e = environ; *e; ++e) {
            if (strncmp(*e, name, nlen) == 0 && (*e)[nlen]=='=') {
                found = true;
                
                for (char **dst = e; *dst; ++dst) {
                    *dst = *(dst+1);
                }
                break;
            }
        }

        if (!found) {
            writeErr("smash error: unsetenv: ");
            writeErr(name);
            writeErr(" does not exist\n");
            freeArgs(argv);
            return;
        }
    }

    freeArgs(argv);
}
////////////////////////////////////////////////////////////
//////////////////// External Command ///////////////////////
void ExternalCommand::execute() {
    
    string cmdLine = _trim(m_cmndLine);


    if (cmdLine.back() == '&') {
        cmdLine.pop_back();
    }
    if (!is_complex) {
        char *args[COMMAND_MAX_ARGS];
        _parseCommandLine(cmdLine.c_str(), args);
        execvp(args[0], args);
    } else {
        execlp("/bin/bash", "bash", "-c", cmdLine.c_str(), nullptr);
        perror("smash error: execlp failed");
    }

    perror("smash error: execvp failed");
    exit(1);
}


////////////////////////////////////////////////////////////
//////////////////// special Commands //////////////////////
////////////////////////////////////////////////////////////
///////////////// IO redirection Command ///////////////////
bool parseCommand(const std::string& input, std::string& command, std::string& outputFile, bool& appendMode) {
    size_t redirectPos = input.find(">");
    if (redirectPos == std::string::npos) {
        
        command = input;
        return false;
    }

    
    appendMode = (input[redirectPos + 1] == '>');
    size_t outputFileStart = appendMode ? redirectPos + 2 : redirectPos + 1;

    
    command = input.substr(0, redirectPos);
    outputFile = input.substr(outputFileStart);

    
    outputFile.erase(0, outputFile.find_first_not_of(" \t"));
    outputFile.erase(outputFile.find_last_not_of(" \t") + 1);


    
    command.erase(command.find_last_not_of(" \t") + 1);

    return true;
}
RedirectionCommand::RedirectionCommand(const char *cmd_line) : Command(cmd_line){}

void RedirectionCommand::execute() {
    int split = 0;
    while (m_cmndLine[split] != '>') {
        split++;
    }
    int size = ((string) m_cmndLine).length();
    char cmdCopy[size]; // command
    char path[size];
    strcpy(cmdCopy, (((string) m_cmndLine).substr(0, split)).c_str());
    strcpy(path, (((string) m_cmndLine).substr(split + 1 + (m_cmndLine[split + 1] == '>'))).c_str());
    _removeBackgroundSign(path);
    strcpy(path, _trim(path).c_str());
    strcpy(cmdCopy, _trim(cmdCopy).c_str());
    pid_t pid = fork();
    if (pid == -1) {
        perror("smash error: fork failed");
        return;
    }
    if (pid == 0) { //son
        if (setpgrp() == -1) {
            perror("smash error: setpgrp failed");
            exit(1);
        }
        if (close(1) == -1) {
            perror("smash error: close failed");
            exit(0);
        }
        int fd_id = -1;
        if (m_cmndLine[split + 1] == '>') {
            fd_id = open(path, O_CREAT | O_WRONLY | O_APPEND, 0664);
            if (fd_id == -1) {
                perror("smash error: open failed");
                exit(0);
            }
        } else {
            fd_id = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0664);
            if (fd_id == -1) {
                perror("smash error: open failed");
                exit(0);
            }
        }
        SmallShell::getInstance().executeCommand(cmdCopy);
        exit(0);
    } else {
        if (waitpid(pid, NULL, WUNTRACED) == -1) {
            perror("smash error: waitpid failed");
            return;
        }
    }
}

////////////////////////////////////////////////////////////
////////////////////// Pipe Command ////////////////////////
PipeCommand::PipeCommand(const char *cmd_line) : Command(cmd_line) {
    string s(cmd_line);

    size_t pos = s.find('|');
    if (pos == string::npos) {

        writesToErr = false;
        writer     = _trim(s);
        reader.clear();
    } else {

        writesToErr = (pos + 1 < s.size() && s[pos+1] == '&');
        if (writesToErr) {

            writer = _trim(s.substr(0,      pos));
            reader = _trim(s.substr(pos + 2));
        } else {

            writer = _trim(s.substr(0,      pos));
            reader = _trim(s.substr(pos + 1));
        }
    }
}

void PipeCommand::execute() {

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("smash error: pipe failed");
        return;
    }


    pid_t pid1 = fork();
    if (pid1 < 0) {
        perror("smash error: fork failed");
        close(pipefd[0]); close(pipefd[1]);
        return;
    }
    if (pid1 == 0) {

        setpgrp();
        close(pipefd[0]);


        int target = writesToErr ? STDERR_FILENO : STDOUT_FILENO;
        dup2(pipefd[1], target);
        close(pipefd[1]);


        Command* c = SmallShell::getInstance().CreateCommand(writer.c_str());
        if (c) {
            c->execute();
            delete c;
        }
        _exit(0);
    }


    pid_t pid2 = fork();
    if (pid2 < 0) {
        perror("smash error: fork failed");
        close(pipefd[0]); close(pipefd[1]);
        return;
    }
    if (pid2 == 0) {

        setpgrp();
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);

        Command* c = SmallShell::getInstance().CreateCommand(reader.c_str());
        if (c) {
            c->execute();
            delete c;
        }
        _exit(0);
    }

    close(pipefd[0]);
    close(pipefd[1]);

    waitpid(pid1, nullptr, 0);
    waitpid(pid2, nullptr, 0);
}

////////////////////////////////////////////////////////////
/////////////////// DiskUsage Command //////////////////////
struct linux_dirent64 {
    ino64_t        d_ino;    
    off64_t        d_off;    
    unsigned short d_reclen; 
    unsigned char  d_type;   
    char           d_name[]; 
};

static bool lstatPath(const char *path, struct stat &st) {
    if (syscall(SYS_lstat, path, &st) < 0) {
        writeErr("smash error: lstat failed\n");
        return false;
    }
    return true;
}

long DiskUsageCommand::getBlocks(const std::string &path) {
    struct stat st;
    if (!lstatPath(path.c_str(), st)) return -1;
    long total = st.st_blocks;

    
    if (S_ISDIR(st.st_mode)) {
        int dir_fd = syscall(SYS_open, path.c_str(), O_RDONLY | O_DIRECTORY, 0);
        if (dir_fd < 0) {
            writeErr("smash error: open failed\n");
            return -1;
        }

        char buf[4096];
        while (true) {
            int nread = syscall(SYS_getdents64, dir_fd, buf, sizeof(buf));
            if (nread < 0) {
                writeErr("smash error: getdents64 failed\n");
                syscall(SYS_close, dir_fd);
                return -1;
            }
            if (nread == 0) break;

            int bpos = 0;
            while (bpos < nread) {
                struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + bpos);
                char *name = d->d_name;
                if (strcmp(name, ".") && strcmp(name, "..")) {
                    std::string child = path + "/" + name;
                    long cb = getBlocks(child);
                    if (cb < 0) {
                        syscall(SYS_close, dir_fd);
                        return -1;
                    }
                    total += cb;
                }
                bpos += d->d_reclen;
            }
        }
        syscall(SYS_close, dir_fd);
    }

    return total;
}

void DiskUsageCommand::execute() {

    char *args[COMMAND_MAX_ARGS] = {nullptr};
    int argc = _parseCommandLine(m_cmndLine, args);

    if (argc > 2) {
        writeErr("smash error: du: too many arguments\n");
        freeArgs(args);
        return;
    }


    std::string dir = (argc == 2 ? args[1] : ".");
    

    struct stat st;
    if (!lstatPath(dir.c_str(), st) || !S_ISDIR(st.st_mode)) {
        writeErr(("smash error: du: directory " + dir + " does not exist\n").c_str());
        freeArgs(args);
        return;
    }


    long blocks = getBlocks(dir);
    if (blocks < 0) {
        freeArgs(args);
        return;
    }


    long kb = (blocks * 512 + 1023) / 1024;


    std::string out = "Total disk usage: " + std::to_string(kb) + " KB\n";
    syscall(SYS_write, STDOUT_FILENO, out.c_str(), out.size());


    freeArgs(args);
}

////////////////////////////////////////////////////////////
///////////////////// WhoAmI Command ///////////////////////
void WhoAmICommand::execute() {
    char *argv[COMMAND_MAX_ARGS] = {nullptr};
     _parseCommandLine(m_cmndLine, argv);

    uid_t uid = syscall(SYS_getuid);

    
    std::string passwd;
    if (!readAll("/etc/passwd", passwd)) {
        freeArgs(argv);
        return;
    }

    string line, username, homedir;
    istringstream iss(passwd);
    
    bool found = false;
    while (std::getline(iss, line)) {
        
        size_t p1 = line.find(':'), p2, p3, p4, p5, p6;
        if (p1==std::string::npos) continue;
        p2 = line.find(':', p1+1);
        p3 = line.find(':', p2+1);
        p4 = line.find(':', p3+1);
        p5 = line.find(':', p4+1);
        p6 = line.find(':', p5+1);
        if (p1==std::string::npos||p2==std::string::npos||p3==std::string::npos
            ||p4==std::string::npos||p5==std::string::npos) continue;

       
        int file_uid = std::stoi(line.substr(p2+1, p3-p2-1));
        if ((uid_t)file_uid == uid) {
            username = line.substr(0, p1);
            homedir  = line.substr(p5+1,
                                   (p6==std::string::npos? line.size(): p6) - (p5+1));
            found = true;
            break;
        }
    }

    if (!found) {
        writeErr("smash error: whoami: cannot retrieve user info\n");
        freeArgs(argv);
        return;
    }

   
    std::string out = username + " " + homedir + "\n";
    syscall(SYS_write, STDOUT_FILENO, out.c_str(), out.size());

    freeArgs(argv);
}
////////////////////////////////////////////////////////////
///////////////////// NetInfo Command //////////////////////
static std::string formatIP(uint32_t addr) {
    return std::to_string((addr >> 24) & 0xFF) + "." +
           std::to_string((addr >> 16) & 0xFF) + "." +
           std::to_string((addr >>  8) & 0xFF) + "." +
           std::to_string((addr      ) & 0xFF);
}

// Fetch address & mask for an interface via raw socket+ioctl
static bool retrieveInterfaceInfo(const std::string &iface,
                                  std::string &outIp,
                                  std::string &outMask)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return false;
    }

    struct ifreq req;
    std::memset(&req, 0, sizeof(req));
    std::strncpy(req.ifr_name, iface.c_str(), IFNAMSIZ-1);

    // IPv4 address
    if (ioctl(s, SIOCGIFADDR, &req) == 0) {
        auto *sin = reinterpret_cast<struct sockaddr_in*>(&req.ifr_addr);
        uint32_t h = ntohl(sin->sin_addr.s_addr);
        outIp = formatIP(h);
    } else {
        close(s);
        return false;
    }

    // Subnet mask
    if (ioctl(s, SIOCGIFNETMASK, &req) == 0) {
        auto *sin = reinterpret_cast<struct sockaddr_in*>(&req.ifr_netmask);
        uint32_t h = ntohl(sin->sin_addr.s_addr);
        outMask = formatIP(h);
    } else {
        close(s);
        return false;
    }

    close(s);
    return true;
}

// Read an entire file into a string
static bool readAll(const char *path, std::string &dest) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return false;
    }
    dest.clear();
    std::array<char, 4096> buf;
    while (true) {
        ssize_t r = read(fd, buf.data(), buf.size());
        if (r < 0) {
            perror("read");
            close(fd);
            return false;
        }
        if (r == 0) break;
        dest.append(buf.data(), r);
    }
    close(fd);
    return true;
}

// Parse /proc/net/route for the default gateway on iface
static std::string fetchDefaultGateway(const std::string &iface) {
    std::string text;
    if (!readAll("/proc/net/route", text)) return "N/A";

    std::istringstream lines(text);
    std::string line;
    // Skip header
    std::getline(lines, line);

    while (std::getline(lines, line)) {
        std::istringstream L(line);
        std::string name, dest, gw, flags;
        if (!(L >> name >> dest >> gw >> flags)) continue;
        if (name == iface && dest == "00000000") {
            // gw is hex little-endian (e.g. "0100A8C0")
            uint32_t x = std::stoul(gw, nullptr, 16);
            uint32_t host = ((x & 0xFF) << 24)
                            | ((x & 0xFF00) << 8)
                            | ((x & 0xFF0000) >> 8)
                            | ((x & 0xFF000000) >> 24);
            return formatIP(host);
        }
    }
    return "N/A";
}

// Parse /etc/resolv.conf for nameserver lines
static std::vector<std::string> parseDNSServers() {
    std::string text;
    if (!readAll("/etc/resolv.conf", text)) return {};

    std::vector<std::string> out;
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.rfind("nameserver", 0) == 0) {
            std::istringstream L(line);
            std::string tag, ip;
            if (L >> tag >> ip) out.push_back(ip);
        }
    }
    return out;
}

NetInfo::NetInfo(const char *cmd_line)
        : Command(cmd_line)
{}

void NetInfo::execute() {
    // 1) Split the command line
    char *argv[COMMAND_MAX_ARGS] = {nullptr};
    for (int i = 0; i < COMMAND_MAX_ARGS; ++i) argv[i] = nullptr;
    _parseCommandLine(m_cmndLine.c_str(), argv);

    // 2) Must have an interface name
    if (!argv[1]) {
        std::cerr << "smash error: netinfo: interface not specified\n";
        return;
    }
    std::string iface = argv[1];

    // 3) Get IP + mask
    std::string ip, mask;
    if (!retrieveInterfaceInfo(iface, ip, mask)) {
        std::cerr << "smash error: netinfo: interface "
                  << iface << " does not exist\n";
        return;
    }

    // 4) Default gateway
    std::string gw = fetchDefaultGateway(iface);

    // 5) DNS servers
    auto dns = parseDNSServers();
    std::string dnsStr = "N/A";
    if (!dns.empty()) {
        dnsStr.clear();
        for (size_t i = 0; i < dns.size(); ++i) {
            if (i) dnsStr += ", ";
            dnsStr += dns[i];
        }
    }

    // 6) Print results
    std::cout << "IP Address: "      << ip   << "\n"
              << "Subnet Mask: "     << mask << "\n"
              << "Default Gateway: " << gw   << "\n"
              << "DNS Servers: "     << dnsStr << "\n";
}



SmallShell::SmallShell() : m_jobs(new JobsList()),
m_aliasSystem(new Alias_system()), m_curr_cmndLine(""), m_prompt("smash"){
    char buf[COMMAND_MAX_LENGTH];
    if (getcwd(buf, sizeof(buf))) {
        currDir_ = buf;
    } else {
        perror("smash error: getcwd failed");
        currDir_.clear();
    }
    prevDir_.clear();
    m_curr_jid = -1;
    m_curr_pid = -1;
    }


/**
* Creates and returns a pointer to Command class which matches the given command line (cmd_line)
*/
Command *SmallShell::CreateCommand(const char *cmd_line) {
	SmallShell& shell = SmallShell::getInstance();
    string checkIfEmpty = (string) cmd_line;
    if (checkIfEmpty.empty()) {
        return nullptr;
    }
    char **splitInput = new char *[20];
    int numOfWords;
    numOfWords = _parseCommandLine(cmd_line, splitInput);
    string cmd = _trim(splitInput[0]);
    string prompt;
    Alias_system* Alias = shell.getAliases();
    const auto& map = Alias->getMap();
    string cmd_s = _trim(string(cmd_line));
    string firstWord = cmd_s.substr(0, cmd_s.find_first_of(" \n"));
    if(cmd_s.empty()){
        return nullptr;
    }
    for(const auto& alias : map){
        if(firstWord == alias.first){
            cmd = alias.second;
        }
    }
    if (numOfWords > 1) {
        prompt = (string) splitInput[1];
    }
    delete[] splitInput;
       if(cmd.compare("whoami") == 0 ) {
        return new WhoAmICommand(cmd_line);
    }
    if(cmd.compare("netinfo") == 0 ) {
        return new NetInfo(cmd_line);
    }
    if(cmd.compare("du") == 0 ) {
        return new DiskUsageCommand(cmd_line);
    }
    if (((string) cmd_line).find("|") != string::npos) {
        return new PipeCommand(cmd_line);
    } else if (((string) cmd_line).find(">") != string::npos) {
        return new RedirectionCommand(cmd_line);
    } else if (cmd.compare("chprompt") == 0) {
        if (numOfWords == 1) {
            getInstance().setPrompt("smash");
            return nullptr;
        }
        setPrompt(prompt);
        return nullptr;
    } else if (cmd.compare("showpid") == 0 || cmd.compare("showpid&") == 0) {
        return new ShowPidCommand(cmd_line);

    }else if (cmd.compare("pwd") == 0 || cmd.compare("pwd&") == 0) {
        return new GetCurrDirCommand(cmd_line);

    } else if (cmd.compare("cd") == 0 || cmd.compare("cd&") == 0) {
        return new ChangeDirCommand(cmd_line);

    } else if (cmd.compare("jobs") == 0 || cmd.compare("jobs&") == 0) {
        return new JobsCommand(cmd_line, shell.getJobs());

    } else if (cmd.compare("fg") == 0 || cmd.compare("fg&") == 0) {
        return new ForegroundCommand(cmd_line, shell.getJobs());

    }else if (cmd.compare("quit") == 0 || cmd.compare("quit&") == 0) {
        return new QuitCommand(cmd_line, shell.getJobs());

    }else if (cmd.compare("kill") == 0 || cmd.compare("kill&") == 0) {
        return new KillCommand(cmd_line, shell.getJobs());
    }
    else if (cmd.compare("alias") == 0 || cmd.compare("alias&") == 0) {
        return new AliasCommand(cmd_line);

    }else if (cmd.compare("unalias") == 0 || cmd.compare("unalias&") == 0) {
        return new UnAliasCommand(cmd_line);

    }else if (cmd.compare("unsetenv") == 0 || cmd.compare("unsetenv&") == 0) {
        return new UnSetEnvCommand(cmd_line);

    }else if (cmd.compare("watchproc") == 0 || cmd.compare("watchproc&") == 0) {
        return new WatchProcCommand(cmd_line);

    }
    else {
        return new ExternalCommand(cmd_line);
    }
    return nullptr;
}


void SmallShell::executeCommand(const char *cmd_line) {
    SmallShell& shell = SmallShell::getInstance();
    JobsList* jobs = shell.getJobs();
    if(!jobs->getJobsList().empty())
    {
        jobs->removeFinishedJobs();
    }

    Command* cmd = CreateCommand(cmd_line);

    const char* commandLine = cmd_line;

    bool isBg = _isBackgroundComamnd(commandLine);

    ExternalCommand* exCmd = dynamic_cast<ExternalCommand*>(cmd);
    BuiltInCommand* builtInCmd = dynamic_cast<BuiltInCommand*>(cmd);

    if (cmd) {
          
        if (builtInCmd != nullptr) {
            builtInCmd->execute();
        }
        
        else if(exCmd){
            if (!isBg  || exCmd->is_complex) {
			
                pid_t pid = fork();
                if (pid == 0) { // Child process
                    setpgrp();
                    cmd->execute();
                    exit(0);
                }else if (pid > 0) { // Parent process
                    shell.setCurrJobPid(pid);
                    int status;
                    waitpid(pid, &status, WUNTRACED);
                    shell.setCurrJobPid(-1);
                } else {
                    perror("smash error: fork failed");
                }
            } else {

                pid_t pid = fork();
                if (pid == 0) {
                    setpgrp();
                    cmd->execute();
                    exit(0);
                } else if (pid > 0) {
                    jobs->addJob(cmd ,pid);
                } else {
                    perror("smash error: fork failed");
                }
            }
        }else{
			cmd->execute();
		}
      
    }
    if (cmd) {
        delete cmd;
    }
    jobs->removeFinishedJobs();

}
