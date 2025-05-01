#include <unistd.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <sys/wait.h>
#include <sys/kill.h>
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

static string intToIP(uint32_t x) {
    std::ostringstream oss;
    oss << ((x >> 24) & 0xFF) << "."
        << ((x >> 16) & 0xFF) << "."
        << ((x >> 8 ) & 0xFF) << "."
        << ( x        & 0xFF);
    return oss.str();
}

static bool fetchInterface(const string &iface,string &outIP,string &outMask) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    // IP address
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    {
        auto *sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
        outIP = inet_ntoa(sin->sin_addr);
    }

    // Subnet mask
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
        close(sock);
        return false;
    }
    {
        auto *sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
        outMask = inet_ntoa(sin->sin_addr);
    }

    close(sock);
    return true;
}

static string fetchGateway(const string &iface) {
    int fd = open("/proc/net/route", O_RDONLY);
    if (fd < 0) return "N/A";

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return "N/A";
    buf[n] = '\0';

    for (char *line = strtok(buf, "\n"); line; line = strtok(nullptr, "\n")) {
        char name[IFNAMSIZ], dest[9], gw[9];
        if (sscanf(line, "%s %8s %8s", name, dest, gw) == 3) {
            if (iface == name && strcmp(dest, "00000000") == 0) {
                uint32_t g; sscanf(gw, "%x", &g);
                return intToIP(g);
            }
        }
    }
    return "N/A";
}


static vector<string> fetchDNSServers() {
    int fd = open("/etc/resolv.conf", O_RDONLY);
    if (fd < 0) return {};
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return {};
    buf[n] = '\0';

    vector<string> out;
    for (char *line = strtok(buf, "\n"); line; line = strtok(nullptr, "\n")) {
        if (strncmp(line, "nameserver", 10) == 0) {
            char ip[64];
            if (sscanf(line, "nameserver %63s", ip) == 1) {
                out.emplace_back(ip);
            }
        }
    }
    return out;
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
    char *args[COMMAND_MAX_ARGS];
    int i=0;
    while (i<COMMAND_MAX_ARGS){
        args[i] = nullptr;
        i++;
    }
    _parseCommandLine(getCommandLine(), args);

    char currentWD[COMMAND_MAX_LENGTH];
    getcwd(currentWD , COMMAND_MAX_LENGTH);

    if(args[2] != nullptr) {
        fprintf(stderr , "smash error: cd: too many arguments\n");
        freeArgs(args);
        return;
    }

    if(!strcmp(args[1] , "-") && args[1]) {
        if(SmallShell::getInstance().getPrevDir() == "") {
            fprintf(stderr , "smash error: cd: OLDPWD not set\n");
        }else{
            if(!chdir(SmallShell::getInstance().getPrevDir())) {
                SmallShell::getInstance().setCurrDir(SmallShell::getInstance().getPrevDir());
                SmallShell::getInstance().setPrevDir(currentWD);
            }else {
                perror("smash error: chdir failed");
            }
        }
    }else {
        if(chdir(args[1])) {
            perror("smash error: chdir failed");
        }else {
            SmallShell::getInstance().setPrevDir(currentWD);
        }
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
        int *lastJobId = nullptr;
        shared_ptr<JobsList::JobEntry> maxIdJob = shell.getJobs()->getLastJob(lastJobId);
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
    }
    if(numOfArgs >= 3){
        std::cerr << "smash error: fg: invalid arguments" << std::endl;
        freeArgs(args);
        return;
    }
    if (args[1]) {
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
    if (strcmp(args[1], "kill") == 0 && numOfArgs>= 2) {
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
    char *args[COMMAND_MAX_ARGS];
    int i=0;
    while (i < COMMAND_MAX_ARGS){
        args[i] = nullptr;
        i++;
    }
    int numOfArgs = _parseCommandLine(getCommandLine(), args);
    if(numOfArgs != 3 || isdigit(args[1][1]) == 0 || args[1][0] != '-' || isdigit(args[2][0]) == 0){
        fprintf(stderr, "smash error: kill: invalid arguments\n");
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
    if(waitpid(job->m_jId, &jobStatus , WNOHANG) >= 1) {
        return true;
    }
    return false;
}

void JobsList::removeFinishedJobs() {
    vector<shared_ptr<JobEntry>> newJobsList;
    for(const auto& job : this->jobs){
        if(!jobIsTerminated(job)) {
            newJobsList.push_back(job);
        }
    }
    this->jobs = newJobsList;

}

void JobsList::removeJobById(int jobId){
    int max = 0;
    std::vector<shared_ptr<JobEntry>>::iterator it = this->jobs.begin();
    while(it != this->jobs.end()) {


        if(it->get()->m_jId == jobId){
            this->jobs.erase(it);
        }else{
            if(it->get()->m_jId > max){
                max = it->get()->m_jId;
            }
        }
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
    cout << "smash: sending SIGKILL signal to" << this->jobs.size() << " jobs:" << endl;
    for(auto& job : jobs){
        cout << job->m_pid << ": " << job->m_cmnd << endl;
        DO_SYS(kill(job->m_pid, SIGKILL, kill));
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
    int numOfArgs = _parseCommandLine(getCommandLine(), args);

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
            }
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
    if (Alias->m_og.count(alias_name) > 0 || Alias->getMap().count(alias_name) > 0) {
        std::cout << "smash error: alias: " << alias_name
                  << " already exists or is a reserved command" << std::endl;
        return;
    }
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

    SmallShell &shell = SmallShell::getInstance();
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

    char *argv[COMMAND_MAX_ARGS] = { nullptr };
    int argc = _parseCommandLine(m_cmndLine, argv);


    if (argc < 2) {
        std::cerr << "smash error: unsetenv: not enough arguments\n";
        freeArgs(argv);
        return;
    }


    for (int i = 1; i < argc; ++i) {
        std::string var = argv[i];


        if (getenv(var.c_str()) == nullptr) {
            std::cerr << "smash error: unsetenv: "
                      << var << " does not exist\n";
            freeArgs(argv);
            return;
        }


        if (unsetenv(var.c_str()) != 0) {
            perror("smash error: unsetenv failed");
            freeArgs(argv);
            return;
        }
    }


    freeArgs(argv);
}
////////////////////////////////////////////////////////////
//////////////////// External Command ///////////////////////
void ExternalCommand::execute() {
    SmallShell &shell = SmallShell::getInstance();
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
RedirectionCommand::RedirectionCommand(const char *cmd_line)
        : Command(cmd_line)
{

    string input(cmd_line);

    size_t redirectPos = input.find('>');
    if (redirectPos == string::npos) {

        m_cmnd  = _trim(input);
        m_fName.clear();
        m_type  = false;
    }
    else {
        m_type = (redirectPos + 1 < input.size() && input[redirectPos + 1] == '>');


        size_t fileStart = redirectPos + (m_type ? 2 : 1);

        // Extract raw command and filename parts
        m_cmnd  = input.substr(0, redirectPos);
        m_fName = input.substr(fileStart);


        m_cmnd  = _trim(m_cmnd);
        m_fName = _trim(m_fName);
    }
}

void RedirectionCommand::execute() {

    int stdout_copy = dup(STDOUT_FILENO);
    if (stdout_copy == -1) {
        perror("smash error: dup failed");
        return;
    }


    string outFile = m_fName;
    if (!outFile.empty() && outFile.back() == '&') {
        outFile.pop_back();
    }


    int flags = O_WRONLY | O_CREAT | (m_type ? O_APPEND : O_TRUNC);
    int file_fd = open(outFile.c_str(), flags, 0644);
    if (file_fd == -1) {
        perror("smash error: open failed");

        dup2(stdout_copy, STDOUT_FILENO);
        close(stdout_copy);
        return;
    }

    // 4) Redirect stdout → file_fd
    if (dup2(file_fd, STDOUT_FILENO) == -1) {
        perror("smash error: dup2 failed");
        close(file_fd);
        dup2(stdout_copy, STDOUT_FILENO);
        close(stdout_copy);
        return;
    }
    close(file_fd);


    Command* cmd = SmallShell::getInstance().CreateCommand(m_cmnd.c_str());
    if (cmd) {
        cmd->execute();
        delete cmd;
    }


    if (dup2(stdout_copy, STDOUT_FILENO) == -1) {
        perror("smash error: dup2 failed");
    }
    close(stdout_copy);
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

        // redirect stdin ← read end of pipe
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);

        // execute the right command
        Command* c = SmallShell::getInstance().CreateCommand(reader.c_str());
        if (c) {
            c->execute();
            delete c;
        }
        _exit(0);
    }

    // 4) parent closes both ends and waits
    close(pipefd[0]);
    close(pipefd[1]);

    waitpid(pid1, nullptr, 0);
    waitpid(pid2, nullptr, 0);
}

////////////////////////////////////////////////////////////
/////////////////// DiskUsage Command //////////////////////
long DiskUsageCommand::getBlocks(const std::string &path) {
    struct stat sb;
    if (lstat(path.c_str(), &sb) < 0) {
        perror("smash error: lstat failed");
       return -1;
    }

    long total = sb.st_blocks;

    if (S_ISDIR(sb.st_mode)) {
        DIR *dir = opendir(path.c_str());
      if (!dir) {
            perror("smash error: opendir failed");
            return -1;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr) {
            const char *name = entry->d_name;
            // skip "." and ".."
            if (name[0] == '.' &&
               (name[1] == '\0' ||
               (name[1] == '.' && name[2] == '\0')))
            {
                continue;
            }

            std::string child = path + "/" + name;
            long cb = getBlocks(child);
            if (cb < 0) {
                closedir(dir);
                return -1;    // propagate failure
            }
            total += cb;
        }
        closedir(dir);
    }

    return total;
}

void DiskUsageCommand::execute() {

    char *args[COMMAND_MAX_ARGS];
    for (int i = 0; i < COMMAND_MAX_ARGS; ++i)
        args[i] = nullptr;
    int numArgs = _parseCommandLine(getCommandLine(), args);

    // 2) Too many arguments?
    if (numArgs > 2) {
        std::cerr << "smash error: du: too many arguments\n";
        // free allocated args
        for (int i = 0; i < numArgs; ++i) free(args[i]);
        return;
    }

    string dir = (numArgs == 2 ? args[1] : ".");

    struct stat sb;
    if (stat(dir.c_str(), &sb) < 0) {
        if (errno == ENOENT) {
            std::cerr << "smash error: du: directory "
                      << dir << " does not exist\n";
        } else {
            perror("smash error: stat failed");
        }
        for (int i = 0; i < numArgs; ++i) free(args[i]);
        return;
    }
    if (!S_ISDIR(sb.st_mode)) {
        std::cerr << "smash error: du: directory "
                  << dir << " does not exist\n";
        for (int i = 0; i < numArgs; ++i) free(args[i]);
        return;
    }


    long blocks = getBlocks(dir);
    // getBlocks already called perror on failure
    if (blocks < 0) {
        for (int i = 0; i < numArgs; ++i) free(args[i]);
        return;
    }
    long kb = (blocks * 512 + 1023) / 1024;
    std::cout << "Total disk usage: "
              << kb
              << " KB\n";

    // 8) Free allocated args
    for (int i = 0; i < numArgs; ++i)
        free(args[i]);
}

////////////////////////////////////////////////////////////
///////////////////// WhoAmI Command ///////////////////////
void WhoAmICommand::execute() {
    std::istringstream iss(m_cmndLine);
    string tok;
    iss >> tok;

    uid_t uid = getuid();
    struct passwd* pw = getpwuid(uid);
    if (!pw) {
        cerr << "smash error: whoami: cannot retrieve user info\n";
        return;
    }

    cout << pw->pw_name << " " << pw->pw_dir << "\n";
}
////////////////////////////////////////////////////////////
///////////////////// NetInfo Command //////////////////////
void NetInfo::execute() {
    // 1) Parse arguments
    std::istringstream iss(m_cmndLine);
    std::vector<std::string> args;
    for (std::string tok; iss >> tok; )
        args.push_back(tok);

    if (args.size() < 2) {
        std::cerr << "smash error: netinfo: interface not specified\n";
        return;
    }
    const std::string iface = args[1];

    // 2) Get IP & mask
    std::string ip, mask;
    if (!fetchInterface(iface, ip, mask)) {
        std::cerr << "smash error: netinfo: interface "
                  << iface << " does not exist\n";
        return;
    }

    // 3) Get gateway
    std::string gateway = fetchGateway(iface);

    // 4) Get DNS servers
    auto dns = fetchDNSServers();
    std::string dnsStr = dns.empty() ? "N/A" : "";
    for (size_t i = 0; i < dns.size(); ++i) {
        dnsStr += dns[i];
        if (i + 1 < dns.size()) dnsStr += ", ";
    }

    // 5) Print
    std::cout << "IP Address: "    << ip       << "\n"
              << "Subnet Mask: "   << mask     << "\n"
              << "Default Gateway: " << gateway << "\n"
              << "DNS Servers: "   << dnsStr   << "\n";
}






/**
* Creates and returns a pointer to Command class which matches the given command line (cmd_line)
*/
Command *SmallShell::CreateCommand(const char *cmd_line) {
    // For example:
    char *args[COMMAND_MAX_ARGS];
    int i=0;
    while (i < COMMAND_MAX_ARGS){
        args[i] = nullptr;
        i++;
    }
    int numOfArgs = _parseCommandLine(cmd_line, args);

    SmallShell &shell = SmallShell::getInstance();
    Alias_system* Alias = shell.getAliases();
    const auto& map = Alias->getMap();
    string cmd_s = _trim(string(cmd_line));
    string firstWord = cmd_s.substr(0, cmd_s.find_first_of(" \n"));
    if(cmd_s.empty()){
        return nullptr;
    }
    for(const auto& alias : map){
        if(firstWord == alias.first){
            firstWord = alias.second;
        }
    }

    if(firstWord.compare("whoami") == 0 ) {
        return new WhoAmICommand(cmd_line);
    }
    if(firstWord.compare("netinfo") == 0 ) {
        return new NetInfo(cmd_line);
    }
    if(firstWord.compare("du") == 0 ) {
        return new DiskUsageCommand(cmd_line);
    }

    if (cmd_s.find('|') != string::npos) {
        return new PipeCommand(cmd_line);
    }
    if (cmd_s.find('>') != string::npos) {
        return new RedirectionCommand(cmd_line);
    }

    if (firstWord.compare("chprompt") == 0 || firstWord.compare("chprompt&") == 0) {
        return new chpromptCommand(cmd_line);

    } else if (firstWord.compare("showpid") == 0 || firstWord.compare("showpid&") == 0) {
        return new ShowPidCommand(cmd_line);

    }else if (firstWord.compare("pwd") == 0 || firstWord.compare("pwd&") == 0) {
        return new GetCurrDirCommand(cmd_line);

    } else if (firstWord.compare("cd") == 0 || firstWord.compare("cd&") == 0) {
        return new ChangeDirCommand(cmd_line);

    } else if (firstWord.compare("jobs") == 0 || firstWord.compare("jobs&") == 0) {
        return new JobsCommand(cmd_line, shell.getJobs());

    } else if (firstWord.compare("fg") == 0 || firstWord.compare("fg&") == 0) {
        return new ForegroundCommand(cmd_line, shell.getJobs());

    }else if (firstWord.compare("quit") == 0 || firstWord.compare("quit&") == 0) {
        return new QuitCommand(cmd_line, shell.getJobs());

    }else if (firstWord.compare("kill") == 0 || firstWord.compare("kill&") == 0) {
        return new KillCommand(cmd_line, shell.getJobs());
    }
    else if (firstWord.compare("alias") == 0 || firstWord.compare("alias&") == 0) {
        return new AliasCommand(cmd_line);

    }else if (firstWord.compare("unalias") == 0 || firstWord.compare("unalias&") == 0) {
        return new UnAliasCommand(cmd_line);

    }else if (firstWord.compare("unsetenv") == 0 || firstWord.compare("unsetenv&") == 0) {
        return new UnSetEnvCommand(cmd_line);

    }else if (firstWord.compare("watchproc") == 0 || firstWord.compare("watchproc&") == 0) {
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

    const char* commandLine = m_curr_cmndLine.c_str();

    bool isBg = _isBackgroundComamnd(commandLine);

    if (cmd) {
        BuiltInCommand* builtInCmd = dynamic_cast<BuiltInCommand*>(cmd);
        if (builtInCmd) {
            builtInCmd->execute();
        }
        ExternalCommand* exCmd = dynamic_cast<ExternalCommand*>(cmd);
        if(exCmd){
            if (!isBg || exCmd->is_complex) {
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
        }
    }
    if (cmd) {
        delete cmd;
    }
    jobs->removeFinishedJobs();

}