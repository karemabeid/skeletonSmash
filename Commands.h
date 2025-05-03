// Ver: 10-4-2025
#ifndef SMASH_COMMAND_H_
#define SMASH_COMMAND_H_

#include <cstdlib>    // for free()
#include <signal.h>
#include <regex>
#include <vector>
#include <utility>
#include <map>
#include <set>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cerrno>
#include <limits.h>
#include <typeinfo>
#include <fcntl.h>
#include <cstring>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>





using namespace std;
#define COMMAND_MAX_LENGTH (200)
#define COMMAND_MAX_ARGS (20)

class Command {
    // TODO: Add your data members
public:
    const char * m_cmndLine;
    bool m_isBg;
    Command(const char *cmd_line) : m_cmndLine(cmd_line){}

    virtual ~Command() = default;

    virtual void execute() = 0;

    //virtual void prepare();
    //virtual void cleanup();
    // TODO: Add your extra methods if needed
    const char * getCommandLine() const {
        return m_cmndLine;
    }
};

class BuiltInCommand : public Command {
public:
    BuiltInCommand(const char *cmd_line) : Command(cmd_line){}

    virtual ~BuiltInCommand() {
    }
};

class ExternalCommand : public Command {
public:
    bool is_complex;
    ExternalCommand(const char *cmd_line) : Command(cmd_line), is_complex(false){
        string cmd = string(cmd_line);
        if(cmd.find('*') != string::npos  || cmd.find('?') != string::npos){
            is_complex = true;
        }
    }
    virtual ~ExternalCommand() {
    }

    void execute() override;
};


class RedirectionCommand : public Command {
    // TODO: Add your data members
    bool m_type;
    string m_cmnd;
    string m_fName;

public:
    explicit RedirectionCommand(const char *cmd_line);

    virtual ~RedirectionCommand() {
    }

    void execute() override;
};

class PipeCommand : public Command {
    // TODO: Add your data members
private:
    bool writesToErr;
    string writer;
    string reader;
public:
    PipeCommand(const char *cmd_line);

    virtual ~PipeCommand() {
    }

    void execute() override;
};


class DiskUsageCommand : public Command {
public:
    DiskUsageCommand(const char *cmd_line)
            : Command(cmd_line)
    {}

    virtual ~DiskUsageCommand() = default;

    void execute() override;
private:
    static long getBlocks(const std::string &path);
};

class WhoAmICommand : public Command {
public:
    WhoAmICommand(const char *cmd_line) : Command(cmd_line){}

    virtual ~WhoAmICommand() {
    }

    void execute() override;
};

class NetInfo : public Command {
    // TODO: Add your data members **BONUS: 10 Points**
    
public:
    NetInfo(const char *cmd_line);

    virtual ~NetInfo() {
    }

    void execute() override;
};

class chpromptCommand : public BuiltInCommand {

private:
    std::string m_prompt;
public:
    chpromptCommand(const char * cmd_line): BuiltInCommand(cmd_line){}

    ///get back after small-Shell
    void execute() override;
    virtual  ~chpromptCommand() {}

};

class ChangeDirCommand : public BuiltInCommand {
public:
    char **plastPwd;
    // TODO: Add your data members public:
    ChangeDirCommand(const char *cmd_line,char **dir_arr) : BuiltInCommand(cmd_line),plastPwd(dir_arr){}

    virtual ~ChangeDirCommand() {
    }

    void execute() override;
};

class GetCurrDirCommand : public BuiltInCommand {
public:
    GetCurrDirCommand(const char *cmd_line) : BuiltInCommand(cmd_line){}

    virtual ~GetCurrDirCommand() {
    }

    void execute() override;
};

class ShowPidCommand : public BuiltInCommand {
public:
    ShowPidCommand(const char *cmd_line) : BuiltInCommand(cmd_line){}


    virtual ~ShowPidCommand() {
    }

    void execute() override;
};

class JobsList;

class QuitCommand : public BuiltInCommand {
private:
    JobsList* m_jobs;
    // TODO: Add your data members public:
public:
    QuitCommand(const char *cmd_line, JobsList *jobs) : BuiltInCommand(cmd_line), m_jobs(jobs){}

    virtual ~QuitCommand() {
    }

    void execute() override;
};


class JobsList {
public:
    class JobEntry {
        // TODO: Add your data members
    public:
        int m_pid;
        int m_jId;
        bool m_isBg;
        const string m_cmnd;
        JobEntry(int pid, int jobId, string cmnd, bool isBackground = false) : m_pid(pid),
        m_jId(jobId), m_isBg(isBackground), m_cmnd(cmnd){}

    };

    // TODO: Add your data members
private:
    int m_maxJId;
    std::vector<shared_ptr<JobEntry>> jobs;
    JobEntry *lastStopped;


public:
    JobsList() : m_maxJId(0){}

    ~JobsList() = default;

    void addJob(Command *cmd, pid_t pid , bool isBackground = false);

    void printJobsList();

    void killAllJobs();

    void removeFinishedJobs();

    shared_ptr<JobEntry> getJobById(int jobId) const;

    void removeJobById(int jobId);

    shared_ptr<JobEntry> getLastJob(int *lastJobId);

    JobEntry *getLastStoppedJob(int *jobId);

    // TODO: Add extra methods or modify exisitng ones as needed
    void update_max(){
        m_maxJId++;
    }
    bool jobIsTerminated(const shared_ptr<JobEntry> &);

    std::vector<shared_ptr<JobEntry>> getJobsList() const{
        return jobs;
    }

};

class JobsCommand : public BuiltInCommand {
    // TODO: Add your data members
private:
    JobsList* m_jobs;
public:
    JobsCommand(const char *cmd_line, JobsList *jobs) : BuiltInCommand(cmd_line), m_jobs(jobs){}

    virtual ~JobsCommand() {
    }

    void execute() override;
};

class KillCommand : public BuiltInCommand {
    // TODO: Add your data members
private:
    JobsList* m_jobs;
public:
    KillCommand(const char *cmd_line, JobsList *jobs) : BuiltInCommand(cmd_line), m_jobs(jobs){}

    virtual ~KillCommand() {
    }

    void execute() override;
};

class ForegroundCommand : public BuiltInCommand {
    // TODO: Add your data members
private:
    JobsList* m_jobs;
public:
    ForegroundCommand(const char *cmd_line, JobsList *jobs) : BuiltInCommand(cmd_line), m_jobs(jobs){}

    virtual ~ForegroundCommand() {
    }

    void execute() override;
};

//our added class//

class Alias_system {
public:
    map<string, string> m_aliases;
    set<string> m_og;
    vector<string> m_added;
    int m_AlNum;

public:
    Alias_system() {
        m_AlNum = 0;
        m_og = {"chprompt", "cd", "quit", "kill", "showpid", "pwd", "alias", "unalias",
                      ">>", "<<", ">", "<", "|", "listdir", "jobs", "fg", "getuser", "watch"
                      ,"|&","cd&", "jobs&","chprompt&", "showpid&", "pwd&", "fg&", "quit&",
                      "kill&", "alias&", "unalias&", "listdir&" , "netinfo" , "netinfo&" ,
                      "getuser&" , "whoami" , "whoami&"};
    }

    int addAlias(string aliasName , string value) {

         if(m_og.find(value)==m_og.end()) {
              std::cerr<<"smash error: alias: invalid alias format"<<std::endl;
              return 0;
          }

        //if the alias already exists
        if(this->m_aliases.find(aliasName) != this->m_aliases.end()){
            std::cerr <<"smash error: alias: "<< aliasName << " already exists or is a reserved command"<< std::endl;
            return 0;
        }

        //if the alias name is a reserved keyword
        if(m_og.find(aliasName)!=m_og.end()) {
            std::cerr <<"smash error: alias: "<< aliasName << " already exists or is a reserved command"<< std::endl;
            return 0;
        }
        m_aliases.insert({aliasName, value});
        m_added.push_back(aliasName);
        return 1;
    }

    int removeAlias(string aliasName){
        if(this->m_aliases.find(aliasName) == this->m_aliases.end()){
            std::cerr <<"smash error: unalias: "<< aliasName << " alias does not exist"<< std::endl;
            return 0;
        }

        this->m_aliases.erase(aliasName);
        size_t index = 0;
        while (index < this->m_added.size()) {
            if (this->m_added[index] == aliasName) {
                this->m_added.erase(this->m_added.begin() + index);
                continue;
            }
            index++;
        }
        return 1;
    }
    map<string, string> getMap()const{
        return m_aliases;
    }
    vector<string> getAdded()const{
        return m_added;
    }

};



class AliasCommand : public BuiltInCommand {
public:
    AliasCommand(const char *cmd_line) : BuiltInCommand(cmd_line) {}

    virtual ~AliasCommand() {
    }

    void execute() override;
};

class UnAliasCommand : public BuiltInCommand {
public:
    UnAliasCommand(const char *cmd_line) : BuiltInCommand(cmd_line){}

    virtual ~UnAliasCommand() {
    }

    void execute() override;
};

class UnSetEnvCommand : public BuiltInCommand {
public:
    UnSetEnvCommand(const char *cmd_line) : BuiltInCommand(cmd_line){}

    virtual ~UnSetEnvCommand() {
    }

    void execute() override;
};

class WatchProcCommand : public BuiltInCommand {
public:
    WatchProcCommand(const char *cmd_line)
            : BuiltInCommand(cmd_line)
    {}

    virtual ~WatchProcCommand() = default;

    void execute() override;

private:
    // Helpers to read and parse /proc
    static bool readFile(const std::string &path, std::string &out);
    static bool getTotalJiffies(unsigned long long &total);
    static bool getUptimeSeconds(double &uptime);
    static bool getProcTimes(pid_t pid,
                             unsigned long &utime,
                             unsigned long &stime,
                             unsigned long long &starttime);
    static bool getProcRSS(pid_t pid, unsigned long &rss_kb);
};

class SmallShell {
private:
    // TODO: Add your data members
    JobsList* m_jobs;
    Alias_system* m_aliasSystem;
    string m_curr_cmndLine;
    string m_prompt;
    int m_curr_jid;
    int m_curr_pid;
    std::string currDir_;
    std::string prevDir_;
    SmallShell();

public:

    Command *CreateCommand(const char *cmd_line);

    SmallShell(SmallShell const &) = delete; // disable copy ctor
    void operator=(SmallShell const &) = delete; // disable = operator
    static SmallShell &getInstance() // make SmallShell singleton
    {
        static SmallShell instance; // Guaranteed to be destroyed.
        // Instantiated on first use.
        return instance;
    }

    ~SmallShell(){
        delete m_jobs;
        delete m_aliasSystem;
        if(m_dir_arr[0] != nullptr) delete m_dir_arr[0];
        if(m_dir_arr[1] != nullptr) delete m_dir_arr[1];
        delete[] m_dir_arr;
        if(prevdir!= nullptr) delete prevdir;
    };

    void executeCommand(const char *cmd_line);

    // TODO: add extra methods as needed
    JobsList* getJobs() {
        return m_jobs;
    }
    Alias_system* getAliases() {
        return m_aliasSystem;
    }
    string getCurrCmndLine() const{
        return m_curr_cmndLine;
    }
    void setCurrCmndLine(const string& newLine){
        m_curr_cmndLine = newLine;
    }
    string getPrompt() const{
        return m_prompt;
    }
    void setPrompt(string newPrompt){
        m_prompt = newPrompt;
    }
    void setCurrJobId(int JobId){
        m_curr_jid = JobId;
    }
    void setCurrJobPid(int JobPid){
        m_curr_pid = JobPid;
    }
    int getCurrJobId(){
        return m_curr_jid;
    }
    int getCurrJobPid(){
        return m_curr_pid;
    }
    const string& getCurrDir() const {
        return currDir_;
    }
    const string& getPrevDir() const {
        return prevDir_;
    }
    void setCurrDir(const std::string &d) {
        currDir_ = d;
    }
    void setPrevDir(const std::string &d) {
        prevDir_ = d;
    }
};

#endif //SMASH_COMMAND_H_
