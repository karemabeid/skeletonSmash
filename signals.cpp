#include <iostream>
#include <signal.h>
#include "signals.h"
#include "Commands.h"


using namespace std;

void ctrlCHandler(int sig_num) {

    cout << "smash: got ctrl-C" << endl;


    pid_t pid = SmallShell::getInstance().getCurrJobPid();
    if (pid != -1) {

        cout << "smash: process " << pid << " was killed" << endl;
        SmallShell::getInstance().setCurrJobPid(-1);


        if (kill(pid, SIGINT) < 0) {
            cerr << "smash error: kill failed: "
                 << strerror(errno) << endl;
        }
    }

}
