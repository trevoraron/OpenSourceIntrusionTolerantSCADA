#include "socket_setup.h"
#include <thread>

/*TODO:
get PORT, NUM_SERVERS, SERVER_ADDRS[] defined 
*/

void mainThread(int b_sock_id){
    int * server_socks = server_sockets(SERVER_ADDRS, NUM_SERVERS, PORT);

    /*TODO: Select loop stuff */
    /*read server_socks with
     *  n=read(server_socks[i], buffer, buffersize) where n is bytes read, n<0 error
     *write server_socks with
     *  n=write(server_socks[i], buffer, buffersize) where n is bytes written n<0 error
     *same with browser sock
     */

}

int main() {
    b_listen = browser_listen(PORT);
    while(true){
        int b_sock_id = browser_accept(b_listen);
        std::thread connection (mainThread, b_sock_id);
    }
}
