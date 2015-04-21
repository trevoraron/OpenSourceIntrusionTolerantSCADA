/***************************************************************************
                          main.cpp  -  description
                             -------------------
    begin                : Son Nov 12 09:43:38 CET 2000
    copyright            : (C) 2000 by R. Lehrig
    email                : lehrig@t-online.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
#include "processviewserver.h"
#include "socket_setup.h"
#include "Client_Lib.h"
#include <sys/select.h>
#include <sys/types.h>

int pvMain(PARAM *p)
{
  const char *  server_name[] = SERVER_NAMES;
  int           server_port[] = SERVER_PORTS;

  int           b_sock, s_sock[NUM_SERVERS];
  fd_set        mask, temp_mask, empty_mask;

  char          event[MAX_EVENT_LENGTH];
  int           ret, i;


  b_sock = p->s;

  // Connect to servers
  for ( i = 0; i < NUM_SERVERS; i++ ) {
    s_sock[i] = server_socket( server_name[i], server_port[i] );
    printf( "Connected to server %d, socket: %d\n", i, s_sock[i] );
  }

  FD_ZERO( &empty_mask );
  FD_ZERO( &mask );
  FD_SET( b_sock, &mask );            // set browser socket
  for ( i = 0; i < NUM_SERVERS; i++ ) // set server sockets
    FD_SET( s_sock[i], &mask );


  while(1)
  {
    temp_mask = mask;
    ret = select( FD_SETSIZE, &temp_mask, &empty_mask, &empty_mask, NULL );
    if ( ret > 0 ) {
      printf( "Message received\n" );
      // Message from browser
      if ( FD_ISSET( b_sock, &temp_mask ) ) {
        //pvtcpreceive( p, event, MAX_EVENT_LENGTH );
        read_socket( b_sock, event, MAX_EVENT_LENGTH );
        printf( "Received event from browser: %s\n", event );
	
        // send to servers
        for ( i = 0; i < NUM_SERVERS; i++ )
          send( s_sock[i], event, strlen(event), 0 );
      }

      // Message from server
      for ( i = 0; i < NUM_SERVERS; i++ ) {
        if ( FD_ISSET( s_sock[i], &temp_mask ) ) {
          read_socket( s_sock[i], event, MAX_EVENT_LENGTH );
          printf( "Received from server: %s\n", event );

          // For now, simply relay
          send( b_sock, event, strlen(event), 0 );
        }
      }

    }

  }

  return 0;
}

#ifdef USE_INETD
int main(int ac, char **av)
{
PARAM p;

  pvInit(ac,av,&p);
  printf("main:version=%s\n",p.version);
  /* here you may interpret ac,av and set p->user to your data */
  pvMain(&p);
  return 0;
}
#else  // multi threaded server
int main(int ac, char **av)
{
PARAM p;
int   s,i;

  pvInit(ac,av,&p);
  /* here you may interpret ac,av and set p->user to your data */
  for(i=1; i<ac; i++)
  {
    if(strcmp(av[i],"-1") == 0)
    {
      s = pvAccept(&p);
      if(s > 0)
      {
        p.s = s;
        p.free = 0;
        pvMain(&p);
      }
      else
      {
        printf("pvAccept error\n");
      }
      return 0;
    }
  }
  while(1)
  {
    s = pvAccept(&p);
    if(s != -1) pvCreateThread(&p,s);
    else        break;
  }
  return 0;
}
#endif
