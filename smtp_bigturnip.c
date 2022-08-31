/* Nathan Fowler
 * Licensed under GPLv3
 * Compile with gcc -Wall -D_FORTIFY_SOURCE=2 -O2 -fPIE -pie -fstack-protector -o smtp_honeypot smtp_honeypot.c
 * Then strip debugging symbols via 'strip ./smtp_honeypot'
 *
 * Feb 05 2019 - xinetd powered time-wasting daemon
 * Feb 06 2019 - Now with syslog support
 * Feb 07 2019 - SMTP not ESMTP
 *	       - Capture only ASCII safe characters or replace them with '?'
 * Feb 09 2019 - Fix isprint() == 0 instead of negation
 * Feb 10 2019 - Handle ESTMP EHLO and consolidate the logging/validation SYSLOG function
 *	       - Better character handling of syslog data
 *	       - s/packetmail\.net/localhost/g
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <ctype.h>

#define OK		0
#define NO_INPUT	1
#define TOO_LONG	2
#define NOT_OK		3

static int getLine( char *prompt, char *buff, size_t sz) {
	int ch, extra;

	//Get line with buffer overflow protection
	if ( prompt != NULL ){
		printf("%s", prompt);
		fflush(stdout);
	}

	if (fgets(buff, sz, stdin) == NULL)
		return NO_INPUT;

	//Flush to newline and indicate it was too long
	if (buff[strlen(buff)-1] != '\n'){
		extra = 0;
		while( ((ch = getchar()) != '\n') && (ch != EOF) )
			extra = 1;
		return (extra == 1) ? TOO_LONG: OK;
	}

	//Make sure only printed is returned
	// \0 terminated string, then \n
	for(ch=0; ch<strlen(buff); ch++){
		//Debug
		//printf("%x\n", buff[ch] & 0xff);

		//Turn all CR into LF
		if ( buff[ch] == '\r' ){
			buff[ch] = '\n';

			//Terminate the string at the first CR or the replaced CR->LF
			if ( ch < strlen(buff) ){ buff[ch+1] = '\0'; }
		}

		//Throw an error if it's not printable, permit newline.
		if ( buff[ch] != '\n' ){
			if ( isprint(buff[ch]) == 0 ){ return NOT_OK; }
		}
	}

	//All ok, return the string to the caller
	buff[strlen(buff)-1] = '\0';
	return OK;
}

static int Validate_and_Log (int rc, char *response) {
	//Random Delay
	FILE *urandom;
	unsigned int seed;
	int rnd_offset;

	//Init rand()
	srand((unsigned)time(NULL));
	urandom = fopen("/dev/urandom", "r");
	if (urandom != NULL) { if( fread (&seed, sizeof(seed), 1, urandom) == 1 ){ srand(seed); } }

	//Random-wait before returning to the caller to best simulate a busy MTA
	rnd_offset = (rand() % 5000) * 1000; usleep(rnd_offset);

	//Validation and error handling
	if ( rc != OK ){
		if ( rc == NO_INPUT ){
			openlog("SMTP_HONEYPOT", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
			syslog(LOG_NOTICE, "%s", "*** NO INPUT DETECTED");
			closelog();
		}

		if ( rc == TOO_LONG ){
			openlog("SMTP_HONEYPOT", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
			syslog(LOG_NOTICE, "%s", "*** POTENTIAL BOF - TOO MANY CHARACTERS DETECTED");
			closelog();
		}

		if ( rc == NOT_OK ){
			openlog("SMTP_HONEYPOT", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
			syslog(LOG_NOTICE, "%s", "*** UNPRINTABLE CHARACTERS DETECTED");
			closelog();
		}

		printf("502 5.5.2 Error: command not recognized\n");
		fflush(stdout);
		return 1;
	}

	//Log the actual received response
	openlog("SMTP_HONEYPOT", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_NOTICE, "%s", response);
	closelog();

	//Allow the SMTP conversation to persist
	return 0;
}

int main(void) {
	//String reading
	char response[4096];
	int rc;

	//Send the banner and get the response
	rc  = getLine("220 localhost ESMTP Use of this system for unsolicited electronic mail advertisements (UCE), SPAM, or malicious content is forbidden.\n", response, sizeof(response));
	if (Validate_and_Log(rc, response) != 0) { return 1; }

	//Did they even attempt to HELO or EHLO?
	if ( strstr(response, "EHLO ") == NULL && strstr(response,"HELO ") == NULL ){
		rc = getLine("502 5.5.2 Error: command not recognized\n", response, sizeof(response));
		if (Validate_and_Log(rc, response) != 0) { return 1; }
	}

	//If they're still being stupid here and cannot HELO or HELO lets terminate the connection
	if ( strstr(response, "EHLO ") == NULL && strstr(response,"HELO ") == NULL ){
		printf("502 5.5.2 Error: command not recognized\n");
		fflush(stdout);
		return 1;
	}

	//Did they EHLO instead of HELO?
	if ( strstr(response, "EHLO ") != NULL ){
		rc = getLine("250-localhost\n250-PIPELINING\n250-SIZE 20480000\n250-VRFY\n250-ETRN\n250-ENHANCEDSTATUSCODES\n250-8BITMIME\n250 DSN\n", response, sizeof(response));
		if (Validate_and_Log(rc, response) != 0) { return 1; }
	}

	//After the EHLO/HELO get the next command, potentially RCPT TO
	rc  = getLine("250 localhost\n", response, sizeof(response));
	if (Validate_and_Log(rc, response) != 0 ) { return 1; }

	//Get the final command before telling them the system is busy, potentially MAIL FROM
	rc  = getLine("250 2.1.0 OK\n", response, sizeof(response));
	if (Validate_and_Log(rc, response) != 0) { return 1; }

	//Oh no, we can't handle this message!  What do!?
	printf("451 4.5.0 Temporary message handling error\n");
	fflush(stdout);
	return 0;
}
