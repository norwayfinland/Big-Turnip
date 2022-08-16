/* Nathan "Big Turnip" Fowler
 * Licensed under GPLv2
 * Compile with gcc -Wall -D_FORTIFY_SOURCE=2 -O2 -fPIE -pie -fstack-protector -o smtp_bigturnip smtp_bigturnip.c
 * Then strip debugging symbols via 'strip ./smtp_bigturnip'
 *
 * Aug 15 2022 - xinetd powered time-wasting SMTP system that instead of issuing an SMTP 354 Go Ahead after the DATA statement,
 * like a normal and sane MTA instead we'll just "hyperblast the connection that is unsolicited", as this isn't an actual MTA,
 * into another reality where the Internet doesn't get spam because the spam bots are not functional.  Basically, SPAM is just
 * random garbage data, so lets ... spam the spammer?
 *
 * Changelog
 *      2022-08-16 - Use 0x09 where possible to piss off the people who prefer 0x20 four times, literally, four bytes of bloat
 *	instead of using a single byte 0x09 where it makes sense.  Oh yeah, also provide some level of visceral
 *	feedback that we just hauled off and kicked a miscreant in the nards using TCP and /dev/random.
 *
 *	Also add better directional logging because that's better than using TCPDump to watch the port.  I'm gonna feature
 *	creep the hell out of this maybe.  Who knows.  Like me and follow me on Shitter peepz so I can pump my self esteem.
 *
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
	FILE* urandom;
	unsigned int seed;
	int rnd_offset;

	//Init rand()
	srand((unsigned)time(NULL));
	urandom = fopen("/dev/urandom", "r");
	if (urandom != NULL) {
		if( fread (&seed, sizeof(seed), 1, urandom) == 1 ){ srand(seed);} 
		fclose(urandom);
	}

	//Random-wait before returning to the caller to best simulate a busy MTA
	rnd_offset = (rand() % 5000) * 1000; usleep(rnd_offset);

	//Validation and error handling
	if ( rc != OK ){
		if ( rc == NO_INPUT ){
			openlog("SMTP_BIGTURNIP", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
			syslog(LOG_NOTICE, "%s", "*** NO INPUT DETECTED");
			closelog();
		}

		if ( rc == TOO_LONG ){
			openlog("SMTP_BIGTURNIP", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
			syslog(LOG_NOTICE, "%s", "*** POTENTIAL BOF - TOO MANY CHARACTERS DETECTED");
			closelog();
		}

		if ( rc == NOT_OK ){
			openlog("SMTP_BIGTURNIP", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
			syslog(LOG_NOTICE, "%s", "*** UNPRINTABLE CHARACTERS DETECTED");
			closelog();
		}

		printf("502 5.5.2 Error: command not recognized\n");
		fflush(stdout);
		return 1;
	}

	//Log the actual received response
	openlog("SMTP_BIGTURNIP", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_NOTICE, "%s", response);
	closelog();

	//Allow the SMTP conversation to persist
	return 0;
}

int main(void) {
	//String reading
	char response[4096];
	int rc = 0;

	//Send the banner and get the response
	if (Validate_and_Log(rc, "> 220 localhost ESMTP Use of this system for unsolicited electronic mail advertisements (UCE), SPAM, or malicious content is forbidden.\n") != 0) { return 1; }
	rc  = getLine("220 localhost ESMTP Use of this system for unsolicited electronic mail advertisements (UCE), SPAM, or malicious content is forbidden.\n", response, sizeof(response));
	if (Validate_and_Log(rc, response) != 0) { return 1; }

	//Did they even attempt to HELO or EHLO?
	if ( strstr(response, "EHLO ") == NULL && strstr(response,"HELO ") == NULL ){
		if (Validate_and_Log(rc, "> 502 5.5.2 Error: command not recognized\n") != 0) { return 1; }
		rc = getLine("502 5.5.2 Error: command not recognized\n", response, sizeof(response));
		if (Validate_and_Log(rc, response) != 0) { return 1; }
	}

	//If they're still being stupid here and cannot HELO or HELO lets terminate the connection
	if ( strstr(response, "EHLO ") == NULL && strstr(response,"HELO ") == NULL ){
		if (Validate_and_Log(rc, "> 502 5.5.2 Error: command not recognized\n") != 0) { return 1; }
		printf("502 5.5.2 Error: command not recognized\n");
		fflush(stdout);
		return 1;
	}

	//Did they EHLO instead of HELO?
	if ( strstr(response, "EHLO ") != NULL ){
		if (Validate_and_Log(rc, "> 250-localhost\\n250-PIPELINING\\n250-SIZE 20480000\\n250-VRFY\\n250-ETRN\\n250-ENHANCEDSTATUSCODES\\n250-8BITMIME\\n250 DSN\\n") != 0) { return 1; }
		rc = getLine("250-localhost\n250-PIPELINING\n250-SIZE 20480000\n250-VRFY\n250-ETRN\n250-ENHANCEDSTATUSCODES\n250-8BITMIME\n250 DSN\n", response, sizeof(response));
		if (Validate_and_Log(rc, response) != 0) { return 1; }
	}

	//After the EHLO/HELO get the next command, potentially RCPT TO
	if (Validate_and_Log(rc, "> 250 localhost\n") != 0) { return 1; }
	rc  = getLine("250 localhost\n", response, sizeof(response));
	if (Validate_and_Log(rc, response) != 0 ) { return 1; }

	//Get the final command before telling them the system is busy, potentially MAIL FROM
	if (Validate_and_Log(rc, "> SENDING ENTROPY FUMES\n") != 0) { return 1; }
	rc  = getLine("250 2.1.0 OK\n", response, sizeof(response));
	if (Validate_and_Log(rc, response) != 0) { return 1; }

	//Summon the chaos entropy engine output, where we stop, no one knows until we hit EOF.  There are no big bucks though, only whammies for miscreants.
	//Not using feof() here because well, /dev/urandom is ... random.  No idea how big the buffer is until EOF so better to read a single character, I think.
	FILE* urandom;
	char random_data;
	int data_count = 0;

	urandom = fopen("/dev/urandom", "r");
	if (urandom != NULL) {
		if (Validate_and_Log(rc, "> Huff Entropy Engine Fumes Ya Bastard\n") != 0) { return 1; }
		for(data_count = 0; data_count < 32; data_count++){
			do {
				random_data = fgetc(urandom);
				printf("%c", random_data);
				fflush(stdout);
			} while (data_count != EOF);
		}
		fclose(urandom);
	}

	//We done
	return 0;
}
