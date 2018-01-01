/****************************************************************************
 *
 * Copyright 2017 Lee Mitchell <lee@indigopepper.com>
 * This file is part of JN51xx 802.15.4 Sniffer Server
 *
 * JN51xx 802.15.4 Sniffer Server is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * JN51xx 802.15.4 Sniffer Server is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with JN51xx 802.15.4 Sniffer Server.  If not,
 * see <http://www.gnu.org/licenses/>.
 *
 ****************************************************************************/

/****************************************************************************/
/***        Include files                                                 ***/
/****************************************************************************/

#include <windows.h>
#include <stdio.h>
#include <winsock.h>
#include <getopt.h>
#include <errno.h>
#include "uart.h"

/****************************************************************************/
/***        Macro Definitions                                             ***/
/****************************************************************************/

#define DEFAULT_SNIFFER_PORT	49999

#define OFFSET_TIMESTAMP		0
#define OFFSET_ID				5
#define OFFSET_CHANNEL			7
#define OFFSET_LQI				8
#define OFFSET_LENGTH			9
#define OFFSET_PACKET			10
#define LENGTH_TIMESTAMP		5
#define LENGTH_ID				1
#define LENGTH_CHANNEL			1
#define LENGTH_LQI				1
#define LENGTH_LENGTH			1

/****************************************************************************/
/***        Type Definitions                                              ***/
/****************************************************************************/

typedef enum
{
	E_STATUS_OK,
	E_STATUS_AGAIN,
	E_STATUS_ERROR_TIMEOUT,
	E_STATUS_ERROR_WRITING,
	E_STATUS_OUT_OF_RANGE,
	E_STATUS_NULL_PARAMETER,
	E_STATUS_FAIL
} teStatus;

typedef enum
{
	E_SNIFFER_MESSAGE_ID_CHANNEL_SELECT	= 0,
	E_SNIFFER_MESSAGE_ID_RECEIVER_CONTROL,
	E_SNIFFER_MESSAGE_ID_DATA_EVENT = 0x80,
	E_SNIFFER_MESSAGE_ID_COMMAND_ACKNOWLEDGE_EVENT = 0x81
} teMessageId;

typedef enum
{
	E_SNIFFER_ACK_SUCCESS = 0,
	E_SNIFFER_ACK_FAILURE,
	E_SNIFFER_ACK_INVALID_CHANNEL,
	E_SNIFFER_ACK_RX_ON,
	E_SNIFFER_ACK_RX_OFF,
} teAck;

typedef enum
{
	E_MESSAGE_STATE_INIT = 0,
	E_MESSAGE_STATE_WAIT_NULL,
	E_MESSAGE_STATE_WAIT_SOH,
	E_MESSAGE_STATE_WAIT_LENGTH,
	E_MESSAGE_STATE_WAIT_MESSAGE,
} teMessageState;

typedef enum
{
	E_STATE_SET_CHANNEL = 0,
	E_STATE_WAIT_SET_CHANNEL_RESPONSE = 1,
	E_STATE_TURN_RX_ON = 2,
	E_STATE_WAIT_TURN_RX_ON_RESPONSE = 3,
	E_STATE_WAIT_FOR_PACKETS = 4,
	E_STATE_TURN_RX_OFF = 5,
	E_STATE_WAIT_TURN_RX_OFF_RESPONSE = 6,
	E_STATE_EXIT = 7
} teState;

typedef struct
{
	teMessageState	eState;
	int 			iBytesReceived;
	int 			iBytesExpected;
    uint8_t 		au8Buffer[256];
	uint8_t			u8MessageId;
	uint8_t			u8Length;
	uint8_t			au8Data[255];
} tsMessage;

typedef struct
{
	volatile boolean	bExitRequest;
	volatile boolean	bExit;
	boolean				bVerbose;
	boolean				bSilent;
	teState				eState;
	char				*pstrSerialPort;
	int					iBaudRate;
	uint8_t				u8Channel;
	char				*pstrIpAddress;
	int					iPort;
	char				*pstrSnifferId;
	HANDLE				hUartHandle;
	int					iPacketsSniffed;
} tsInstance;

/****************************************************************************/
/***        Local Function Prototypes                                     ***/
/****************************************************************************/

static void vParseCommandLineOptions(tsInstance *psInstance, int argc, char *argv[]);
static BOOL WINAPI bCtrlHandler(DWORD dwCtrlType);
static teStatus eReadMessage(tsInstance *psInstance, tsMessage *psMessage);
static teStatus eWriteMessage(tsInstance *psInstance, tsMessage *psMessage);
static teStatus eReadFromUart(tsInstance *psInstance, int iTimeoutMilliseconds, int iBytesExpected, uint8_t *pu8Buffer, int *piBytesRead);
static teStatus eWriteToUart(tsInstance *psInstance, int iLength, uint8_t *pu8Data);
static uint8_t u8CalculateChecksum(uint8_t *pu8Message);

/****************************************************************************/
/***        Exported Variables                                            ***/
/****************************************************************************/

/****************************************************************************/
/***        Local Variables                                               ***/
/****************************************************************************/

static tsInstance sInstance;

/****************************************************************************/
/***        Exported Functions                                            ***/
/****************************************************************************/

/****************************************************************************
 *
 * NAME: main
 *
 * DESCRIPTION:
 * Application entry point
 *
 * RETURNS:
 * int
 *
 ****************************************************************************/
int main(int argc, char *argv[])
{
	int udp_socket;
	struct sockaddr_in si_other;
	int slen = sizeof(si_other);

    WSADATA wsaData;

    tsMessage sMessage;
    uint8_t au8MessageBuffer[255];
    int iOffset;
//          |--------|--------|--------|--------|--------|--------|--------|--------
	printf("+----------------------------------------------------------------------+\n" \
		   "|               JN51xx 802.15.4 Sniffer Server                         |\n" \
		   "| Copyright (C) 2017 Lee Mitchell <lee@indigopepper.com>               |\n" \
		   "|                                                                      |\n" \
	       "| This program comes with ABSOLUTELY NO WARRANTY.                      |\n" \
		   "| This is free software, and you are welcome to redistribute it        |\n" \
		   "| under certain conditions; See the GNU General Public License         |\n" \
		   "| version 3 or later for more details. You should have received a copy |\n" \
		   "| of the GNU General Public License along with JN51xx 802.15.4 Sniffer |\n" \
		   "| Server. If not, see <http://www.gnu.org/licenses/>.                  |\n" \
		   "+----------------------------------------------------------------------+\n\n");

	/* Initialise application state and set some defaults */
	sInstance.bExit = FALSE;
	sInstance.bVerbose = FALSE;
	sInstance.bSilent = FALSE;
	sInstance.eState = E_STATE_SET_CHANNEL;
	sInstance.pstrSerialPort = NULL;
	sInstance.iBaudRate = 1000000;
	sInstance.u8Channel = 11;
	sInstance.pstrIpAddress = "127.0.0.1";
	sInstance.iPort = DEFAULT_SNIFFER_PORT;
	sInstance.pstrSnifferId = NULL;
	sInstance.iPacketsSniffed = 0;

	memset(&sMessage, 0, sizeof(tsMessage));

    SetConsoleCtrlHandler(bCtrlHandler, TRUE);

    /* Parse the command line options */
    vParseCommandLineOptions(&sInstance, argc, argv);

    /* Check that a serial port option was passed on the command line */
    if(sInstance.pstrSerialPort == NULL)
    {
    	printf("Error: No serial port specified\n");
		UART_vListPorts();
    	exit(EXIT_FAILURE);
    }

    /* Check that any channel specified is valid */
	if((sInstance.u8Channel < 11) || (sInstance.u8Channel > 26))
	{
		printf("Error: Invalid channel specified. Valid options are 11 to 26\n");
		exit(EXIT_FAILURE);
	}

	/* If no sniffer Id was passed, use the name of the serial port */
	if(sInstance.pstrSnifferId == NULL)
	{
		sInstance.pstrSnifferId = sInstance.pstrSerialPort;
	}

    /* Try and open the comm port */
	if(UART_bOpen(&sInstance.hUartHandle, sInstance.pstrSerialPort, 1000000) == FALSE)
	{
		printf("Error: Failed to open the serial port!\n");
		UART_vListPorts();
		exit(EXIT_FAILURE);
	}

	/* Create the socket */
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    udp_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_socket < 0) {
		printf("Error: Can't create UDP socket\n");
		exit(EXIT_FAILURE);
	}

	/* Set the socket address */
	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(sInstance.iPort);
	si_other.sin_addr.S_un.S_addr = inet_addr(sInstance.pstrIpAddress);

	printf("Starting on port %s at %d baud\nSniffing on channel %d\nSending to %s:%d\n", sInstance.pstrSerialPort,
			sInstance.iBaudRate,
			sInstance.u8Channel,
			sInstance.pstrIpAddress,
			sInstance.iPort);


    /* Main program loop, execute until we get a signal requesting to exit */
    while(!sInstance.bExit)
    {

    	switch(sInstance.eState)
    	{

    	case E_STATE_SET_CHANNEL:
    	    if(sInstance.bVerbose) printf("Setting channel to %d\n", sInstance.u8Channel);
    		sMessage.u8MessageId = E_SNIFFER_MESSAGE_ID_CHANNEL_SELECT;
    		sMessage.u8Length = 1;
    		sMessage.au8Data[0] = sInstance.u8Channel;
    		if(eWriteMessage(&sInstance, &sMessage) == E_STATUS_OK)
    		{
    			sInstance.eState++;
    		}
    		break;

    	case E_STATE_WAIT_SET_CHANNEL_RESPONSE:
    		switch(eReadMessage(&sInstance, &sMessage))
    		{

    		case E_STATUS_OK:
    			if(sMessage.u8MessageId == E_SNIFFER_MESSAGE_ID_COMMAND_ACKNOWLEDGE_EVENT &&
    			   sMessage.u8Length == 1 &&
    			   sMessage.au8Data[0] == E_SNIFFER_ACK_SUCCESS)
    			{
    				if(sInstance.bVerbose) printf("Channel set to %d successfully\n", sInstance.u8Channel);
    	    	    sInstance.eState++;
    			}
    			else
    			{
    				if(sInstance.bVerbose) printf("State %d response %d\n", sInstance.eState, sMessage.au8Data[0]);
    	    	    sInstance.eState = E_STATE_SET_CHANNEL;
    			}
    			break;

    		case E_STATUS_AGAIN:
    			break;

    		case E_STATUS_ERROR_TIMEOUT:
    			if(sInstance.bVerbose) printf("Timeout waiting for set channel response\n");
        	    sInstance.eState = E_STATE_SET_CHANNEL;
    			break;

    		default:
    			if(sInstance.bVerbose) printf("Got unexpected response while waiting for set channel response, retrying\n");
        	    sInstance.eState = E_STATE_SET_CHANNEL;
    			break;

    		}
     		break;

    	case E_STATE_TURN_RX_ON:
    		if(sInstance.bVerbose) printf("Turning receiver on\n");
    		sMessage.u8MessageId = E_SNIFFER_MESSAGE_ID_RECEIVER_CONTROL;
    		sMessage.u8Length = 1;
    		sMessage.au8Data[0] = 1;
    		if(eWriteMessage(&sInstance, &sMessage) == E_STATUS_OK)
    		{
    			sInstance.eState++;
    		}
    		break;

        case E_STATE_WAIT_TURN_RX_ON_RESPONSE:
    		switch(eReadMessage(&sInstance, &sMessage))
    		{

    		case E_STATUS_OK:
    			if(sMessage.u8MessageId == E_SNIFFER_MESSAGE_ID_COMMAND_ACKNOWLEDGE_EVENT &&
    			   sMessage.u8Length == 1 &&
    			   ((sMessage.au8Data[0] == E_SNIFFER_ACK_SUCCESS) || (sMessage.au8Data[0] == E_SNIFFER_ACK_RX_ON)))
    			{
    				if(sInstance.bVerbose) printf("Receiver on, waiting for packets\n");
        			if(!sInstance.bSilent) printf("Packets received: 0");
    	    	    sInstance.eState++;
    			}
    			else
    			{
    				if(sInstance.bVerbose) printf("State %d response %d\n", sInstance.eState, sMessage.au8Data[0]);
    	    	    sInstance.eState = E_STATE_SET_CHANNEL;
    			}
    			break;

    		case E_STATUS_ERROR_TIMEOUT:
    			if(sInstance.bVerbose) printf("Timeout waiting for rx on response\n");
        	    sInstance.eState = E_STATE_SET_CHANNEL;
    			break;

    		case E_STATUS_AGAIN:
    			break;

    		default:
    			sInstance.eState = E_STATE_SET_CHANNEL;
    			break;

    		}
        	break;


    	case E_STATE_WAIT_FOR_PACKETS:
    		switch(eReadMessage(&sInstance, &sMessage))
    		{

    		case E_STATUS_OK:
    			if(sMessage.u8MessageId != E_SNIFFER_MESSAGE_ID_DATA_EVENT)
    			{
    				break;
    			}

    			sInstance.iPacketsSniffed++;

    			if(!sInstance.bSilent)
    			{
        			printf("\rPackets received: %d", sInstance.iPacketsSniffed);
        			fflush(stdout);
    			}

    			/* Construct a UDP message containing the sniffed packet */
    			iOffset = OFFSET_TIMESTAMP;

				/* Copy timestamp from the sniffed message */
				memcpy(&au8MessageBuffer[iOffset], &sMessage.au8Data[0], LENGTH_TIMESTAMP);
				iOffset += LENGTH_TIMESTAMP;

				/* Copy ID */
				memcpy(&au8MessageBuffer[iOffset], sInstance.pstrSnifferId, LENGTH_ID + strlen(sInstance.pstrSnifferId));
				iOffset += LENGTH_ID + strlen(sInstance.pstrSnifferId);

				/* Copy channel */
				memcpy(&au8MessageBuffer[iOffset], &sInstance.u8Channel, LENGTH_CHANNEL);
				iOffset += LENGTH_CHANNEL;

				/* Copy LQI from sniffed message */
				memcpy(&au8MessageBuffer[iOffset], &sMessage.au8Data[sMessage.u8Length - 2], LENGTH_LQI);
				iOffset += LENGTH_LQI;

				/* Copy length from sniffed message */
				memcpy(&au8MessageBuffer[iOffset], &sMessage.au8Data[5], LENGTH_LENGTH);
				iOffset += LENGTH_LENGTH;

				/* Copy packet and FCS from sniffed message */
				memcpy(&au8MessageBuffer[iOffset], &sMessage.au8Data[6], sMessage.au8Data[5]);
				iOffset += sMessage.au8Data[5];

				/* Send the UDP message */
				if(sendto(udp_socket, au8MessageBuffer, iOffset, 0, (struct sockaddr*)&si_other, slen) < 0)
				{
					printf("Error sending to socket %d\n", sInstance.iPort);
				}
    			break;

    		case E_STATUS_AGAIN:
    		case E_STATUS_ERROR_TIMEOUT:
    			break;

    		default:
    			sInstance.eState = E_STATE_SET_CHANNEL;
    			break;

    		}
    		break;

		case E_STATE_TURN_RX_OFF:
			if(sInstance.bVerbose) printf("Turning receiver off\n");
			sMessage.u8MessageId = E_SNIFFER_MESSAGE_ID_RECEIVER_CONTROL;
			sMessage.u8Length = 1;
			sMessage.au8Data[0] = 0;
			if(eWriteMessage(&sInstance, &sMessage) == E_STATUS_OK)
			{
				sInstance.eState++;
			}
			break;

		case E_STATE_WAIT_TURN_RX_OFF_RESPONSE:
			switch(eReadMessage(&sInstance, &sMessage))
			{

			case E_STATUS_OK:
				if(sMessage.u8MessageId == E_SNIFFER_MESSAGE_ID_COMMAND_ACKNOWLEDGE_EVENT &&
				   sMessage.u8Length == 1 &&
				   ((sMessage.au8Data[0] == E_SNIFFER_ACK_SUCCESS) || (sMessage.au8Data[0] == E_SNIFFER_ACK_RX_OFF)))
				{
					if(sInstance.bVerbose) printf("Receiver turned off\n");
					sInstance.eState++;
				}
				else
				{
					if(sInstance.bVerbose) printf("State %d response %d\n", sInstance.eState, sMessage.au8Data[0]);
					sInstance.eState = E_STATE_EXIT;
				}
				break;

			case E_STATUS_ERROR_TIMEOUT:
				if(sInstance.bVerbose) printf("Timeout waiting for rx off response\n");
				sInstance.eState = E_STATE_EXIT;
				break;

			case E_STATUS_AGAIN:
				break;

			default:
				sInstance.eState = E_STATE_EXIT;
				break;

			}
			break;

		case E_STATE_EXIT:
			sInstance.bExit = TRUE;
			break;

    	}

    	if(sInstance.bExitRequest)
    	{
			sInstance.eState = E_STATE_TURN_RX_OFF;
			sInstance.bExitRequest = FALSE;
    	}

    }

    /* Tidy up and then exit */
    UART_bClose(sInstance.hUartHandle);
	closesocket(udp_socket);
	WSACleanup();
	
	printf("Shutdown complete\n");
	
	return EXIT_SUCCESS;
}


/****************************************************************************/
/***        Local Functions                                               ***/
/****************************************************************************/
/****************************************************************************
 *
 * NAME: vParseCommandLineOptions
 *
 * DESCRIPTION:
 * Parse command line options
 *
 * RETURNS:
 * void
 *
 ****************************************************************************/
static void vParseCommandLineOptions(tsInstance *psInstance, int argc, char *argv[])
{

	int c;

	static const struct option lopts[] = {
		{ "serialport",   	required_argument,	0, 	's'	},
		{ "baudrate",   	required_argument,	0, 	'b'	},

		{ "channel",   		required_argument,	0, 	'c'	},

		{ "ipaddress", 		required_argument,	0, 	'i'	},
		{ "port", 			required_argument,	0, 	'p'	},

		{ "name", 			required_argument,	0, 	'n'	},

        { "verbose",       	no_argument,  		0,  'v' },
        { "quiet",       	no_argument,  		0,  'q' },

        { "help",       	no_argument,  		0,  'h' },
        { "help",       	no_argument,  		0,  '?' },

		{ NULL, 0, 0, 0 },
	};


	while(1)
	{

		c = getopt_long(argc, argv, "s:b:c:d:p:n:vq?", lopts, NULL);

		if (c == -1)
			break;

		switch(c)
		{

		case 's':
			psInstance->pstrSerialPort = optarg;
			break;

		case 'b':
			psInstance->iBaudRate = atoi(optarg);
			break;

		case 'c':
			psInstance->u8Channel = atoi(optarg);
			break;

		case 'i':
			psInstance->pstrIpAddress = optarg;
			break;

		case 'p':
			psInstance->iPort = atoi(optarg);
			break;

		case 'n':
			psInstance->pstrSnifferId = optarg;
			printf("Setting sniffer ID to %s\n", psInstance->pstrSnifferId);
			break;

		case 'v':
			printf("Verbose mode enabled\n");
			psInstance->bVerbose = TRUE;
			break;

		case 'q':
			printf("Quiet mode enabled\n");
			psInstance->bSilent = TRUE;
			break;

        case '?':
		case 'h':
		default:
			printf("Usage: %s <options>\n\n", argv[0]);
			puts("  -s --serialport <COMn>      Serial port to use\n\n"
				 "  -b --baudrate <baud>        Baud rate to use (default is 1000000)\n\n"
				 "  -c --channel <n>            Channel to sniff on (default is 11)\n\n"
				 "  -i --ipaddress \"IP\"         IP address to send sniffer traffic to\n"
				 "                               (default is 127.0.0.1)\n\n"
				 "  -p --port <n>               Port number to send sniffer traffic to\n"
				 "                               (default is 49999)\n\n"
				 "  -n --name \"Name\"            Id string for the sniffer\n"
				 "                               (default is the name of the serial port)\n\n"
				 "  -v --verbose                Enable verbose mode\n\n"
				 "  -q --quiet                  Enable quiet mode (no updates on console)\n\n"
				 "  -? --help                   Display help\n");
			exit(EXIT_FAILURE);
			break;
		}

	}

}


/****************************************************************************
 *
 * NAME: bCtrlHandler
 *
 * DESCRIPTION:
 * Handles Ctrl+C events
 *
 * RETURNS:
 * BOOL
 *
 ****************************************************************************/
static BOOL WINAPI bCtrlHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {

    case CTRL_C_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        printf("\nExit requested\n");
        sInstance.bExitRequest = TRUE;
        return TRUE;

    case CTRL_BREAK_EVENT:
        printf("\nImmediate exit requested\n");
        sInstance.bExit = TRUE;
    	return TRUE;

    default:
        return FALSE;
    }
}


/****************************************************************************
 *
 * NAME: eReadMessage
 *
 * DESCRIPTION:
 * Read a formatted message from the sniffer
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
static teStatus eReadMessage(tsInstance *psInstance, tsMessage *psMessage)
{

	int n;

    teStatus eStatus;
	int iLen;

	if(psMessage->eState == E_MESSAGE_STATE_INIT)
	{
		psMessage->iBytesReceived = 0;
		psMessage->iBytesExpected = 1;
		psMessage->eState++;
	}

    eStatus = eReadFromUart(psInstance, 100, psMessage->iBytesExpected, &psMessage->au8Buffer[psMessage->iBytesReceived], &iLen);
    if(eStatus == E_STATUS_OK)
    {
//    	printf("Got %d bytes\n", iLen);

		psMessage->iBytesReceived += iLen;

#if 0
	    printf("Read");
	    for(n = 0; n < psMessage->iBytesReceived; n++)
	    {
	        printf(" %02x", psMessage->au8Buffer[n]);
	    }
	    printf(" Bytes=%d State=%d\n", psMessage->iBytesReceived, psMessage->eState);
#endif

	    eStatus = E_STATUS_AGAIN;

		switch(psMessage->eState)
		{

		case E_MESSAGE_STATE_INIT:
			break;

		case E_MESSAGE_STATE_WAIT_NULL:
			if(psMessage->au8Buffer[0] == 0x00)
			{
				psMessage->eState++;
			}
			break;

		case E_MESSAGE_STATE_WAIT_SOH:
			if(psMessage->au8Buffer[1] == 0x01)
			{
				psMessage->eState++;
			}
			else
			{
				psMessage->eState = E_MESSAGE_STATE_INIT;
			}
			break;

		case E_MESSAGE_STATE_WAIT_LENGTH:
			psMessage->iBytesExpected = psMessage->au8Buffer[2];
			psMessage->eState++;
			break;

		case E_MESSAGE_STATE_WAIT_MESSAGE:
			psMessage->iBytesExpected -= iLen;

			/* If we now have the whole message */
			if(psMessage->iBytesExpected == 0)
			{

//			    printf("Got whole message %02x\n", psMessage->au8Buffer[psMessage->au8Buffer[2]]);

				/* If the last byte is EOT */
				if(psMessage->au8Buffer[psMessage->au8Buffer[2] + 2] == 0x04)
				{

//				    printf("EOT\n");

					/* If the checksum is good, return the message */
					if(u8CalculateChecksum(psMessage->au8Buffer) == psMessage->au8Buffer[psMessage->au8Buffer[2] + 1])
					{

//					    printf("CHKOK\n");

						psMessage->u8Length = psMessage->au8Buffer[2] - 3;
						psMessage->u8MessageId = psMessage->au8Buffer[3];
						memcpy(psMessage->au8Data, &psMessage->au8Buffer[4], psMessage->u8Length);
						eStatus = E_STATUS_OK;
					}
				}

//			    printf("\n");

			    psMessage->eState = E_MESSAGE_STATE_INIT;
			}
			break;

		default:
			psMessage->eState = E_MESSAGE_STATE_INIT;
			break;

		}

    }

    return eStatus;

}


/****************************************************************************
 *
 * NAME: eWriteMessage
 *
 * DESCRIPTION:
 * Writes a message to the sniffer module
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
static teStatus eWriteMessage(tsInstance *psInstance, tsMessage *psMessage)
{
	int n;
	uint8_t au8Buffer[258] = {0};

	if(psMessage->u8Length > (0xff - 3))
	{
		return E_STATUS_OUT_OF_RANGE;
	}

	au8Buffer[0] = 0x00;
	au8Buffer[1] = 0x01;
	au8Buffer[2] = psMessage->u8Length + 3;
	au8Buffer[3] = psMessage->u8MessageId;
	memcpy(&au8Buffer[4], psMessage->au8Data, psMessage->u8Length);
	au8Buffer[au8Buffer[2] + 1] = u8CalculateChecksum(au8Buffer);
	au8Buffer[au8Buffer[2] + 2] = 0x04;

	UART_vFlush(psInstance->hUartHandle);

	/* Write message */
	if(eWriteToUart(psInstance, au8Buffer[2] + 3, au8Buffer) != E_STATUS_OK)
	{
		return E_STATUS_ERROR_WRITING;
	}

	return E_STATUS_OK;

}


/****************************************************************************
 *
 * NAME: eReadFromUart
 *
 * DESCRIPTION:
 * Read bytes from the UART
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
static teStatus eReadFromUart(tsInstance *psInstance, int iTimeoutMilliseconds, int iBytesExpected, uint8_t *pu8Buffer, int *piBytesRead)
{

	DWORD dwBytesRead = 0;
	teStatus eStatus = E_STATUS_OK;

    if(pu8Buffer == NULL)
    {
        return E_STATUS_NULL_PARAMETER;
    }

    *piBytesRead = 0;

    if(UART_bReadWithTimeout(psInstance->hUartHandle, &pu8Buffer[*piBytesRead], iBytesExpected, iTimeoutMilliseconds, &dwBytesRead) != TRUE)
    {
    	eStatus = E_STATUS_ERROR_TIMEOUT;
    }

//	printf("Got %d bytes\n", dwBytesRead);
	*piBytesRead = (int)dwBytesRead;

    return eStatus;
}


/****************************************************************************
 *
 * NAME: eWriteToUart
 *
 * DESCRIPTION:
 * Write bytes to the UART
 *
 * RETURNS:
 * teStatus
 *
 ****************************************************************************/
static teStatus eWriteToUart(tsInstance *psInstance, int iLength, uint8_t *pu8Data)
{
	int n;

	/* Write message */
	if(UART_bWriteBytes(psInstance->hUartHandle, pu8Data, iLength) == FALSE)
	{
		printf("Error writing to UART\n");
		return E_STATUS_ERROR_WRITING;
	}

#if 0
    printf("Write");
    for(n = 0; n < iLength; n++)
    {
        printf(" %02x", pu8Data[n]);
    }
    printf("\n");
#endif

	return E_STATUS_OK;
}


/****************************************************************************
 *
 * NAME: u8CalculateChecksum
 *
 * DESCRIPTION:
 * Calculates the message checksum
 *
 * RETURNS:
 * uint8_t
 *
 ****************************************************************************/
static uint8_t u8CalculateChecksum(uint8_t *pu8Message)
{

	int n;
	uint8_t u8Checksum;
	uint8_t u8Length = pu8Message[2];
	uint8_t u8MessageId = pu8Message[3];
	int iPayloadLength = u8Length - 3;

	u8Checksum = u8Length;
	u8Checksum += u8MessageId;

	/* Calculate the checksum */
	for(n = 0; n < iPayloadLength; n++)
	{
		u8Checksum += pu8Message[4 + n];
	}

	u8Checksum = 256 - u8Checksum;

//	printf("MsgId=%d Len=%d PayloadLen=%d CheckSum=%02x\n", u8MessageId, u8Length, iPayloadLength, u8Checksum);

	return u8Checksum;

}

/****************************************************************************/
/***        END OF FILE                                                   ***/
/****************************************************************************/

