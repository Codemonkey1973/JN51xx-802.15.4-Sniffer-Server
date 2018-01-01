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
#include <stdint.h>
#include <string.h>
#include "uart.h"

/****************************************************************************/
/***        Macro Definitions                                             ***/
/****************************************************************************/

#define UART_READ_TIMEOUT     2000    /* timeout time in millisecs    */
#define UART_WRITE_TIMEOUT    2000    /* write timeout in millisecs   */

#define MAX_PORT_NAME   100
#define MAX_VALUE_NAME  100

/****************************************************************************/
/***        Type Definitions                                              ***/
/****************************************************************************/

/****************************************************************************/
/***        Local Function Prototypes                                     ***/
/****************************************************************************/

/****************************************************************************/
/***        Exported Variables                                            ***/
/****************************************************************************/

/****************************************************************************/
/***        Local Variables                                               ***/
/****************************************************************************/

/****************************************************************************/
/***        Exported Functions                                            ***/
/****************************************************************************/
/****************************************************************************
 *
 * NAME:       UART_vListPorts
 *
 * DESCRIPTION:
 * Lists the serial ports available
 *
 * RETURNS:
 * void
 *
 ****************************************************************************/
void UART_vListPorts(void)
{
    DWORD count = 0;
    LONG retCode;
    CHAR portname[MAX_PORT_NAME];

    printf("The following serial ports are present:");

    while (1)
    {
        retCode = UART_bEnumeratePorts(portname, sizeof(portname), count);
        if( retCode != TRUE)
        {
            break;
        }
        printf(" %s", portname);
        count++;
    }
    printf("\n");
}


/****************************************************************************
 *
 * NAME:       UART_bEnumeratePorts
 *
 * DESCRIPTION:
 * Enumerates a serial port
 *
 * PARAMETERS: Name     RW  Usage
 *
 * RETURNS:
 * boolean
 *
 ****************************************************************************/
boolean UART_bEnumeratePorts(char *deviceName, DWORD maxLen, DWORD index)
{
    LPCSTR RegPath = "HARDWARE\\DEVICEMAP\\SERIALCOMM";
    HKEY hKey;
    HKEY hKeyRoot = HKEY_LOCAL_MACHINE;
    DWORD retCode;
    char ClassName[MAX_PATH] = {"\0"}; 		// Buffer for class name.
    LPSTR strClassName = ClassName;
    DWORD dwcClassLen = MAX_PATH;           // Length of class string.
    DWORD dwcSubKeys;                       // Number of sub keys.
    DWORD dwcMaxSubKey;                     // Longest sub key size.
    DWORD dwcMaxClass;                      // Longest class string.
    DWORD dwcValues;                        // Number of values for this key.
    char valueName[MAX_VALUE_NAME];
    LPCH strValueName = valueName;
    DWORD dwcValueName = MAX_VALUE_NAME;
    DWORD dwcMaxValueName;                  // Longest Value name.
    DWORD dwcMaxValueData;                  // Longest Value data.
    DWORD dwcSecDesc;                       // Security descriptor.
    FILETIME ftLastWriteTime;               // Last write time.
    DWORD dwType;
    DWORD retValue;
    DWORD cbData;

    // Use RegOpenKeyEx() with the new Registry path to get an open handle
    // to the child key you want to enumerate.
    retCode = RegOpenKeyEx (hKeyRoot,
                            RegPath,
                            0,
                            KEY_ENUMERATE_SUB_KEYS |
                            KEY_EXECUTE |
                            KEY_QUERY_VALUE,
                            &hKey);

    if (retCode != ERROR_SUCCESS) return(FALSE);

    // Get Class name, Value count.
    RegQueryInfoKey(hKey,                   // Key handle.
    				strClassName,              // Buffer for class name.
                    &dwcClassLen,           // Length of class string.
                    NULL,                   // Reserved.
                    &dwcSubKeys,            // Number of sub keys.
                    &dwcMaxSubKey,          // Longest sub key size.
                    &dwcMaxClass,           // Longest class string.
                    &dwcValues,             // Number of values for this key.
                    &dwcMaxValueName,       // Longest Value name.
                    &dwcMaxValueData,       // Longest Value data.
                    &dwcSecDesc,            // Security descriptor.
                    &ftLastWriteTime);      // Last write time.

    // Enumerate the Key Values
    cbData = maxLen;
    dwcValueName = MAX_VALUE_NAME;
    valueName[0] = '\0';

    retValue = RegEnumValue(hKey,
    						index,
							strValueName,
                            &dwcValueName,
                            NULL,
                            &dwType,
                            (BYTE *)&deviceName[0],
                            &cbData);

    RegCloseKey (hKey); // Close the key handle.
    if(dwType == REG_SZ && retValue == (DWORD)ERROR_SUCCESS)
    {
        return(TRUE);
    }
    else
    {
        return(FALSE);
    }
}

/****************************************************************************
 *
 * NAME:       UART_bOpen
 *
 * DESCRIPTION:
 * Opens the comms port with the desired baudrate
 *
 * PARAMETERS:  Name        RW  Usage
 * 				phUartHandle W	Pointer to where to store the handle if opened ok
 *              acPortName  R   String containing the port name (eg COM1)
 *              iBaudrate   R   Baudrate to use
 *
 * RETURNS:
 * boolean:     TRUE of port was opened ok
 *              FALSE if something went wrong
 *
 ****************************************************************************/
boolean UART_bOpen(HANDLE *phUartHandle, const char *acPortName, int iBaudRate)
{

    DCB dcb = {0};
    COMMTIMEOUTS timeouts;
    HANDLE hUartComm;

    char acFullPortName[50];

    sprintf(acFullPortName, "//./%s", acPortName);

    hUartComm = CreateFile (acFullPortName,
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            0,
                            OPEN_EXISTING,
                            0,
                            0);

    if(hUartComm==INVALID_HANDLE_VALUE)
    {
    	printf("Error: Invalid handle value while opening serial port\n");
        return(FALSE);
    }

    if (!GetCommState(hUartComm, &dcb))
    {
        // Error getting current DCB settings
    	printf("Error: Can't get serial port DCB settings\n");
        return(FALSE);
    }

    dcb.BaudRate = iBaudRate;
    dcb.fBinary = TRUE;
    dcb.fParity = FALSE;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fDtrControl = DTR_CONTROL_DISABLE;
    dcb.fDsrSensitivity = FALSE;
    dcb.fTXContinueOnXoff = TRUE;
    dcb.fOutX = FALSE;
    dcb.fInX = FALSE;
    dcb.fErrorChar = FALSE;
    dcb.fNull = FALSE;
    dcb.fRtsControl = RTS_CONTROL_DISABLE;
    dcb.fAbortOnError = FALSE;
    dcb.XonLim = 300;
    dcb.XoffLim = 300;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.XonChar = 0;
    dcb.XoffChar = 0;
    dcb.ErrorChar = 0;
    dcb.EofChar = 0;
    dcb.EvtChar = 0;

    /* Write the settings to the comms port */
    if(!SetCommState(hUartComm, &dcb))
    {
        printf("Error: Can't get comm state\n");
		CloseHandle(hUartComm);
        return(FALSE);
    }

    /* Get current comm port timeouts */
    if(!GetCommTimeouts(hUartComm, &timeouts))
    {
        printf("Error: Can't get timeouts\n");
		CloseHandle(hUartComm);
        return(FALSE);
    }

    /*
     * If we set ReadIntervalTimeout and ReadTotalTimeoutMultiplier
     * to MAXDWORD, then the port will return immediately if any
     * characters are received, but will time out after
     * ReadTotalTimeoutConstant if the desired number of bytes are
     * not read.
     */
    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
    timeouts.ReadTotalTimeoutConstant = UART_READ_TIMEOUT;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = UART_WRITE_TIMEOUT;

    if(!SetCommTimeouts (hUartComm, &timeouts))
    {
        printf("Error: Can't set timeouts\n");
		CloseHandle(hUartComm);
        return(FALSE);
    }

    /* Return the handle to the port */
    *phUartHandle = hUartComm;

    return(TRUE);

}

/****************************************************************************
 *
 * NAME:       UART_bClose
 *
 * DESCRIPTION:
 * Closes the serial port
 *
 * PARAMETERS:  Name    	RW  Usage
 * 				hUartHandle	R	Handle for the UART to use
 *
 * RETURNS:
 * boolean:        TRUE of port was close ok
 *
 ****************************************************************************/
boolean UART_bClose(HANDLE hUartHandle)
{
    CloseHandle(hUartHandle);
    return(TRUE);
}

/****************************************************************************
 *
 * NAME:       UART_bRead
 *
 * DESCRIPTION:
 * Attempts to read a byte from the serial port
 *
 * PARAMETERS:  Name        RW  Usage
 * 				hUartHandle	R	Handle for the UART to use
 *              pu8Data     W   Place to store byte read from the serial port
 *
 * RETURNS:
 * boolean:     TRUE of byte was read ok
 *              FALSE if byte wasn't read
 *
 ****************************************************************************/
boolean UART_bRead(HANDLE hUartHandle, uint8_t *pu8Data)
{
    DWORD dwBytesTransferred = 0;

    if(ReadFile(hUartHandle, pu8Data, 1, &dwBytesTransferred, 0))
    {
        if(dwBytesTransferred == 1)
        {
            return(TRUE);
        }
    }

    return(FALSE);
}

/****************************************************************************
 *
 * NAME:       UART_bReadWithTimeout
 *
 * DESCRIPTION:
 * Attempts to read a byte from the serial port. Also allows you to choose
 * the timeout time in milliseconds.
 *
 * PARAMETERS:  Name        RW  Usage
 * 				hUartHandle	R	Handle for the UART to use
 *              pu8Data     W   Place to store byte read from the serial port
 *              dwTimeout   R   Timeout time in milliseconds
 *
 * RETURNS:
 * boolean:     TRUE of byte was read ok
 *              FALSE if byte wasn't read
 *
 ****************************************************************************/
boolean UART_bReadWithTimeout(HANDLE hUartHandle, uint8_t *pu8Data, int iNumBytesToRead, DWORD dwTimeout, DWORD *pdwBytesRead)
{
    DWORD dwBytesTransferred = 0;
    COMMTIMEOUTS timeouts;

    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
    timeouts.ReadTotalTimeoutConstant = dwTimeout;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = UART_WRITE_TIMEOUT;

    if(!SetCommTimeouts (hUartHandle, &timeouts)){
        printf("Error: Can't set timeouts\n");
		CloseHandle(hUartHandle);
        return(FALSE);
    }

    if(ReadFile(hUartHandle, pu8Data, iNumBytesToRead, &dwBytesTransferred, 0)){
    	*pdwBytesRead = dwBytesTransferred;
        if(dwBytesTransferred == iNumBytesToRead){
            return(TRUE);
        }
    }

    return(FALSE);
}

/****************************************************************************
 *
 * NAME:       UART_bWrite
 *
 * DESCRIPTION:
 * Writes a byte to the serial port
 *
 * PARAMETERS:  Name    	RW  Usage
 * 				hUartHandle	R	Handle for the UART to use
 *              u8Data  	R   Character to write to the port
 *
 * RETURNS:
 * boolean:     TRUE of byte was written ok
 *              FALSE if byte wasn't written
 *
 ****************************************************************************/
boolean UART_bWrite(HANDLE hUartHandle, uint8_t u8Data)
{
    DWORD iBytesTransferred = 0;

    if(!WriteFile(hUartHandle, &u8Data, 1, &iBytesTransferred, NULL))
    {
        return(FALSE);
    }
    else
    {
        return(TRUE);
    }
}

/****************************************************************************
 *
 * NAME:       UART_bWrite
 *
 * DESCRIPTION:
 * Writes a byte to the serial port
 *
 * PARAMETERS:  Name    	RW  Usage
 * 				hUartHandle	R	Handle for the UART to use
 *              pu8Data 	R   Character to write to the port
 *
 * RETURNS:
 * boolean:     TRUE of byte was written ok
 *              FALSE if byte wasn't written
 *
 ****************************************************************************/
boolean UART_bWriteBytes(HANDLE hUartHandle, uint8_t *pu8Data, int iLength)
{
    DWORD iBytesTransferred = 0;

    if(!WriteFile(hUartHandle, pu8Data, iLength, &iBytesTransferred, NULL))
    {
        return(FALSE);
    }
    else
    {
        return(TRUE);
    }
}

/****************************************************************************
 *
 * NAME:       UART_vFlush
 *
 * DESCRIPTION:
 * Flushes both the RX & TX FIFO's
 *
 * PARAMETERS: 	Name     	RW  Usage
 * 				hUartHandle	R	Handle for the UART to use
 *
 * RETURNS:
 * void
 *
 ****************************************************************************/
void UART_vFlush(HANDLE hUartHandle)
{
    PurgeComm(hUartHandle, PURGE_RXCLEAR | PURGE_TXCLEAR);
}


/****************************************************************************/
/***        Local Functions                                               ***/
/****************************************************************************/

/****************************************************************************/
/***        END OF FILE                                                   ***/
/****************************************************************************/
