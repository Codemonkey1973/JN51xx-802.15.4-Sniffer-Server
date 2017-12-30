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

#ifndef UART_H_INCLUDED
#define UART_H_INCLUDED

/****************************************************************************/
/***        Include files                                                 ***/
/****************************************************************************/

#include <windows.h>
#include <stdint.h>

/****************************************************************************/
/***        Macro Definitions                                             ***/
/****************************************************************************/

/****************************************************************************/
/***        Exported Functions                                            ***/
/****************************************************************************/

/****************************************************************************/
/***        Exported Variables                                            ***/
/****************************************************************************/

/****************************************************************************/
/***        Classes                                                       ***/
/****************************************************************************/

void UART_vListPorts(void);
boolean UART_bEnumeratePorts(char *deviceName, DWORD maxLen, DWORD index);
boolean UART_bOpen(HANDLE *phUartHandle, const char *acPortName, int iBaudRate);
boolean UART_bClose(HANDLE hUartHandle);
boolean UART_bRead(HANDLE hUartHandle, uint8_t *pu8Data);
boolean UART_bReadWithTimeout(HANDLE hUartHandle, uint8_t *pu8Data, DWORD dwTimeout);
boolean UART_bWrite(HANDLE hUartHandle, uint8_t u8Data);
boolean UART_bWriteBytes(HANDLE hUartHandle, uint8_t *pu8Data, int iLength);
void UART_vFlush(HANDLE hUartHandle);


#endif /* UART_H_INCLUDED */

/****************************************************************************/
/***        END OF FILE                                                   ***/
/****************************************************************************/
