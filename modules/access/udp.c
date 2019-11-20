/*****************************************************************************
 * udp.c: raw UDP input module
 *****************************************************************************
 * Copyright (C) 2001-2005 VLC authors and VideoLAN
 * Copyright (C) 2007 Remi Denis-Courmont
 * $Id$
 *
 * Authors: Christophe Massiot <massiot@via.ecp.fr>
 *          Tristan Leteurtre <tooney@via.ecp.fr>
 *          Laurent Aimar <fenrir@via.ecp.fr>
 *          Jean-Paul Saman <jpsaman #_at_# m2x dot nl>
 *          Remi Denis-Courmont
 *
 * Reviewed: 23 October 2003, Jean-Paul Saman <jpsaman _at_ videolan _dot_ org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

/*****************************************************************************
 * Preamble
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <errno.h>
#include <vlc_common.h>
#include <vlc_plugin.h>
#include <vlc_access.h>
#include <vlc_network.h>
#include <vlc_block.h>
#include <vlc_interrupt.h>
#ifdef HAVE_POLL
# include <poll.h>
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif

/*****************************************************************************
 * Module descriptor
 *****************************************************************************/
static int  Open( vlc_object_t * );
static void Close( vlc_object_t * );

#define BUFFER_TEXT N_("Receive buffer")
#define BUFFER_LONGTEXT N_("UDP receive buffer size (bytes)" )
#define TIMEOUT_TEXT N_("UDP Source timeout (sec)")

vlc_module_begin ()
    set_shortname( N_("UDP" ) )
    set_description( N_("UDP input") )
    set_category( CAT_INPUT )
    set_subcategory( SUBCAT_INPUT_ACCESS )

    add_obsolete_integer( "server-port" ) /* since 2.0.0 */
    add_obsolete_integer( "udp-buffer" ) /* since 3.0.0 */
    add_integer( "udp-timeout", -1, TIMEOUT_TEXT, NULL, true )

    set_capability( "access", 0 )
    add_shortcut( "udp", "udpstream", "udp4", "udp6" )

    set_callbacks( Open, Close )
vlc_module_end ()

struct access_sys_t
{
    int fd;
    int timeout;
    size_t mtu;
	
	/* specific IGMP data */
	int igmp_fd;
	uint8_t dscp;
	uint8_t ecn;
	uint16_t identification;
	uint8_t ttl;
	uint32_t igmpInterval;
	
	char *nic_name;
	
	struct sockaddr_in *nic_address;
	size_t nic_address_length;
	
	struct addrinfo *igmp_address;
	size_t igmp_address_length;
	
	uint32_t lastIgmpPacket;
};

/*****************************************************************************
 * Local prototypes
 *****************************************************************************/
static block_t *BlockUDP( stream_t *, bool * );
static int Control( stream_t *, int, va_list );

static uint16_t CalculateChecksum(uint8_t *payload, uint16_t length)
{
  uint32_t result = 0;

  if ((payload != NULL) && (length > 0) && ((length % 2) == 0))
  {
    for (uint16_t i = 0; i < length; i++)
    {
      result += ((*(payload + i)) << 8) + (*(payload + i + 1));
      i++;
    }

    while (result > 0x0000FFFF)
    {
      uint16_t carry = (result >> 16);

      result &= 0x0000FFFF;
      result += carry;
    }
  }

  return (uint16_t)(~result);
}

static void net_UnsubscribeRaw (vlc_object_t *p_this)
{
	stream_t     *p_access = (stream_t*)p_this;
	access_sys_t *sys = p_access->p_sys;
	
	msg_Dbg (p_this, "(net_UnsubscribeRaw): unsubscribing from multicast group");
	
	// try to subscribe with raw IGMP packet
			
	unsigned char *igmpPacket = NULL;
	unsigned char *ipv4Packet = NULL;
	
	uint16_t ipv4PacketHeaderLength = 0x18;
	uint16_t ipv4PacketLength = ipv4PacketHeaderLength + 0x08;
	
	igmpPacket = malloc( 0x08 );
	ipv4Packet = malloc( ipv4PacketLength );
	
	if ((igmpPacket != NULL) && (ipv4Packet != NULL))
	{
		memset(igmpPacket, 0, 0x08);
		memset(ipv4Packet, 0, ipv4PacketLength);
		
		// prepare IGMP packet
		
		// IGMPv2 type
		*igmpPacket = 0x17;

		// IGMPv2 max response time
		*(igmpPacket + 1) = 0;

		// IGMPv2 checksum (skip)
		
		// IGMPv2 group address
		memcpy(igmpPacket + 4, &((struct sockaddr_in *)sys->igmp_address)->sin_addr.S_un.S_addr, 4);

		// calculate IGMPv2 payload checksum
		uint16_t checksum = CalculateChecksum(igmpPacket, 0x08);

		// update IGMPv2 checksum
		*(igmpPacket + 2) = ((checksum & 0xFF00) >> 8);
		*(igmpPacket + 3) = (checksum & 0x00FF);
		
		// prepare IPv4 packet
		
		uint8_t ihl = ipv4PacketHeaderLength / 4;

		// version field is always 4
		*(ipv4Packet) = (0x40 + ihl);

		// DSCP and ECN fields
		*(ipv4Packet + 1) = ((sys->dscp << 2) + sys->ecn);

		// total length of IPV4 packet
		*(ipv4Packet + 2) = (ipv4PacketLength >> 8);
		*(ipv4Packet + 3) = (ipv4PacketLength & 0x00FF);

		// IPV4 packet identification
		*(ipv4Packet + 4) = (sys->identification >> 8);
		*(ipv4Packet + 5) = (sys->identification & 0x00FF);

		// IPV4 flags and fragment offset (always 0)
		*(ipv4Packet + 6) = 0x40; // don't fragment

		*(ipv4Packet + 7) = 0x00;

		*(ipv4Packet + 8) = sys->ttl;
		*(ipv4Packet + 9) = 0x02;

		// IPV4 source address
		memcpy(ipv4Packet + 12, &sys->nic_address->sin_addr.S_un.S_addr, 4);

		// IPV4 destination address
		memcpy(ipv4Packet + 16, &((struct sockaddr_in *)sys->igmp_address)->sin_addr.S_un.S_addr, 4);

		// IPV4 options
		*(ipv4Packet + 20) = 0x94;
		*(ipv4Packet + 21) = 0x04;
		*(ipv4Packet + 22) = 0x00;
		*(ipv4Packet + 23) = 0x00;

		// calculate IPv4 header checksum
		checksum = CalculateChecksum(ipv4Packet, ipv4PacketHeaderLength);

		// update IPv4 header checksum
		*(ipv4Packet + 10) = ((checksum & 0xFF00) >> 8);
		*(ipv4Packet + 11) = (checksum & 0x00FF);

		// add IGMPv2 payload
		memcpy(ipv4Packet + ipv4PacketHeaderLength, igmpPacket, 0x08);
		
		// everything correct, try to send IGMP packet
		if (sendto(sys->igmp_fd, ipv4Packet, ipv4PacketLength, 0, sys->igmp_address, sys->igmp_address_length) == SOCKET_ERROR)
		{
			msg_Err (p_this, "(net_UnsubscribeRaw) sendto() error: %s", vlc_strerror_c(net_errno));
		}
	}
	else
	{
		msg_Err (p_this, "(net_UnsubscribeRaw) not enough memory for IGMP or IPV4 packet");
	}
	
	if (igmpPacket != NULL)
	{
		free(igmpPacket);
	}
	if (ipv4Packet != NULL)
	{
		free(ipv4Packet);
	}
}

static int net_SubscribeRaw (stream_t *access)
{
	access_sys_t *sys = access->p_sys;
	int result = 0;
	
	msg_Dbg (access, "(net_SubscribeRaw): subscribing to multicast group");
	
	// try to subscribe with raw IGMP packet
			
	unsigned char *igmpPacket = NULL;
	unsigned char *ipv4Packet = NULL;
	
	uint16_t ipv4PacketHeaderLength = 0x18;
	uint16_t ipv4PacketLength = ipv4PacketHeaderLength + 0x08;
	
	igmpPacket = malloc( 0x08 );
	ipv4Packet = malloc( ipv4PacketLength );
	
	if ((igmpPacket != NULL) && (ipv4Packet != NULL))
	{
		memset(igmpPacket, 0, 0x08);
		memset(ipv4Packet, 0, ipv4PacketLength);
		
		// prepare IGMP packet
		
		// IGMPv2 type
		*igmpPacket = 0x16;

		// IGMPv2 max response time
		*(igmpPacket + 1) = 0;

		// IGMPv2 checksum (skip)
		
		// IGMPv2 group address
		memcpy(igmpPacket + 4, &((struct sockaddr_in *)sys->igmp_address)->sin_addr.S_un.S_addr, 4);

		// calculate IGMPv2 payload checksum
		uint16_t checksum = CalculateChecksum(igmpPacket, 0x08);

		// update IGMPv2 checksum
		*(igmpPacket + 2) = ((checksum & 0xFF00) >> 8);
		*(igmpPacket + 3) = (checksum & 0x00FF);
		
		// prepare IPv4 packet
		
		uint8_t ihl = ipv4PacketHeaderLength / 4;

		// version field is always 4
		*(ipv4Packet) = (0x40 + ihl);

		// DSCP and ECN fields
		*(ipv4Packet + 1) = ((sys->dscp << 2) + sys->ecn);

		// total length of IPV4 packet
		*(ipv4Packet + 2) = (ipv4PacketLength >> 8);
		*(ipv4Packet + 3) = (ipv4PacketLength & 0x00FF);

		// IPV4 packet identification
		*(ipv4Packet + 4) = (sys->identification >> 8);
		*(ipv4Packet + 5) = (sys->identification & 0x00FF);

		// IPV4 flags and fragment offset (always 0)
		*(ipv4Packet + 6) = 0x40; // don't fragment

		*(ipv4Packet + 7) = 0x00;

		*(ipv4Packet + 8) = sys->ttl;
		*(ipv4Packet + 9) = 0x02;

		// IPV4 source address
		memcpy(ipv4Packet + 12, &sys->nic_address->sin_addr.S_un.S_addr, 4);

		// IPV4 destination address
		memcpy(ipv4Packet + 16, &((struct sockaddr_in *)sys->igmp_address)->sin_addr.S_un.S_addr, 4);

		// IPV4 options
		*(ipv4Packet + 20) = 0x94;
		*(ipv4Packet + 21) = 0x04;
		*(ipv4Packet + 22) = 0x00;
		*(ipv4Packet + 23) = 0x00;

		// calculate IPv4 header checksum
		checksum = CalculateChecksum(ipv4Packet, ipv4PacketHeaderLength);

		// update IPv4 header checksum
		*(ipv4Packet + 10) = ((checksum & 0xFF00) >> 8);
		*(ipv4Packet + 11) = (checksum & 0x00FF);

		// add IGMPv2 payload
		memcpy(ipv4Packet + ipv4PacketHeaderLength, igmpPacket, 0x08);
		
		// everything correct, try to send IGMP packet
		if (sendto(sys->igmp_fd, ipv4Packet, ipv4PacketLength, 0, sys->igmp_address, sys->igmp_address_length) == SOCKET_ERROR)
		{
			msg_Err (access, "(net_SubscribeRaw) sendto() error: %s", vlc_strerror_c(net_errno));
			result = VLC_EGENERIC;
		}
	}
	else
	{
		msg_Err (access, "(net_SubscribeRaw) not enough memory for IGMP or IPV4 packet");
		result = VLC_ENOMEM;
	}
	
	if (igmpPacket != NULL)
	{
		free(igmpPacket);
	}
	if (ipv4Packet != NULL)
	{
		free(ipv4Packet);
	}
	
	return result;
}

/*****************************************************************************
 * Open: open the socket
 *****************************************************************************/
static int Open( vlc_object_t *p_this )
{
    stream_t     *p_access = (stream_t*)p_this;
    access_sys_t *sys;

    if( p_access->b_preparsing )
        return VLC_EGENERIC;

    sys = vlc_obj_malloc( p_this, sizeof( *sys ) );
    if( unlikely( sys == NULL ) )
        return VLC_ENOMEM;
	
	sys->fd = -1;
	sys->igmp_fd = -1;
	sys->dscp = 0;
	sys->ecn = 0;
#ifdef _WIN32
	sys->identification = GetTickCount();
#else
	sys->identification = 0x0000;
#endif
	sys->ttl = 1;
	sys->igmpInterval = 30000;
	sys->nic_name = NULL;
	sys->nic_address = NULL;
	sys->nic_address_length = 0;
	sys->igmp_address = NULL;
	sys->igmp_address_length = 0;
	sys->lastIgmpPacket = 0;

    p_access->p_sys = sys;

    /* Set up p_access */
    ACCESS_SET_CALLBACKS( NULL, BlockUDP, Control, NULL );

    char *psz_name = strdup( p_access->psz_location );
    char *psz_parser;
    const char *psz_server_addr, *psz_bind_addr = "";
    int  i_bind_port = 1234, i_server_port = 0;

    if( unlikely(psz_name == NULL) )
        return VLC_ENOMEM;
	
    /* Parse psz_name syntax :
     * [serveraddr[:serverport]][@[bindaddr]:[bindport]] */
    psz_parser = strchr( psz_name, '@' );
    if( psz_parser != NULL )
    {
        /* Found bind address and/or bind port */
        *psz_parser++ = '\0';
        psz_bind_addr = psz_parser;

        if( psz_bind_addr[0] == '[' )
            /* skips bracket'd IPv6 address */
            psz_parser = strchr( psz_parser, ']' );

        if( psz_parser != NULL )
        {
            psz_parser = strchr( psz_parser, ':' );
            if( psz_parser != NULL )
            {
                *psz_parser++ = '\0';
                i_bind_port = atoi( psz_parser );
            }
        }
    }

    psz_server_addr = psz_name;
    psz_parser = ( psz_server_addr[0] == '[' )
        ? strchr( psz_name, ']' ) /* skips bracket'd IPv6 address */
        : psz_name;

    if( psz_parser != NULL )
    {
        psz_parser = strchr( psz_parser, ':' );
        if( psz_parser != NULL )
        {
            *psz_parser++ = '\0';
            i_server_port = atoi( psz_parser );
        }
    }
	
	char *psz_params = strchr( p_access->psz_location, '?' );
	if (psz_params != NULL)
	{
		psz_params++;
		
		do
		{
			char *psz_next_param = strchr(psz_params, '&');
			
			size_t param_len = (psz_next_param != NULL) ? (size_t)(psz_next_param - psz_params) : strlen(psz_params);
			param_len++;
			
			char *psz_param = malloc(param_len * sizeof(char));
			
			if (psz_next_param != NULL)
			{
				psz_next_param++;
			}
			
			if (psz_param != NULL)
			{
				memset(psz_param, 0, param_len);
				strncpy(psz_param, psz_params, (param_len - 1));
				
				char *psz_param_value = strchr(psz_param, '=');
				if (psz_param_value != NULL)
				{
					size_t param_name_len = psz_param_value - psz_param;
					param_name_len++;
					psz_param_value++;
					
					char *psz_param_name = malloc(param_name_len * sizeof(char));
					if (psz_param_name != NULL)
					{
						memset(psz_param_name, 0, param_name_len);
						strncpy(psz_param_name, psz_param, (param_name_len - 1));
						
						if (stricmp(psz_param_name, "interface") == 0)
						{
							// interface
							size_t psz_param_value_len = strlen(psz_param_value);
							psz_param_value_len++;
					
							sys->nic_name = malloc(psz_param_value_len * sizeof(char));
							
							if (sys->nic_name != NULL)
							{
								memset(sys->nic_name, 0, psz_param_value_len);
								strncpy(sys->nic_name, psz_param_value, psz_param_value_len - 1);
							}
						}
						else if (stricmp(psz_param_name, "dscp") == 0)
						{
							// DSCP
					
							sys->dscp = atoi(psz_param_value);
						}
						else if (stricmp(psz_param_name, "ecn") == 0)
						{
							// ECN

							sys->ecn = atoi(psz_param_value);
						}
						else if (stricmp(psz_param_name, "identification") == 0)
						{
							// identification
					
							sys->identification = atoi(psz_param_value);
						}
						else if (stricmp(psz_param_name, "ttl") == 0)
						{
							// TTL
					
							sys->ttl = atoi(psz_param_value);
						}
						else if (stricmp(psz_param_name, "igmpinterval") == 0)
						{
							// IGMP interval
					
							sys->igmpInterval = atoi(psz_param_value);
						}
						
						free(psz_param_name);
					}
				}
				
				free(psz_param);
				psz_param = NULL;
			}
			
			psz_params = psz_next_param;
		}
		while (psz_params != NULL);
		
		msg_Dbg( p_access, "interface: '%s'", (sys->nic_name == NULL) ? "NULL" : sys->nic_name );
		msg_Dbg( p_access, "DSCP: %d", sys->dscp );
		msg_Dbg( p_access, "ECN: %d", sys->ecn );
		msg_Dbg( p_access, "TTL: %d", sys->ttl );
		msg_Dbg( p_access, "identification: %d", sys->identification );
		msg_Dbg( p_access, "IGMP interval: %d (ms)", sys->igmpInterval );
	}
	
	msg_Dbg( p_access, "opening raw server=%s:%d local=%s:%d",
             psz_server_addr, i_server_port, psz_bind_addr, i_bind_port );
			 
	sys->igmp_fd = net_OpenDgramRaw( p_access, psz_bind_addr, i_bind_port,
			psz_server_addr, i_server_port, 0x02 );
    
	if ( sys->igmp_fd != -1)
	{
#ifdef _WIN32		
		sys->lastIgmpPacket = GetTickCount();
#else
		sys->lastIgmpPacket = 0x00000000;
#endif	
		
		msg_Dbg( p_access, "opening server=%s:%d local=%s:%d",
             psz_server_addr, i_server_port, psz_bind_addr, i_bind_port );

		sys->fd = net_OpenDgram( p_access, psz_bind_addr, i_bind_port,
			psz_server_addr, i_server_port, IPPROTO_UDP );	
	}
	
    free( psz_name );
	
    if( sys->igmp_fd == -1 )
    {
        msg_Err( p_access, "cannot open raw socket" );
        return VLC_EGENERIC;
    }
	
	if( sys->fd == -1 )
    {
        msg_Err( p_access, "cannot open socket" );
		
		net_UnsubscribeRaw( p_this );
		net_Close( sys->igmp_fd );
		sys->igmp_fd = -1;
		
        return VLC_EGENERIC;
    }

    sys->mtu = 7 * 188;

    sys->timeout = var_InheritInteger( p_access, "udp-timeout");
    if( sys->timeout > 0)
        sys->timeout *= 1000;

    return VLC_SUCCESS;
}

/*****************************************************************************
 * Close: free unused data structures
 *****************************************************************************/
static void Close( vlc_object_t *p_this )
{
    stream_t     *p_access = (stream_t*)p_this;
    access_sys_t *sys = p_access->p_sys;

	if ( sys->igmp_fd != -1)
	{
		net_UnsubscribeRaw(p_this);
		net_Close( sys->igmp_fd );
		sys->igmp_fd = -1;
	}
	if ( sys->fd != -1)
	{
		net_Close( sys->fd );
		sys->fd = -1;
	}
	
	if (sys->nic_name != NULL)
	{
		free(sys->nic_name);
		sys->nic_name = NULL;
	}
	if (sys->nic_address != NULL)
	{
		free(sys->nic_address);
		sys->nic_address = NULL;
		sys->nic_address_length = 0;
	}
	if (sys->igmp_address != NULL)
	{
		free(sys->igmp_address);
		sys->igmp_address = NULL;
		sys->igmp_address_length = 0;
	}
}

/*****************************************************************************
 * Control:
 *****************************************************************************/
static int Control( stream_t *p_access, int i_query, va_list args )
{
    bool    *pb_bool;
    int64_t *pi_64;

    switch( i_query )
    {
        case STREAM_CAN_SEEK:
        case STREAM_CAN_FASTSEEK:
        case STREAM_CAN_PAUSE:
        case STREAM_CAN_CONTROL_PACE:
            pb_bool = va_arg( args, bool * );
            *pb_bool = false;
            break;

        case STREAM_GET_PTS_DELAY:
            pi_64 = va_arg( args, int64_t * );
            *pi_64 = INT64_C(1000)
                   * var_InheritInteger(p_access, "network-caching");
            break;

        default:
            return VLC_EGENERIC;
    }
    return VLC_SUCCESS;
}

/*****************************************************************************
 * BlockUDP:
 *****************************************************************************/
static block_t *BlockUDP(stream_t *access, bool *restrict eof)
{
    access_sys_t *sys = access->p_sys;
#ifdef _WIN32
	uint32_t current = GetTickCount();
	
	if (current > (sys->lastIgmpPacket + sys->igmpInterval))
	{
		if (!net_SubscribeRaw(access))
		{
			sys->lastIgmpPacket = current;
		}
	}
#else
	net_SubscribeRaw(access);
	sys->lastIgmpPacket = 0x00000000;
#endif	

    block_t *pkt = block_Alloc(sys->mtu);
    if (unlikely(pkt == NULL))
    {   /* OOM - dequeue and discard one packet */
        char dummy;
        recv(sys->fd, &dummy, 1, 0);
        return NULL;
    }

#ifdef __linux__
    const int trunc_flag = MSG_TRUNC;
#else
    const int trunc_flag = 0;
#endif

    struct iovec iov = {
        .iov_base = pkt->p_buffer,
        .iov_len = sys->mtu,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_flags = trunc_flag,
    };

    struct pollfd ufd[1];

    ufd[0].fd = sys->fd;
    ufd[0].events = POLLIN;

    switch (vlc_poll_i11e(ufd, 1, sys->timeout))
    {
        case 0:
            msg_Err(access, "receive time-out");
            *eof = true;
            /* fall through */
        case -1:
            goto skip;
     }

    ssize_t len = recvmsg(sys->fd, &msg, trunc_flag);

    if (len < 0)
    {
skip:
        block_Release(pkt);
        return NULL;
    }

    if (msg.msg_flags & trunc_flag)
    {
        msg_Err(access, "%zd bytes packet truncated (MTU was %zu)",
                len, sys->mtu);
        pkt->i_flags |= BLOCK_FLAG_CORRUPTED;
        sys->mtu = len;
    }
    else
        pkt->i_buffer = len;

    return pkt;
}