/*****************************************************************************
 * udp.c:
 *****************************************************************************
 * Copyright (C) 2004-2006 VLC authors and VideoLAN
 * Copyright © 2006-2007 Rémi Denis-Courmont
 *
 * $Id$
 *
 * Authors: Laurent Aimar <fenrir@videolan.org>
 *          Rémi Denis-Courmont <rem # videolan.org>
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

#include <vlc_common.h>

#include <errno.h>
#include <assert.h>

#include <vlc_network.h>
#include <vlc_stream.h>

#ifdef _WIN32
#   undef EAFNOSUPPORT
#   define EAFNOSUPPORT WSAEAFNOSUPPORT
#else
#   include <unistd.h>
#   ifdef HAVE_NET_IF_H
#       include <net/if.h>
#   endif
#endif

#ifdef HAVE_LINUX_DCCP_H
# include <linux/dccp.h>
# ifndef SOCK_DCCP /* provisional API */
#  define SOCK_DCCP 6
# endif
#endif

#ifndef SOL_IP
# define SOL_IP IPPROTO_IP
#endif
#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef IPPROTO_IPV6
# define IPPROTO_IPV6 41 /* IANA */
#endif
#ifndef SOL_DCCP
# define SOL_DCCP IPPROTO_DCCP
#endif
#ifndef IPPROTO_DCCP
# define IPPROTO_DCCP 33 /* IANA */
#endif
#ifndef SOL_UDPLITE
# define SOL_UDPLITE IPPROTO_UDPLITE
#endif
#ifndef IPPROTO_UDPLITE
# define IPPROTO_UDPLITE 136 /* IANA */
#endif

#if defined (HAVE_NETINET_UDPLITE_H)
# include <netinet/udplite.h>
#elif defined (__linux__)
/* still missing from glibc 2.6 */
# define UDPLITE_SEND_CSCOV     10
# define UDPLITE_RECV_CSCOV     11
#endif

#ifdef _WIN32
#include <iphlpapi.h>
#endif

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

extern int net_Socket( vlc_object_t *p_this, int i_family, int i_socktype,
                       int i_protocol );

/* */
static int net_SetupDgramSocket (vlc_object_t *p_obj, int fd,
                                 const struct addrinfo *ptr)
{
#ifdef SO_REUSEPORT
    if (setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, &(int){ 1 }, sizeof (int)) < 0)
	{
		msg_Err( p_obj, "setsockopt(SO_REUSEPORT) error: %s", vlc_strerror_c(net_errno) );
	}
#endif
#ifdef SO_REUSEADDR
    if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof (int)) < 0)
	{
		msg_Err( p_obj, "setsockopt(SO_REUSEADDR) error: %s", vlc_strerror_c(net_errno) );
	}
#endif

#if defined (_WIN32)

    /* Check windows version so we know if we need to increase receive buffers
     * for Windows 7 and earlier

     * SetSocketMediaStreamingMode is present in win 8 and later, so we set
     * receive buffer if that isn't present
     */
#if (_WIN32_WINNT < _WIN32_WINNT_WIN8)
    HINSTANCE h_Network = LoadLibrary(TEXT("Windows.Networking.dll"));
    if( (h_Network == NULL) ||
        (GetProcAddress( h_Network, "SetSocketMediaStreamingMode" ) == NULL ) )
    {
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF,
                         (void *)&(int){ 0x80000 }, sizeof (int));
    }
    if( h_Network )
        FreeLibrary( h_Network );
#endif

    if (net_SockAddrIsMulticast (ptr->ai_addr, ptr->ai_addrlen)
     && (sizeof (struct sockaddr_storage) >= ptr->ai_addrlen))
    {
        // This works for IPv4 too - don't worry!
        struct sockaddr_in6 dumb =
        {
            .sin6_family = ptr->ai_addr->sa_family,
            .sin6_port =  ((struct sockaddr_in *)(ptr->ai_addr))->sin_port
        };

        bind (fd, (struct sockaddr *)&dumb, ptr->ai_addrlen);
    }
    else
#endif
    if (bind (fd, ptr->ai_addr, ptr->ai_addrlen))
    {
        msg_Err( p_obj, "socket bind error: %s", vlc_strerror_c(net_errno) );
        net_Close (fd);
        return -1;
    }
    return fd;
}

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

static char *ConvertToMultiByteW(const wchar_t *string)
{
	char *result = NULL;

	if (string != NULL)
	{
		size_t length = 0;
		if (wcstombs_s(&length, NULL, 0, string, wcslen(string)) == 0)
		{
			result = malloc(length);
			if (result != NULL)
			{
				memset(result, 0, length);
				if (wcstombs_s(&length, result, length, string, wcslen(string)) != 0)
				{
					// error occurred but buffer is created
					free(result);
					result = NULL;
				}
			}
		}
	}

	return result;
}

static struct sockaddr_in *GetInterfaceAddressIpv4(vlc_object_t *obj, const char *nic_name)
{
#ifdef _WIN32
	struct sockaddr_in *result = NULL;
	
	ULONG bufferLen = 0;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
	PIP_ADAPTER_ADDRESSES addresses = NULL;
	
	if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addresses, &bufferLen) == ERROR_BUFFER_OVERFLOW)
    {
		addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferLen);
		if (addresses == NULL)
		{
			msg_Err (obj, "not enough memory for adapter IP addresses");
		}
		else
		{
			int res = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addresses, &bufferLen);
			bool found = false;
			
			if (res == ERROR_SUCCESS)
			{
				for (PIP_ADAPTER_ADDRESSES address = addresses; ((!found) && (address != NULL)); address = address->Next)
				{
					char *friendlyName = ConvertToMultiByteW(address->FriendlyName);
					
					if (friendlyName != NULL)
					{
						msg_Dbg (obj, "adapter name: '%s'", address->AdapterName);
						msg_Dbg (obj, "adapter friendly name: '%s'", friendlyName);
						msg_Dbg (obj, "adapter operation status: %d", address->OperStatus);
					
						if (((nic_name != NULL) && (strcmp(friendlyName, nic_name) == 0)) ||
							((nic_name == NULL) && (result == NULL) && (address->OperStatus == IfOperStatusUp)))
						{
							// found specified adapter
							for (PIP_ADAPTER_UNICAST_ADDRESS unicastAddress = address->FirstUnicastAddress; ((!found) && (unicastAddress != NULL)); unicastAddress = unicastAddress->Next)
							{
								if (unicastAddress->Address.iSockaddrLength == sizeof(struct sockaddr_in))
								{
									// IPv4 address
								
									if (result != NULL)
									{
										free(result);
										result = NULL;
									}
							
									result = malloc(unicastAddress->Address.iSockaddrLength);
									if (result != NULL)
									{
										memset(result, 0, unicastAddress->Address.iSockaddrLength);
										memcpy(result, unicastAddress->Address.lpSockaddr, unicastAddress->Address.iSockaddrLength);
									
										found = true;
									}
								}
							}
						}
					
						free(friendlyName);
					}
				}
			}
			else
			{
				msg_Err (obj, "GetAdaptersAddresses() error code: %d", res);
			}
		  
			free(addresses);
		}
    }
	
	return result;
#else
	return NULL;
#endif	
}

/* */
static int net_ListenSingle (vlc_object_t *obj, const char *host, int port,
                             int protocol)
{
    struct addrinfo hints = {
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = protocol,
        .ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_IDN,
    }, *res;

    if (host && !*host)
        host = NULL;

    msg_Dbg (obj, "(net_ListenSingle): opening %s datagram port %d",
             host ? host : "any", port);

    int val = vlc_getaddrinfo (host, port, &hints, &res);
    if (val)
    {
        msg_Err (obj, "(net_ListenSingle) cannot resolve %s port %d : %s", host, port,
                 gai_strerror (val));
        return -1;
    }

    val = -1;

    for (const struct addrinfo *ptr = res; ptr != NULL; ptr = ptr->ai_next)
    {
        int fd = net_Socket (obj, ptr->ai_family, ptr->ai_socktype,
                             ptr->ai_protocol);
        if (fd == -1)
        {
            msg_Dbg (obj, "(net_ListenSingle) socket error: %s", vlc_strerror_c(net_errno));
            continue;
        }

#ifdef IPV6_V6ONLY
        /* Try dual-mode IPv6 if available. */
        if (ptr->ai_family == AF_INET6)
            setsockopt (fd, SOL_IPV6, IPV6_V6ONLY, &(int){ 0 }, sizeof (int));
#endif
        fd = net_SetupDgramSocket( obj, fd, ptr );
        if( fd == -1 )
            continue;

        if (net_SockAddrIsMulticast (ptr->ai_addr, ptr->ai_addrlen)
         && net_Subscribe (obj, fd, ptr->ai_addr, ptr->ai_addrlen))
        {
            net_Close (fd);
            continue;
        }

        val = fd;
        break;
    }

    freeaddrinfo (res);
    return val;
}

/* */
static int net_ListenSingleRaw (vlc_object_t *obj, const char *host, int port,
                             int protocol)
{
	stream_t     *p_access = (stream_t*)obj;
	access_sys_t *sys = p_access->p_sys;
	
    struct addrinfo hints = {
        .ai_socktype = SOCK_RAW,
        .ai_protocol = protocol,
        .ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_IDN,
    }, *res;

    if (host && !*host)
        host = NULL;

    msg_Dbg (obj, "(net_ListenSingleRaw) opening %s datagram port %d",
             host ? host : "any", port);

    int val = vlc_getaddrinfo (host, port, &hints, &res);
    if (val)
    {
        msg_Err (obj, "(net_ListenSingleRaw) cannot resolve %s port %d : %s", host, port,
                 gai_strerror (val));
        return -1;
    }

    val = -1;

    for (const struct addrinfo *ptr = res; ptr != NULL; ptr = ptr->ai_next)
    {
        int fd = net_Socket (obj, ptr->ai_family, ptr->ai_socktype,
                             ptr->ai_protocol);
        if (fd == -1)
        {
            msg_Dbg (obj, "(net_ListenSingleRaw) socket error: %s", vlc_strerror_c(net_errno));
            continue;
        }

#ifdef IPV6_V6ONLY
        /* Try dual-mode IPv6 if available. */
        if (ptr->ai_family == AF_INET6)
		{
			msg_Dbg (obj, "(net_ListenSingleRaw) AF_INET6 not supported");
			continue;
		}
#endif

        fd = net_SetupDgramSocket( obj, fd, ptr );
        if( fd == -1 )
            continue;
		
		// include IPv4 header with packet data
		if (setsockopt (fd, IPPROTO_IP, IP_HDRINCL, &(int){ 1 }, sizeof (int)) < 0)
		{
			msg_Err( obj, "(net_ListenSingleRaw) setsockopt(IP_HDRINCL) error: %s", vlc_strerror_c(net_errno) );
			net_Close(fd);
			fd = -1;
			continue;
		}
		
		if (net_SockAddrIsMulticast (ptr->ai_addr, ptr->ai_addrlen))
		{
			struct sockaddr_in *interfaceAddress = GetInterfaceAddressIpv4(obj, sys->nic_name);
			if (interfaceAddress == NULL)
			{
				msg_Err (obj, "(net_ListenSingleRaw) no IPV4 address for network interface: '%s'", (sys->nic_name == NULL) ? "" : sys->nic_name);
				net_Close(fd);
				fd = -1;
				continue;
			}
			
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
				memcpy(igmpPacket + 4, &((struct sockaddr_in *)ptr->ai_addr)->sin_addr.S_un.S_addr, 4);

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
				memcpy(ipv4Packet + 12, &interfaceAddress->sin_addr.S_un.S_addr, 4);

				// IPV4 destination address
				memcpy(ipv4Packet + 16, &((struct sockaddr_in *)ptr->ai_addr)->sin_addr.S_un.S_addr, 4);

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
				sys->igmp_address = malloc(ptr->ai_addrlen);
				sys->nic_address = malloc(sizeof(struct sockaddr_in));
				
				if ((sys->igmp_address != NULL) && (sys->nic_address != NULL))
				{
					memset(sys->igmp_address, 0, ptr->ai_addrlen);
					memcpy(sys->igmp_address, ptr->ai_addr, ptr->ai_addrlen);
					sys->igmp_address_length = ptr->ai_addrlen;
					
					memset(sys->nic_address, 0, sizeof(struct sockaddr_in));
					memcpy(sys->nic_address, interfaceAddress, sizeof(struct sockaddr_in));
					sys->nic_address_length = sizeof(struct sockaddr_in);
				
					if (sendto(fd, ipv4Packet, ipv4PacketLength, 0, ptr->ai_addr, ptr->ai_addrlen) == SOCKET_ERROR)
					{
						msg_Err (obj, "(net_ListenSingleRaw) sendto() error: %s", vlc_strerror_c(net_errno));
						net_Close (fd);
						fd = -1;
						
						free(sys->igmp_address);
						free(sys->nic_address);
						
						sys->igmp_address = NULL;
						sys->igmp_address_length = 0;
						sys->nic_address = NULL;
						sys->nic_address_length = 0;
					}
				}
				else
				{
					msg_Err (obj, "(net_ListenSingleRaw) not enough memory to remember IGMP address");
					net_Close (fd);
					fd = -1;
					
					if (sys->igmp_address != NULL)
					{
						free(sys->igmp_address);
					}
					if (sys->nic_address != NULL)
					{
						free(sys->nic_address);
					}
					
					sys->igmp_address_length = 0;
					sys->nic_address_length = 0;
				}
			}
			else
			{
				msg_Err (obj, "(net_ListenSingleRaw) not enough memory for IGMP or IPV4 packet");
				net_Close (fd);
				fd = -1;
			}
			
			free(interfaceAddress);
			if (igmpPacket != NULL)
			{
				free(igmpPacket);
			}
			if (ipv4Packet != NULL)
			{
				free(ipv4Packet);
			}
		}
		
        val = fd;
        break;
    }

    freeaddrinfo (res);
    return val;
}

static int net_SetMcastHopLimit( vlc_object_t *p_this,
                                 int fd, int family, int hlim )
{
    int proto, cmd;

    /* There is some confusion in the world whether IP_MULTICAST_TTL
     * takes a byte or an int as an argument.
     * BSD seems to indicate byte so we are going with that and use
     * int as a fallback to be safe */
    switch( family )
    {
#ifdef IP_MULTICAST_TTL
        case AF_INET:
            proto = SOL_IP;
            cmd = IP_MULTICAST_TTL;
            break;
#endif

#ifdef IPV6_MULTICAST_HOPS
        case AF_INET6:
            proto = SOL_IPV6;
            cmd = IPV6_MULTICAST_HOPS;
            break;
#endif

        default:
            errno = EAFNOSUPPORT;
            msg_Warn( p_this, "%s", vlc_strerror_c(EAFNOSUPPORT) );
            return VLC_EGENERIC;
    }

    if( setsockopt( fd, proto, cmd, &hlim, sizeof( hlim ) ) < 0 )
    {
        /* BSD compatibility */
        unsigned char buf;

        msg_Dbg( p_this, "cannot set hop limit (%d): %s", hlim,
                 vlc_strerror_c(net_errno) );
        buf = (unsigned char)(( hlim > 255 ) ? 255 : hlim);
        if( setsockopt( fd, proto, cmd, &buf, sizeof( buf ) ) )
        {
            msg_Err( p_this, "cannot set hop limit (%d): %s", hlim,
                     vlc_strerror_c(net_errno) );
            return VLC_EGENERIC;
        }
    }

    return VLC_SUCCESS;
}


static int net_SetMcastOut (vlc_object_t *p_this, int fd, int family,
                            const char *iface)
{
    int scope = if_nametoindex (iface);
    if (scope == 0)
    {
        msg_Err (p_this, "invalid multicast interface: %s", iface);
        return -1;
    }

    switch (family)
    {
#ifdef IPV6_MULTICAST_IF
        case AF_INET6:
            if (setsockopt (fd, SOL_IPV6, IPV6_MULTICAST_IF,
                            &scope, sizeof (scope)) == 0)
                return 0;
            break;
#endif

#ifdef __linux__
        case AF_INET:
        {
            struct ip_mreqn req = { .imr_ifindex = scope };
            if (setsockopt (fd, SOL_IP, IP_MULTICAST_IF,
                            &req, sizeof (req)) == 0)
                return 0;
            break;
        }
#endif
        default:
            errno = EAFNOSUPPORT;
    }
    msg_Err (p_this, "cannot force multicast interface %s: %s", iface,
             vlc_strerror_c(errno));
    return -1;
}


static unsigned var_GetIfIndex (vlc_object_t *obj)
{
    char *ifname = var_InheritString (obj, "miface");
    if (ifname == NULL)
        return 0;

    unsigned ifindex = if_nametoindex (ifname);
    if (ifindex == 0)
        msg_Err (obj, "invalid multicast interface: %s", ifname);
    free (ifname);
    return ifindex;
}


/**
 * IP-agnostic multicast join,
 * with fallback to old APIs, and fallback from SSM to ASM.
 */
static int
net_SourceSubscribe (vlc_object_t *obj, int fd,
                     const struct sockaddr *src, socklen_t srclen,
                     const struct sockaddr *grp, socklen_t grplen)
{
/* MCAST_JOIN_SOURCE_GROUP was introduced to OS X in v10.7, but it doesn't work,
 * so ignore it to use the same code path as on 10.5 or 10.6 */
#if defined (MCAST_JOIN_SOURCE_GROUP) && !defined (__APPLE__)
    /* Family-agnostic Source-Specific Multicast join */
    int level;
    struct group_source_req gsr;

    memset (&gsr, 0, sizeof (gsr));
    gsr.gsr_interface = var_GetIfIndex (obj);

    switch (grp->sa_family)
    {
#ifdef AF_INET6
        case AF_INET6:
        {
            const struct sockaddr_in6 *g6 = (const struct sockaddr_in6 *)grp;

            level = SOL_IPV6;
            assert (grplen >= sizeof (struct sockaddr_in6));
            if (g6->sin6_scope_id != 0)
                gsr.gsr_interface = g6->sin6_scope_id;
            break;
        }
#endif
        case AF_INET:
            level = SOL_IP;
            break;
        default:
            errno = EAFNOSUPPORT;
            return -1;
    }

    assert (grplen <= sizeof (gsr.gsr_group));
    memcpy (&gsr.gsr_source, src, srclen);
    assert (srclen <= sizeof (gsr.gsr_source));
    memcpy (&gsr.gsr_group,  grp, grplen);
    if (setsockopt (fd, level, MCAST_JOIN_SOURCE_GROUP,
                    &gsr, sizeof (gsr)) == 0)
        return 0;

#else
    if (src->sa_family != grp->sa_family)
    {
        errno = EAFNOSUPPORT;
        return -1;
    }

    switch (grp->sa_family)
    {
# ifdef IP_ADD_SOURCE_MEMBERSHIP
        /* IPv4-specific API */
        case AF_INET:
        {
            struct ip_mreq_source imr;

            memset (&imr, 0, sizeof (imr));
            assert (grplen >= sizeof (struct sockaddr_in));
            imr.imr_multiaddr = ((const struct sockaddr_in *)grp)->sin_addr;
            assert (srclen >= sizeof (struct sockaddr_in));
            imr.imr_sourceaddr = ((const struct sockaddr_in *)src)->sin_addr;
            if (setsockopt (fd, SOL_IP, IP_ADD_SOURCE_MEMBERSHIP,
                            &imr, sizeof (imr)) == 0)
                return 0;
            break;
        }
# endif
        default:
            errno = EAFNOSUPPORT;
    }

#endif
    msg_Err (obj, "cannot join source multicast group: %s",
             vlc_strerror_c(net_errno));
    msg_Warn (obj, "trying ASM instead of SSM...");
    return net_Subscribe (obj, fd, grp, grplen);
}


int net_Subscribe (vlc_object_t *obj, int fd,
                   const struct sockaddr *grp, socklen_t grplen)
{
/* MCAST_JOIN_GROUP was introduced to OS X in v10.7, but it doesn't work,
 * so ignore it to use the same code as on 10.5 or 10.6 */
#if defined (MCAST_JOIN_GROUP) && !defined (__APPLE__)
    /* Family-agnostic Any-Source Multicast join */
    int level;
    struct group_req gr;

    memset (&gr, 0, sizeof (gr));
    gr.gr_interface = var_GetIfIndex (obj);

    switch (grp->sa_family)
    {
#ifdef AF_INET6
        case AF_INET6:
        {
            const struct sockaddr_in6 *g6 = (const struct sockaddr_in6 *)grp;

            level = SOL_IPV6;
            assert (grplen >= sizeof (struct sockaddr_in6));
            if (g6->sin6_scope_id != 0)
                gr.gr_interface = g6->sin6_scope_id;
            break;
        }
#endif
        case AF_INET:
            level = SOL_IP;
            break;
        default:
            errno = EAFNOSUPPORT;
            return -1;
    }

    assert (grplen <= sizeof (gr.gr_group));
    memcpy (&gr.gr_group, grp, grplen);
    if (setsockopt (fd, level, MCAST_JOIN_GROUP, &gr, sizeof (gr)) == 0)
        return 0;

#else
    switch (grp->sa_family)
    {
# ifdef IPV6_JOIN_GROUP
        case AF_INET6:
        {
            struct ipv6_mreq ipv6mr;
            const struct sockaddr_in6 *g6 = (const struct sockaddr_in6 *)grp;

            memset (&ipv6mr, 0, sizeof (ipv6mr));
            assert (grplen >= sizeof (struct sockaddr_in6));
            ipv6mr.ipv6mr_multiaddr = g6->sin6_addr;
            ipv6mr.ipv6mr_interface = g6->sin6_scope_id;
            if (!setsockopt (fd, SOL_IPV6, IPV6_JOIN_GROUP,
                             &ipv6mr, sizeof (ipv6mr)))
                return 0;
            break;
        }
# endif
# ifdef IP_ADD_MEMBERSHIP
        case AF_INET:
        {
            struct ip_mreq imr;

            memset (&imr, 0, sizeof (imr));
            assert (grplen >= sizeof (struct sockaddr_in));
            imr.imr_multiaddr = ((const struct sockaddr_in *)grp)->sin_addr;
            if (setsockopt (fd, SOL_IP, IP_ADD_MEMBERSHIP,
                            &imr, sizeof (imr)) == 0)
                return 0;
            break;
        }
# endif
        default:
            errno = EAFNOSUPPORT;
    }

#endif
    msg_Err (obj, "cannot join multicast group: %s",
             vlc_strerror_c(net_errno));
    return -1;
}


static int net_SetDSCP( int fd, uint8_t dscp )
{
    struct sockaddr_storage addr;
    if( getsockname( fd, (struct sockaddr *)&addr, &(socklen_t){ sizeof (addr) }) )
        return -1;

    int level, cmd;

    switch( addr.ss_family )
    {
#ifdef IPV6_TCLASS
        case AF_INET6:
            level = SOL_IPV6;
            cmd = IPV6_TCLASS;
            break;
#endif

        case AF_INET:
            level = SOL_IP;
            cmd = IP_TOS;
            break;

        default:
#ifdef ENOPROTOOPT
            errno = ENOPROTOOPT;
#endif
            return -1;
    }

    return setsockopt( fd, level, cmd, &(int){ dscp }, sizeof (int));
}

#undef net_ConnectDgram
/*****************************************************************************
 * net_ConnectDgram:
 *****************************************************************************
 * Open a datagram socket to send data to a defined destination, with an
 * optional hop limit.
 *****************************************************************************/
int net_ConnectDgram( vlc_object_t *p_this, const char *psz_host, int i_port,
                      int i_hlim, int proto )
{
    struct addrinfo hints = {
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = proto,
        .ai_flags = AI_NUMERICSERV | AI_IDN,
    }, *res;
    int       i_handle = -1;
    bool      b_unreach = false;

    if( i_hlim < 0 )
        i_hlim = var_InheritInteger( p_this, "ttl" );

    msg_Dbg( p_this, "net: connecting to [%s]:%d", psz_host, i_port );

    int val = vlc_getaddrinfo (psz_host, i_port, &hints, &res);
    if (val)
    {
        msg_Err (p_this, "cannot resolve [%s]:%d : %s", psz_host, i_port,
                 gai_strerror (val));
        return -1;
    }

    for (struct addrinfo *ptr = res; ptr != NULL; ptr = ptr->ai_next)
    {
        char *str;
        int fd = net_Socket (p_this, ptr->ai_family, ptr->ai_socktype,
                             ptr->ai_protocol);
        if (fd == -1)
            continue;

        /* Allow broadcast sending */
        setsockopt (fd, SOL_SOCKET, SO_BROADCAST, &(int){ 1 }, sizeof (int));

        if( i_hlim >= 0 )
            net_SetMcastHopLimit( p_this, fd, ptr->ai_family, i_hlim );

        str = var_InheritString (p_this, "miface");
        if (str != NULL)
        {
            net_SetMcastOut (p_this, fd, ptr->ai_family, str);
            free (str);
        }

        net_SetDSCP (fd, var_InheritInteger (p_this, "dscp"));

        if( connect( fd, ptr->ai_addr, ptr->ai_addrlen ) == 0 )
        {
            /* success */
            i_handle = fd;
            break;
        }

#if defined( _WIN32 )
        if( WSAGetLastError () == WSAENETUNREACH )
#else
        if( errno == ENETUNREACH )
#endif
            b_unreach = true;
        else
            msg_Warn( p_this, "%s port %d : %s", psz_host, i_port,
                      vlc_strerror_c(errno) );
        net_Close( fd );
    }

    freeaddrinfo( res );

    if( i_handle == -1 )
    {
        if( b_unreach )
            msg_Err( p_this, "Host %s port %d is unreachable", psz_host,
                     i_port );
        return -1;
    }

    return i_handle;
}

#undef net_OpenDgram
/*****************************************************************************
 * net_OpenDgram:
 *****************************************************************************
 * OpenDgram a datagram socket and return a handle
 *****************************************************************************/
int net_OpenDgram( vlc_object_t *obj, const char *psz_bind, int i_bind,
                   const char *psz_server, int i_server, int protocol )
{
    if ((psz_server == NULL) || (psz_server[0] == '\0'))
        return net_ListenSingle (obj, psz_bind, i_bind, protocol);

    msg_Dbg (obj, "net: connecting to [%s]:%d from [%s]:%d",
             psz_server, i_server, psz_bind, i_bind);

    struct addrinfo hints = {
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = protocol,
        .ai_flags = AI_NUMERICSERV | AI_IDN,
    }, *loc, *rem;

    int val = vlc_getaddrinfo (psz_server, i_server, &hints, &rem);
    if (val)
    {
        msg_Err (obj, "cannot resolve %s port %d : %s", psz_server, i_server,
                 gai_strerror (val));
        return -1;
    }

    hints.ai_flags |= AI_PASSIVE;
    val = vlc_getaddrinfo (psz_bind, i_bind, &hints, &loc);
    if (val)
    {
        msg_Err (obj, "cannot resolve %s port %d : %s", psz_bind, i_bind,
                 gai_strerror (val));
        freeaddrinfo (rem);
        return -1;
    }

    val = -1;
    for (struct addrinfo *ptr = loc; ptr != NULL; ptr = ptr->ai_next)
    {
        int fd = net_Socket (obj, ptr->ai_family, ptr->ai_socktype,
                             ptr->ai_protocol);
        if (fd == -1)
            continue; // usually, address family not supported

        fd = net_SetupDgramSocket( obj, fd, ptr );
        if( fd == -1 )
            continue;

        for (struct addrinfo *ptr2 = rem; ptr2 != NULL; ptr2 = ptr2->ai_next)
        {
            if ((ptr2->ai_family != ptr->ai_family)
             || (ptr2->ai_socktype != ptr->ai_socktype)
             || (ptr2->ai_protocol != ptr->ai_protocol))
                continue;

            if (net_SockAddrIsMulticast (ptr->ai_addr, ptr->ai_addrlen)
              ? net_SourceSubscribe (obj, fd,
                                     ptr2->ai_addr, ptr2->ai_addrlen,
                                     ptr->ai_addr, ptr->ai_addrlen)
              : connect (fd, ptr2->ai_addr, ptr2->ai_addrlen))
            {
                msg_Err (obj, "cannot connect to %s port %d: %s",
                         psz_server, i_server, vlc_strerror_c(net_errno));
                continue;
            }
            val = fd;
            break;
        }

        if (val != -1)
            break;

        net_Close (fd);
    }

    freeaddrinfo (rem);
    freeaddrinfo (loc);
    return val;
}

#undef net_OpenDgramRaw
/*****************************************************************************
 * net_OpenDgramRaw:
 *****************************************************************************
 * OpenDgramRaw a raw datagram socket and return a handle
 *****************************************************************************/
int net_OpenDgramRaw( vlc_object_t *obj, const char *psz_bind, int i_bind,
                   const char *psz_server, int i_server, int protocol )
{
    if ((psz_server == NULL) || (psz_server[0] == '\0'))
        return net_ListenSingleRaw (obj, psz_bind, i_bind, protocol);
	
	return EAFNOSUPPORT;
}


/**
 * net_SetCSCov:
 * Sets the send and receive checksum coverage of a socket:
 * @param fd socket
 * @param sendcov payload coverage of sent packets (bytes), -1 for full
 * @param recvcov minimum payload coverage of received packets, -1 for full
 */
int net_SetCSCov (int fd, int sendcov, int recvcov)
{
    int type;

    if (getsockopt (fd, SOL_SOCKET, SO_TYPE,
                    &type, &(socklen_t){ sizeof (type) }))
        return VLC_EGENERIC;

    switch (type)
    {
#ifdef UDPLITE_RECV_CSCOV
        case SOCK_DGRAM: /* UDP-Lite */
            if (sendcov == -1)
                sendcov = 0;
            else
                sendcov += 8; /* partial */
            if (setsockopt (fd, SOL_UDPLITE, UDPLITE_SEND_CSCOV, &sendcov,
                            sizeof (sendcov)))
                return VLC_EGENERIC;

            if (recvcov == -1)
                recvcov = 0;
            else
                recvcov += 8;
            if (setsockopt (fd, SOL_UDPLITE, UDPLITE_RECV_CSCOV,
                            &recvcov, sizeof (recvcov)))
                return VLC_EGENERIC;

            return VLC_SUCCESS;
#endif
#ifdef DCCP_SOCKOPT_SEND_CSCOV
        case SOCK_DCCP: /* DCCP and its ill-named socket type */
            if ((sendcov == -1) || (sendcov > 56))
                sendcov = 0;
            else
                sendcov = (sendcov + 3) / 4;
            if (setsockopt (fd, SOL_DCCP, DCCP_SOCKOPT_SEND_CSCOV,
                            &sendcov, sizeof (sendcov)))
                return VLC_EGENERIC;

            if ((recvcov == -1) || (recvcov > 56))
                recvcov = 0;
            else
                recvcov = (recvcov + 3) / 4;
            if (setsockopt (fd, SOL_DCCP, DCCP_SOCKOPT_RECV_CSCOV,
                            &recvcov, sizeof (recvcov)))
                return VLC_EGENERIC;

            return VLC_SUCCESS;
#endif
    }
#if !defined( UDPLITE_RECV_CSCOV ) && !defined( DCCP_SOCKOPT_SEND_CSCOV )
    VLC_UNUSED(sendcov);
    VLC_UNUSED(recvcov);
#endif

    return VLC_EGENERIC;
}
