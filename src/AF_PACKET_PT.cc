/* Copyright (c) 2020 by sysmocom - s.f.m.c. GmbH
 * Author: Harald Welte <hwelte@sysmocom.de> */

#include "AF_PACKET_PT.hh"
#include "AF_PACKET_PortType.hh"

#include <cassert>

#include <poll.h>

#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <netpacket/packet.h>
#include <netinet/in.h>

#include <linux/if_ether.h>
#include <linux/if.h>

#include <osmocom/core/utils.h>

static int devname2ifindex(const char *ifname)
{
	struct ifreq ifr;
	int sk, rc;

	sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sk < 0)
		return sk;


	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = 0;

	rc = ioctl(sk, SIOCGIFINDEX, &ifr);
	close(sk);
	if (rc < 0)
		return rc;

	return ifr.ifr_ifindex;
}

static int open_socket(int ifindex)
{
	struct sockaddr_ll addr;
	int fd, rc;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = ifindex;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return fd;

	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		close(fd);
		return rc;
	}

	return fd;
}



using namespace AF__PACKET__PortTypes;

namespace AF__PACKET__PortType {




AF__PACKET__PT_PROVIDER::AF__PACKET__PT_PROVIDER(const char *par_port_name)
	:PORT(par_port_name), mSocket(-1)
{
}

AF__PACKET__PT_PROVIDER::~AF__PACKET__PT_PROVIDER()
{
	free(mNetdev_name);
}

void AF__PACKET__PT_PROVIDER::log(const char *fmt, ...)
{
	TTCN_Logger::begin_event(TTCN_WARNING);
	TTCN_Logger::log_event("AF_PACKET Test port (%s): ", get_name());
	va_list args;
	va_start(args, fmt);
	TTCN_Logger::log_event_va_list(fmt, args);
	va_end(args);
	TTCN_Logger::end_event();
}

void AF__PACKET__PT_PROVIDER::set_parameter(const char *parameter_name, const char *parameter_value)
{
	if (!strcmp(parameter_name, "netdev")) {
		if (mNetdev_name) {
			TTCN_warning("netdev port parameter specified multiple times (old: %s, new: %s)", mNetdev_name, parameter_value);
			free(mNetdev_name);
			mNetdev_name = NULL;
		}
		mNetdev_name = strdup(parameter_value);
	} else
		TTCN_error("Unsupported test port parameter `%s'.", parameter_name);
}

void AF__PACKET__PT_PROVIDER::Handle_Fd_Event(int fd, boolean is_readable, boolean is_writable, boolean is_error)
{
	if (fd != mSocket)
		return;

	if (is_readable) {
		int rc;

		rc = read(fd, mRxBuf, sizeof(mRxBuf));
		if (rc < 0)
			TTCN_error("Error reading from socket: %s", strerror(errno));
		if (rc == 0)
			TTCN_error("Dead socket: %s", strerror(errno));

		incoming_message(AF__PACKET__Unitdata(OCTETSTRING(rc, mRxBuf)));
	}
}

void AF__PACKET__PT_PROVIDER::user_map(const char *system_port, Map_Params& params)
{
	CHARSTRING p_netdev;

	log("user_map");

	if (!mNetdev_name) {
		if (params.get_nof_params() < 1)
			TTCN_error("You must specify the netdev name as map parameter or port parameter!");
		string_to_ttcn(params.get_param(0), p_netdev);
		mNetdev_name = strdup(p_netdev);
	} else {
		if (params.get_nof_params() >= 1) {
			TTCN_warning("netdev given both as port parameter (%s) and map parameter (%s), using %s",
				     mNetdev_name, params.get_param(0), params.get_param(0));
			string_to_ttcn(params.get_param(0), p_netdev);
			free(mNetdev_name);
			mNetdev_name = strdup(p_netdev);
		}
	}

	log("Using AF_PACKET netdev `%s'", mNetdev_name);

	/* resolve ifindex; open the socket; register filedescriptor */
	mIfindex = devname2ifindex(mNetdev_name);
	if (mIfindex < 0) {
		TTCN_error("Cannot resolve interface index of netdev `%s': Does it exist?",
			   mNetdev_name);
	}

	mSocket = open_socket(mIfindex);
	if (mSocket < 0) {
		TTCN_error("Cannot create/bind AF_PACKET socket: Does it exist?", mNetdev_name);
	}

	Handler_Add_Fd_Read(mSocket);
}

void AF__PACKET__PT_PROVIDER::user_unmap(const char *system_port, Map_Params& params)
{
	/* close the socket */

	if (mSocket != -1) {
		Handler_Remove_Fd(mSocket);
		close(mSocket);
	}

	free(mNetdev_name);
	mNetdev_name = NULL;
}

void AF__PACKET__PT_PROVIDER::user_start()
{
	log("user_start");
}

void AF__PACKET__PT_PROVIDER::user_stop()
{
	log("user_stop");
}



void AF__PACKET__PT_PROVIDER::outgoing_send(const AF__PACKET__Unitdata& send_par)
{
	int rc;

	assert(mSocket >= 0);

	rc = write(mSocket, send_par.data(), send_par.data().lengthof());
	if (rc < send_par.data().lengthof())
		TTCN_error("Short write on AF_PACKET socket: %s", strerror(errno));
}




} // namespace AF__PACKET__PortType
