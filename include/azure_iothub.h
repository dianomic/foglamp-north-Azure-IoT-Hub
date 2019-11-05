#ifndef _AZURE_IOTHUB_H
#define _AZURE_IOTHUB_H
#include <reading.h>
#include <config_category.h>
#include <logger.h>
#include <string>
#include "MQTTClient.h"
#include <jwt.h>
#include <set>

class AZURE_IOTHUB {
	public:
		AZURE_IOTHUB();
		~AZURE_IOTHUB();

		void		configure(const ConfigCategory *conf);
		int		connect();
		uint32_t	send(const std::vector<Reading *>& readings);

	private:
		void		getDevices();
		std::string	getAuthToken();

		MQTTClient	m_client;
		Logger		*m_log;
		char		*m_jwtStr;
		bool		m_subscribed;
		bool		m_connected;
		int		m_lastDelivered;
		int		m_lastSent;
		char		*m_jwtAPI;
		time_t		m_jwtExpire;

		std::string	m_iotHubName;

		static const std::string
				m_apiAddress;
		std::string	m_authToken;
};

#endif
