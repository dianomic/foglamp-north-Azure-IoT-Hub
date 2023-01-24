#ifndef _AZURE_IOTHUB_H
#define _AZURE_IOTHUB_H
#include <reading.h>
#include <config_category.h>
#include <logger.h>
#include <string>
#include "MQTTClient.h"
#include <jwt.h>
#include <set>

using namespace std;

class AZURE_IOTHUB {
	public:
		AZURE_IOTHUB();
		~AZURE_IOTHUB();

		void		configure(const ConfigCategory *conf);
		int		connect();
		uint32_t	send(const std::vector<Reading *>& readings);

                int             provision_device(string device_id);
                string          calc_hash(string &device_id);
                int             send_data(Reading *reading);
		string          makePayload(Reading *reading);
                string          get_connection_string(const string &assetName);

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
