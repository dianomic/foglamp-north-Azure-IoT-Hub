/*
 * FogLAMP Azure IoT-Hub north plugin.
 *
 * Copyright (c) 2019 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Mark Riddoch, Stefano Simonelli
 */
#include <azure_iothub.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "jwt.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "MQTTClient.h"
#include "simple_https.h"
#include <rapidjson/document.h>

using namespace rapidjson;
using namespace std;

// FIXME_I:
const string AZURE_IOTHUB::m_apiAddress("TBD");

/**
 * Constructor for the AZURE_IOTHUB object
 */
AZURE_IOTHUB::AZURE_IOTHUB() :
                m_jwtStr(NULL), m_subscribed(false), m_connected(false),
                m_lastDelivered(0), m_lastSent(0), m_jwtAPI(NULL), m_jwtExpire(0)
{
        m_log = Logger::getLogger();
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_digests();
        OpenSSL_add_all_ciphers();

	Logger::getLogger()->setMinLevel("debug");
	m_log->debug("call AZURE_IOTHUB");
}

/**
 * Destructor fpr the AZURE_IOTHUB object
 */
AZURE_IOTHUB::~AZURE_IOTHUB()
{
        if (m_jwtStr)
        {
                free(m_jwtStr);
                m_jwtStr = NULL;
        }
        if (m_jwtAPI)
        {
                free(m_jwtAPI);
                m_jwtAPI = NULL;
        }
	Logger::getLogger()->setMinLevel("debug");
	m_log->debug("call ~AZURE_IOTHUB");
}


/**
 * AZURE_IOTHUB configuration method. This is mostly concerned with getting
 * the data from the FogLAMP configuration category that defines
 * the parameters of the AZURE_IOTHUB we will connect with.
 *
 * @param conf	FogLAMP configuration category
 */
void AZURE_IOTHUB::configure(const ConfigCategory *conf)
{
	if (conf->itemExists("iot_hub_name"))
		m_iotHubName = conf->getValue("iot_hub_name");
	else
		m_log->error("Missing Azure IoT-Hub name in configuration");

	// To be implemented
	Logger::getLogger()->setMinLevel("debug");
	m_log->debug("call configure");

	// Populate the list of devices from GCP
	getDevices();
}

/**
 * Connect to the Azure IoT-Hub using MQTT
 *
 * @return connection status
 */
int AZURE_IOTHUB::connect()
{
	int rc = -1;

	// To be implemented
	rc = MQTTCLIENT_SUCCESS;
	Logger::getLogger()->setMinLevel("debug");
	m_log->debug("call connect");

	return rc;
}

/**
 * Send a block of reading to Azure IoT-Hub service using MQTT
 *
 * @param readings	The readings to send
 * @return 		The number of readings sent
 */
uint32_t AZURE_IOTHUB::send(const vector<Reading *>& readings)
{
	uint32_t	n = 0;

	// To be implemented
	n = 10;
	Logger::getLogger()->setMinLevel("debug");
	m_log->debug("call send new");

	return n;
}

/**
 * Populate the list of devices defined in the IoT Hub registry
 */
void AZURE_IOTHUB::getDevices()
{
	HttpsClient sender(m_apiAddress, false);
	SimpleWeb::CaseInsensitiveMultimap header;
	char		url[1024];

	header.emplace("Content-Type", "application/x-www-form-urlencoded");
	header.emplace("Authorization", "Bearer " + getAuthToken());

	// To be implemented
	// FIXME_I:
	Logger::getLogger()->setMinLevel("debug");
	m_log->debug("call getDevices");
}


/**
 * Get an authentication token for the Azure IoT-Hub
 *
 * @return The authentication token
 */
string AZURE_IOTHUB::getAuthToken()
{
	// FIXME_I:
	HttpsClient sender("TBD", false);
	SimpleWeb::CaseInsensitiveMultimap header;
	char		auth[1024];

	// To be implemented
	// FIXME_I:
	m_authToken = "";
	Logger::getLogger()->setMinLevel("debug");
	m_log->debug("call getAuthToken");

	return m_authToken;
}



