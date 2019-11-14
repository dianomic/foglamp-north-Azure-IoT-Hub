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

#include "iothub.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_c_shared_utility/http_proxy_io.h"
#include "azure_c_shared_utility/threadapi.h"

#include "azure_prov_client/prov_device_client.h"
#include "azure_prov_client/prov_security_factory.h"

// MQTT protocol
#include "iothubtransportmqtt.h"
#include "azure_prov_client/prov_transport_mqtt_client.h"

using namespace rapidjson;
using namespace std;

// FIXME_I:
const string AZURE_IOTHUB::m_apiAddress("TBD");


// Azure IoT hub
#define PROTOCOL_MQTT

// FIXME_I:
// This sample is to demostrate iothub reconnection with provisioning and should not
// be confused as production code

MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_RESULT, PROV_DEVICE_RESULT_VALUE);
MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_REG_STATUS, PROV_DEVICE_REG_STATUS_VALUES);


static const char* global_prov_uri = "global.azure-devices-provisioning.net";
// FIXME_I:
static const char* id_scope = "0ne0009009E";

static bool g_registration_complete = false;
static bool g_use_proxy = false;
static const char* PROXY_ADDRESS = "127.0.0.1";

#define PROXY_PORT                  8888
#define MESSAGES_TO_SEND            2
#define TIME_BETWEEN_MESSAGES       2

static void registration_status_callback(PROV_DEVICE_REG_STATUS reg_status, void* user_context)
{
	// FIXME_I:
	Logger *logger = Logger::getLogger();

	(void)user_context;
	logger->debug("Azure - Provisioning Status: %s", MU_ENUM_TO_STRING(PROV_DEVICE_REG_STATUS, reg_status));
}

static void register_device_callback(PROV_DEVICE_RESULT register_result, const char* iothub_uri, const char* device_id, void* user_context)
{
	// FIXME_I:
	Logger *logger = Logger::getLogger();

	(void)user_context;
	if (register_result == PROV_DEVICE_RESULT_OK)
	{
		logger->debug("Azure - Registration Information received from service: %s, deviceId: %s", iothub_uri, device_id);
	}
	else
	{
		logger->error("Azure - Failure registering device: %s", MU_ENUM_TO_STRING(PROV_DEVICE_RESULT, register_result));
	}
	g_registration_complete = true;
}


// FIXME_I:
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

/**
 * Strips Line feed and carige return
 *
 */
void StringStripCRLF2(std::string& StringToManage)
{
	string::size_type pos = 0;

	StringToManage.erase( std::remove(StringToManage.begin(), StringToManage.end(), '\r'), StringToManage.end() );

	StringToManage.erase(std::remove(StringToManage.begin(), StringToManage.end(), '\n'), StringToManage.end());

}

// FIXME_I: temporary function
std::string exec(const char* cmd) {

	std::array<char, 128> buffer;
	std::string result;
	std::string line;
	std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
	if (!pipe) throw std::runtime_error("popen() failed!");
	while (!feof(pipe.get())) {
		if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
		{
			line = buffer.data();
			StringStripCRLF2(line);
			result += line;
		}
	}
	return result;
}


string AZURE_IOTHUB::calc_hash(string &device_id)
{
	Logger *logger = Logger::getLogger();

	string symmetric_Key="xZdonZMjyuw4AsAYsw8kqmvWT9W8H6JIQvzQTPsLZz4BZ7z+lE0jDn16c+2qExzDOIiK9GuqpOFrf8U48CJbMg==";

	string cmd="echo -n " + device_id + " | openssl sha256 -mac HMAC -macopt hexkey:$(echo " + symmetric_Key + " | base64 --decode | xxd -p -u -c 1000)  -binary | base64";
	string output=exec(cmd.c_str());

	logger->debug("DBG - calc_hash cmd :%s: output :%s:",cmd.c_str(), output.c_str() );

	return output;
}


int AZURE_IOTHUB::send_data(Reading *reading)
{
	// FIXME_I:
	string payload = makePayload(reading);
	string assetName = reading->getAssetName();
	char topic[1024];

	snprintf(topic, sizeof(topic), "devices/%s/messages/events/", assetName.c_str());

}

/**
 * Construct a payload from a single reading.
 *
 * @param reading	The reading to use for payload construction
 * @return	The JSON payload
 */
string AZURE_IOTHUB::makePayload(Reading *reading)
{
	string payload = "{";
	struct timeval tm;
	reading->getTimestamp(&tm);
	payload += "\"ts\" : \"";
	// Add timestamp
	payload += reading->getAssetDateUserTime(Reading::FMT_DEFAULT, true);
	payload += "\", ";
	string assetName = reading->getAssetName();
	vector<Datapoint *> dpv = reading->getReadingData();
	for (auto dp = dpv.cbegin(); dp != dpv.cend(); dp++)
	{
		payload += (*dp)->toJSONProperty();
		if ((dp + 1) != dpv.cend())
		{
			payload += ", ";
		}
	}
	payload += "}";
	return payload;
}

int AZURE_IOTHUB::provision_device(std::string device_id)
{
	// FIXME_I:
	string step="11";

	string symmetric_Key;
	Logger *logger = Logger::getLogger();
	logger->debug("DBG - azure_provision_device %s start",step.c_str());

	symmetric_Key = calc_hash(device_id);

	SECURE_DEVICE_TYPE hsm_type;
	// FIXME_I:
	hsm_type = SECURE_DEVICE_TYPE_SYMMETRIC_KEY;

	// Used to initialize IoTHub SDK subsystem
	(void)IoTHub_Init();
	(void)prov_dev_security_init(hsm_type);

	logger->debug("DBG - azure_provision_device %s step",step.c_str());

	// FIXME_I:
	// Set the symmetric key if using they auth type
	prov_dev_set_symmetric_key_info(device_id.c_str(), symmetric_Key.c_str());

	PROV_DEVICE_TRANSPORT_PROVIDER_FUNCTION prov_transport;

	// Protocol to USE - HTTP, AMQP, AMQP_WS, MQTT, MQTT_WS
#ifdef PROTOCOL_MQTT
	prov_transport = Prov_Device_MQTT_Protocol;
#endif

	// FIXME_I:
	//logger->debug("Azure - Provisioning API Version: %s\r\n", Prov_Device_GetVersionString());

	logger->debug("DBG - azure_provision_device %s step 2",step.c_str());

	PROV_DEVICE_RESULT prov_device_result = PROV_DEVICE_RESULT_ERROR;
	PROV_DEVICE_HANDLE prov_device_handle;
	if ((prov_device_handle = Prov_Device_Create(global_prov_uri, id_scope, prov_transport)) == NULL)
	{
		logger->error("Azure - failed calling Prov_Device_Create\r\n");
		return -1;
	}
	else
	{
		logger->debug("DBG - azure_provision_device %s step 2.1",step.c_str());

		prov_device_result = Prov_Device_Register_Device(prov_device_handle, register_device_callback, NULL, registration_status_callback, NULL);

		logger->debug("Azure - Registering device :%s:  key :%s:", device_id.c_str(), symmetric_Key.c_str() );
		// FIXME_I:
		int i=0;
		do
		{
			i++;
			ThreadAPI_Sleep(1000);
		} while ( (!g_registration_complete) && i < 10);

		if (!g_registration_complete)
		{
			logger->debug("Azure - Registration failed for device :%s:", device_id.c_str());
		}

		Prov_Device_Destroy(prov_device_handle);
	}

	logger->debug("DBG - azure_provision_device %s step 3",step.c_str());

	prov_dev_security_deinit();

	// Free all the sdk subsystem
	IoTHub_Deinit();

	logger->debug("DBG - azure_provision_device %s  end",step.c_str());

	return 0;
}



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

	// FIXME_I:
	m_log->debug("DBG - call test start");

	m_log->debug("DBG - call test end");
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

	// FIXME_I:
	for(Reading *item : readings) {
		m_log->debug("DBG0 send send new :%s:", item->getAssetName().c_str());

		provision_device(item->getAssetName());
		send_data(item);
	}



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

