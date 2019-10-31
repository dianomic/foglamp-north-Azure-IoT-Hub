/*
 * FogLAMP Azure IoT-Hub north plugin.
 *
 * Copyright (c) 2019 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Mark Riddoch, Stefano Simonelli
 */
#include <plugin_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string>
#include <logger.h>
#include <plugin_exception.h>
#include <iostream>
#include <config_category.h>
#include <version.h>
#include <azure_iothub.h>

#define TO_STRING(...) DEFER(TO_STRING_)(__VA_ARGS__)
#define DEFER(x) x
#define TO_STRING_(...) #__VA_ARGS__
#define QUOTE(...) TO_STRING(__VA_ARGS__)

using namespace std;
using namespace rapidjson;

extern "C" {

#define PLUGIN_NAME "azure_iothub"

/**
 * Plugin specific default configuration
 */
const char *default_config = QUOTE({
			"plugin" : {
				"description" : "Azure IoT-Hub",
				"type" : "string",
				"default" : PLUGIN_NAME,
				"readonly" : "true"
				},
			"iot_hub_name" : {
				"description" : "The Azure IoT-Hub name",
				"type" : "string",
				"default" : "",
				"order" : "1",
				"displayName" : "Azure IoT-Hub name"
			},
			"source": {
				"description" : "The source of data to send",
				"type" : "enumeration",
				"default" : "readings",
				"order" : "8",
				"displayName" : "Data Source",
				"options" : ["readings", "statistics"]
			}
		});

/**
 * The AZURE_IOTHUB plugin interface
 */

/**
 * The C API plugin information structure
 */
static PLUGIN_INFORMATION info = {
	PLUGIN_NAME,			// Name
	VERSION,			// Version
	0,				// Flags
	PLUGIN_TYPE_NORTH,		// Type
	"1.0.0",			// Interface version
	default_config			// Configuration
};

/**
 * Return the information about this plugin
 */
PLUGIN_INFORMATION *plugin_info()
{
	return &info;
}

/**
 * Initialise the plugin with configuration.
 *
 * This function is called to get the plugin handle.
 */
PLUGIN_HANDLE plugin_init(ConfigCategory* configData)
{

	AZURE_IOTHUB *azure_iothub = new AZURE_IOTHUB();
	azure_iothub->configure(configData);
	azure_iothub->connect();

	return (PLUGIN_HANDLE)azure_iothub;
}

/**
 * Send Readings data to historian server
 */
uint32_t plugin_send(const PLUGIN_HANDLE handle,
		     const vector<Reading *>& readings)
{
	AZURE_IOTHUB *azure_iothub = (AZURE_IOTHUB *)handle;

	return azure_iothub->send(readings);
}

/**
 * Shutdown the plugin
 *
 * Delete allocated data
 *
 * @param handle    The plugin handle
 */
void plugin_shutdown(PLUGIN_HANDLE handle)
{
	AZURE_IOTHUB *azure_iothub = (AZURE_IOTHUB *)handle;

        delete azure_iothub;
}

// End of extern "C"
};
