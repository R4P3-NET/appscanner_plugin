#ifdef _WIN32
#pragma warning (disable : 4100)  /* Disable Unreferenced parameter warning */
#include <Windows.h>
#include <Psapi.h>
#endif

#include <wchar.h>
#include <stdlib.h>
#include <stddef.h>

#if (__STDC_VERSION__ >= 199901L)
#include <stdint.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <assert.h>
#include "teamspeak/public_errors.h"
#include "teamspeak/public_errors_rare.h"
#include "teamspeak/public_definitions.h"
#include "teamspeak/public_rare_definitions.h"
#include "teamspeak/clientlib_publicdefinitions.h"
#include "ts3_functions.h"
#include "plugin.h"
#include <chrono>
#include <ctime>

static struct TS3Functions ts3Functions;

#ifdef _WIN32
#define _strcpy(dest, destSize, src) strcpy_s(dest, destSize, src)
#define snprintf sprintf_s
#else
#define _strcpy(dest, destSize, src) { strncpy(dest, src, destSize-1); (dest)[destSize-1] = '\0'; }
#endif

#ifdef ENV32
#define MOD (L"ts3client_win32.exe")
#else
#define MOD (L"ts3client_win64.exe")
#endif

#define PLUGIN_API_VERSION 22

#define PATH_BUFSIZE 512
#define COMMAND_BUFSIZE 128
#define INFODATA_BUFSIZE 128
#define SERVERINFO_BUFSIZE 256
#define CHANNELINFO_BUFSIZE 512
#define RETURNCODE_BUFSIZE 128

static char* pluginID = NULL;

#ifdef _WIN32
/* Helper function to convert wchar_T to Utf-8 encoded strings on Windows */
static int wcharToUtf8(const wchar_t* str, char** result) {
	int outlen = WideCharToMultiByte(CP_UTF8, 0, str, -1, 0, 0, 0, 0);
	*result = (char*)malloc(outlen);
	if(WideCharToMultiByte(CP_UTF8, 0, str, -1, *result, outlen, 0, 0) == 0) {
		*result = NULL;
		return -1;
	}
	return 0;
}
#endif

/*********************************** Required functions ************************************/
/*
 * If any of these required functions is not implemented, TS3 will refuse to load the plugin
 */

/* Unique name identifying this plugin */
const char* ts3plugin_name() {
#ifdef _WIN32
	/* TeamSpeak expects UTF-8 encoded characters. Following demonstrates a possibility how to convert UTF-16 wchar_t into UTF-8. */
	static char* result = NULL;  /* Static variable so it's allocated only once */
	if(!result) {
		const wchar_t* name = L"appscanner_plugin";
		if(wcharToUtf8(name, &result) == -1) {  /* Convert name into UTF-8 encoded result */
			result = "appscanner_plugin";  /* Conversion failed, fallback here */
		}
	}
	return result;
#else
	return "appscanner_plugin";
#endif
}

/* Plugin version */
const char* ts3plugin_version() {
    return "1.0";
}

/*MODULEINFO GetModuleInfo(const LPCWSTR szModule)
{
	MODULEINFO modinfo = { 0 };
	HMODULE hModule = GetModuleHandle(szModule);
	if (hModule == nullptr)
		return modinfo;
	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	return modinfo;
}
SIZE_T FindPattern(const LPCWSTR module, const char *pattern, const char *mask)
{
	//Get all module related information
	const MODULEINFO mInfo = GetModuleInfo(module);

	//Assign our base and module size
	//Having the values right is ESSENTIAL, this makes sure
	//that we don't scan unwanted memory and leading our game to crash
	const SIZE_T base = (SIZE_T)mInfo.lpBaseOfDll;
	const SIZE_T size = (SIZE_T)mInfo.SizeOfImage;

	//Get length for our mask, this will allow us to loop through our array
	const SIZE_T patternLength = strlen(mask);

	for (SIZE_T i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		for (SIZE_T j = 0; j < patternLength; j++)
		{
			//if we have a ? in our mask then we have true by default, 
			//or if the bytes match then we keep searching until finding it or not
			found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
		}

		//found = true, our entire pattern was found
		//return the memory addy so we can write to it
		if (found)
		{
			return base + i;
		}
	}

	return NULL;
}

int ts3plugin_apiVersion() {
	int target = -1;
	SIZE_T match = NULL;

	if (match == NULL && (match = FindPattern(MOD, "\x89\x83\x00\x04\x00\x00\x83\xC0?\x83\xF8\x01\x0F\x87", "xxxxxxxx?xxxxx")))
		target = abs((int)(*(signed char*)(match + 8)));

	if (match == NULL && (match = FindPattern(MOD, "\x89\x83??\x00\x00\x83\xF8?\x0F\x84", "xx??xxxx?xx")))
		target = abs((int)(*(signed char*)(match + 8)));

	if (match == NULL)
	{
		printf("%s: Cannot auto-detect required PluginAPI version, using %d\n", ts3plugin_name(), PLUGIN_API_VERSION);
		return 22;
	}

	printf("%s: Auto-detected required PluginAPI %d\n", ts3plugin_name(), target);
	return target;
}*/

int ts3plugin_apiVersion() { return PLUGIN_API_VERSION; }

/* Plugin author */
const char* ts3plugin_author() {
	/* If you want to use wchar_t, see ts3plugin_name() on how to use */
    return "Bluscream";
}

/* Plugin description */
const char* ts3plugin_description() {
	/* If you want to use wchar_t, see ts3plugin_name() on how to use */
    return "Fake Plugin to recieve appscanner_plugin plugincmds.";
}

/* Set TeamSpeak 3 callback functions */
void ts3plugin_setFunctionPointers(const struct TS3Functions funcs) {
    ts3Functions = funcs;
}

/*
 * Custom code called right after loading the plugin. Returns 0 on success, 1 on failure.
 * If the function returns 1 on failure, the plugin will be unloaded again.
 */
int ts3plugin_init() {
    char appPath[PATH_BUFSIZE];
    char resourcesPath[PATH_BUFSIZE];
    char configPath[PATH_BUFSIZE];
	char pluginPath[PATH_BUFSIZE];
    return 0;
}

/* Custom code called right before the plugin is unloaded */
void ts3plugin_shutdown() {
	if(pluginID) {
		free(pluginID);
		pluginID = NULL;
	}
}

/*
 * If the plugin wants to use error return codes, plugin commands, hotkeys or menu items, it needs to register a command ID. This function will be
 * automatically called after the plugin was initialized. This function is optional. If you don't use these features, this function can be omitted.
 * Note the passed pluginID parameter is no longer valid after calling this function, so you must copy it and store it in the plugin.
 */
void ts3plugin_registerPluginID(const char* id) {
	const size_t sz = strlen(id) + 1;
	pluginID = (char*)malloc(sz * sizeof(char));
	_strcpy(pluginID, sz, id);  /* The id buffer will invalidate after exiting this function */
	printf("%s: registerPluginID: %s\n", ts3plugin_name(), pluginID);
}

/* Plugin command keyword. Return NULL or "" if not used. */
const char* ts3plugin_commandKeyword() {
	return "as";
}

/* Plugin processes console command. Return 0 if plugin handled the command, 1 if not handled. */
int ts3plugin_processCommand(uint64 serverConnectionHandlerID, const char* command) {
	char buf[COMMAND_BUFSIZE];
	char *s, *param1 = NULL, *param2 = NULL;
	int i = 0;
	enum { CMD_NONE = 0, CMD_SEND } cmd = CMD_NONE;
	#ifdef _WIN32
	char* context = NULL;
	#endif

	printf("PLUGIN: process command: '%s'\n", command);

	_strcpy(buf, COMMAND_BUFSIZE, command);
	#ifdef _WIN32
		s = strtok_s(buf, " ", &context);
	#else
		s = strtok(buf, " ");
	#endif
	while(s != NULL) {
		if(i == 0) {
			if(!strcmp(s, "send")) {
				cmd = CMD_SEND;
            }
		} else if(i == 1) {
			param1 = s;
		} else {
			param2 = s;
		}
		#ifdef _WIN32
			s = strtok_s(NULL, " ", &context);
		#else
			s = strtok(NULL, " ");
		#endif
		i++;
	}

	switch(cmd) {
		case CMD_NONE:
			return 1;  /* Command not handled by plugin */
		case CMD_SEND:  /* /test command <command> */
			if(param1) {
				/* Send plugin command to all clients in current channel. In this case targetIds is unused and can be NULL. */
				if(pluginID) {
					/* See ts3plugin_registerPluginID for how to obtain a pluginID */
					std::string::size_type pos;
					std::string cmdString(command);
					std::string second;
					pos = cmdString.find(' ', 0);
					second = cmdString.substr(pos + 1);
					second = "Sending plugin command as appscanner_plugin: " + second;
					//first = first.substr(0, pos);
					ts3Functions.printMessageToCurrentTab(second.c_str());
					ts3Functions.sendPluginCommand(serverConnectionHandlerID, pluginID, second.c_str(), PluginCommandTarget_SERVER, NULL, NULL);
				} else {
					printf("PLUGIN: Failed to send plugin command, was not registered.\n");
				}
			} else {
				ts3Functions.printMessageToCurrentTab("Missing command parameter.");
			}
			break;
	}

	return 0;  /* Plugin handled command */
}

/* Required to release the memory for parameter "data" allocated in ts3plugin_infoData and ts3plugin_initMenus */
void ts3plugin_freeMemory(void* data) {
	free(data);
}

/*
 * Plugin requests to be always automatically loaded by the TeamSpeak 3 client unless
 * the user manually disabled it in the plugin dialog.
 * This function is optional. If missing, no autoload is assumed.
 */
int ts3plugin_requestAutoload() {
	return 1;  /* 1 = request autoloaded, 0 = do not request autoload */
}

std::string getTimeStamp()
{
	const time_t rawtime = std::time(nullptr);


	struct tm * dt;
	char timestr[30];
	char buffer[30];

	dt = localtime(&rawtime);
	// use any strftime format spec here
	strftime(timestr, sizeof(timestr), "<%H:%M:%S>", dt);
	sprintf(buffer, "%s", timestr);
	std::string stdBuffer(buffer);
	return stdBuffer;
}

std::string getClientURL(uint64 serverConnectionHandlerID, anyID clientID) {


	
	std::string cClientID = std::to_string(clientID);

	char *clientUid;
	char *username;
	


	if (clientID == 0) {
		ts3Functions.getServerVariableAsString(serverConnectionHandlerID, VIRTUALSERVER_NAME, &username);
		clientUid = "";

	}
	else {
		ts3Functions.getClientVariableAsString(serverConnectionHandlerID, clientID, CLIENT_UNIQUE_IDENTIFIER, &clientUid);
		ts3Functions.getClientVariableAsString(serverConnectionHandlerID, clientID, CLIENT_NICKNAME, &username);
	}
	
	return "[color=firebrick][URL=client://" + cClientID + "/" + clientUid + "]\"" + username + "\"[/URL][/color]";
}

void ts3plugin_onPluginCommandEvent(uint64 serverConnectionHandlerID, const char* pluginName, const char* pluginCommand) {
	std::string pluginNameString(pluginName);
	std::string pluginCommandString(pluginCommand);
	std::string timestamp = getTimeStamp();
	std::string senderstr;
	// [IN] notifyplugincmd name=appscanner_plugin data=6&&Mozilla\sFirefox,\sMicrosoft\sVisual\sStudio
	int position = pluginCommandString.find("&&", 0);
	std::string sender = pluginCommandString.substr(std::string::npos, position);
	int senderID = strtol(sender.c_str(), nullptr, 10);

	if (senderID == 0L) {
		senderstr = sender;
	} else {
		senderstr = getClientURL(serverConnectionHandlerID, senderID);
	}

	std::string cmd = pluginCommandString.substr(0, position);

	std::string printedString = timestamp + " Got \"" + cmd + "\" from " + senderstr;

	ts3Functions.printMessage(serverConnectionHandlerID, printedString.c_str(), PLUGIN_MESSAGE_TARGET_SERVER);
}


// This function receives your key Identifier you send to notifyKeyEvent and should return
// the friendly device name of the device this hotkey originates from. Used for display in UI.
const char* ts3plugin_keyDeviceName(const char* keyIdentifier) {
	return NULL;
}

// This function translates the given key identifier to a friendly key name for display in the UI
const char* ts3plugin_displayKeyText(const char* keyIdentifier) {
	return NULL;
}

// This is used internally as a prefix for hotkeys so we can store them without collisions.
// Should be unique across plugins.
const char* ts3plugin_keyPrefix() {
	return NULL;
}
