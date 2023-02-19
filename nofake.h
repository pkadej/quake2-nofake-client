#include "../../src/g_local.h"
#include "../../src/tdm_plugins.h"

unsigned short key_tab[256] = { 52667, 40628, 1892, 41656, 29155, 11099, 12630, 34262, 4907, 45099, 34705, 7348, 40531, 18718, 26583, 44232, 15255, 57610, 17269, 44072, 65442, 2767, 10855, 2558, 12984, 23972, 10078, 49974, 13473, 32588, 22401, 604, 7681, 24294, 42260, 36836, 35393, 54891, 5563, 40301, 34454, 40268, 47650, 9449, 58986, 8697, 53682, 8706, 771, 5415, 52778, 678, 8183, 63634, 3236, 21167, 22070, 13315, 5605, 35543, 45904, 28007, 36147, 53585, 52301, 12872, 24886, 22158, 2227, 30449, 62459, 36681, 5181, 44574, 46131, 64168, 53271, 34278, 7339, 54043, 39693, 60118, 54721, 47877, 58216, 57958, 3508, 14750, 5737, 9113, 50293, 51642, 37121, 20905, 39691, 23886, 33777, 64577, 46044, 36005, 29490, 42968, 7151, 34672, 22006, 53282, 33305, 9742, 22025, 40644, 63786, 61719, 35226, 52972, 44060, 27907, 45394, 47568, 42657, 51132, 56682, 27415, 37238, 28267, 48320, 11393, 52153, 16562, 10435, 32662, 52567, 39925, 10095, 59718, 9062, 32102, 47465, 42367, 41845, 3954, 17476, 40095, 137, 52702, 27531, 44198, 15074, 7390, 26230, 57731, 58522, 17377, 19611, 30225, 45645, 2396, 41619, 32263, 18958, 52054, 64926, 5990, 26444, 9485, 172, 35506, 41588, 47638, 12338, 17897, 51593, 29814, 57992, 51730, 16981, 19987, 30393, 32055, 27378, 56624, 24251, 20365, 8465, 43862, 50590, 54111, 46258, 26674, 20838, 65217, 13193, 20228, 5671, 39637, 29714, 5844, 9608, 5766, 53482, 21946, 23663, 39539, 51761, 16119, 25734, 3206, 36107, 56128, 35262, 63485, 47216, 59513, 18315, 55682, 37839, 3369, 44257, 18562, 30044, 65095, 18243, 43237, 19788, 23915, 17339, 49503, 29759, 26948, 55269, 17706, 48895, 13396, 57246, 35120, 29516, 17445, 38327, 88, 8037, 8053, 63574, 55253, 2030, 16353, 45399, 39870, 19723, 24121, 58432, 49767, 23680, 11140, 27469, 43469, 35055, 44809 };

struct sClient
{
	char playerName[16];
	qboolean isAdmin;
};

struct sDataBuffer
{
	char *dataBuff;
	unsigned long dataLen;
};

struct sTask
{
	/* things from client */
	char uniqueId[41];
	int ent;
	char getClanTag;
	float glModulate;
	float vidGamma;
	float intensity;
	char fov;
	float sensitivity;
	char ip[17];

	/* things recived from check_user script */
	char name[16];
	char clanTag[16];
	char *banMessage;
	int isAdmin;

	time_t arrival; /* for timeout check */
	qboolean ready;
	struct sTask *next;

	struct sDataBuffer dataBuff;
};

struct sNofake
{
	pthread_t threadId;
	pthread_mutex_t queueMutex;
	pthread_mutex_t loggerMutex;
	pthread_cond_t signalCond;
	qboolean mainThreadStop;

	struct sClient *clients;
	unsigned short serverPort;

	cvar_t *logFileName;
	cvar_t *nofakeAddress;
	cvar_t *serverIp;

	FILE *logFile;
	CURL *curl;

	struct sPluginFunctions pluginFuncs;

	struct sTask *queueFirst;
	struct sTask *queueLast;

	unsigned char iv[16];
	unsigned char lastTabIndex;
} nofakeData;

/* Add task to the end of the queue */
#define ADD_TASK( task, first, last ) \
do \
{ \
	if ( !(first) ) \
		(first) = (task); \
	(task)->next = NULL; \
	if ( (last) ) \
		(last)->next = (task); \
	(last) = (task); \
} while( 0 )

/* Remove task from the begining of the queue */
#define DEL_TASK( task, first, last ) \
do \
{ \
	(first) = (task)->next; \
	if ( (task) == (last) ) \
		(last) = NULL; \
} while( 0 )

