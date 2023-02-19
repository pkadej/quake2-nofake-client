#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <curl/curl.h>
#include "aes/aes.h"
#include "nofake.h"

#define FUNC_NOFAKE_CHANGEPLAYERNAME "NofakeChangePlayerName"
#define FUNC_NOFAKE_KICKPLAYER "NofakeKickPlayer"
#define NOFAKE_VERSION "1.2"

char *IPLongToString(unsigned long IP)
{
	static char ret[20];

	snprintf(ret, sizeof( ret ), "%d.%d.%d.%d", IP&0xFF, (IP>>8)&0xFF, (IP>>16)&0xFF, (IP>>24)&0xFF);
	return ret;
}

void log_printf( const char *fmt, ... )
{
	va_list ap;
	time_t now = time( NULL );
	static char date[100];
	struct tm *tmp;

	pthread_mutex_lock( &nofakeData.loggerMutex );

	if ( !nofakeData.logFile )
		return;

	tmp = localtime( &now );
	strftime( date, sizeof( date ), "%c", tmp );
	fprintf( nofakeData.logFile, "[%s] ", date );

	va_start( ap, fmt );
	vfprintf( nofakeData.logFile, fmt, ap);
	va_end( ap );

	fflush( nofakeData.logFile );

	pthread_mutex_unlock( &nofakeData.loggerMutex );
}

char base64tab[256];
char *base64letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void init_base64_tab( void )
{
	int i;
	
	for( i=0; i<strlen( base64letters ); i++ )
		base64tab[base64letters[i]] = i;
}

char *md5_sum( char *buffer )
{
	static char ret_buf[33];
	char tmp[16], *ptr;
	int i;

	tmp[0] = 0;

	md5_buffer( buffer, strlen( buffer ), tmp );

	ptr = ret_buf;

	for( i=0; i<16; i++, ptr+=2 )
		sprintf( ptr, "%02x", (unsigned char)tmp[i] );

	ret_buf[32] = 0;
	return ret_buf;
}

char *base64_encode( char *in )
{
        char *ret = NULL;
        int out_len = 0, i, len, j;

        len = strlen( in );
        out_len = ( len * 1.4 ) + 5;

        ret = malloc( out_len );
        if ( !ret )
	{
		log_printf( "Memory allocation error at %s:%d!\n", __FILE__, __LINE__ );
                return NULL;
	}

        for( j=0,i=0; i<len; i+=3, j+=4 )
        {
		sprintf( ret+j, "%c%c%c%c", base64letters[(in[i]>>2)&0x3F], base64letters[((in[i]<<4)&0x30)|(*(in+i+1) ? ((in[i+1]>>4)&0x0F) : 0)], *(in+i+1) == 0 ? '=' : base64letters[((in[i+1]<<2)&0x3C)|(*(in+i+2) ? ((in[i+2]>>6)&0x03) : 0)], *(in+i+1) == 0 ? '=' : ( *(in+i+2) == 0 ? '=' : base64letters[in[i+2]&0x3F] ) );
        }

        ret[j] = 0;
        return ret;
}

char *base64_decode( char *input, int input_len )
{
	int len = ( input_len / 4 ) * 3, i;
	char *ret = (char *)malloc( len+1 ), *ptr;

	if ( input_len%4 != 0 )
		return NULL;

	if ( !ret )
	{
		log_printf( "Memory allocation error at %s:%d!\n", __FILE__, __LINE__ );
		return NULL;
	}

	ptr = ret;

	for( i=0; i<input_len; i+=4 )
	{
		*(ptr)++ = (char)((base64tab[input[i]] << 2)&0xfc)|((base64tab[input[i+1]] >> 4)&0x03);
		if ( input[i+2] == '=' )
			break;
		*(ptr)++ = (char)((base64tab[input[i+1]] << 4)&0xf0)|((base64tab[input[i+2]] >> 2)&0x0f);
		if ( input[i+2] == '=' )
			break;
		*(ptr)++ = (char)((base64tab[input[i+2]] << 6)&0xc0)|(base64tab[input[i+3]]&0x3f);
	}

	ret[ptr-ret] = 0;

	return ret;
}

void create_iv( void )
{
	char tmp[17], *sum;
	int i,j;

	for( i=8,j=0;j<16;j++ )
	{
		sprintf( tmp+j, "%d", i );
		if ( i > 5 )
			i--;
		else if ( i == 5 )
			i = 1;
		else if ( i < 4 )
			i++;
		else if ( i == 4 )
			i = 8;
	}

	tmp[16] = 0;

	sum = md5_sum( tmp );
	memcpy( nofakeData.iv, sum, 16 );
}

char *nofake_aes_encrypt( unsigned char index, char *ptr, aes_encrypt_ctx *ctx )
{
	static char outbuf[1024];
	int len, diff, i, j;
	char *ret;

	ptr = base64_encode( ptr );
	if ( !ptr )
	{
		log_printf( "nofake_aes_encrypt(): Error while base64 encoding (ptr==NULL).\n" );
		return NULL;
	}

	len = strlen( ptr );

	diff = len%16;

	if ( diff > 0 )
	{
		diff = 16-diff;
		ptr = (char*)realloc( ptr, len+diff );
		memset( ptr+len, 0, diff );
	}

	len += diff;

	aes_cbc_encrypt( ptr, outbuf, len, nofakeData.iv, ctx );

	free( ptr );

	ret = (char *)malloc( len*2+2+1 );
	if ( !ret )
	{
		log_printf( "nofake_aes_encrypt(): Memory allocation error at %s:%d!\n", __FILE__, __LINE__ );
		return NULL;
	}

	sprintf( ret, "%02X", (unsigned char)index );

	for( i=0, j=2; i<len; i++, j+=2 )
		sprintf( ret+j, "%02X", (unsigned char)outbuf[i] );

	return ret;
}

void nofake_set_aes_key( aes_encrypt_ctx *e_ctx, aes_decrypt_ctx *d_ctx, int encrypt )
{
	char raw_key[27]; /* IP:16, PORT:5, TAB:5, 0:1 */
	char *key;
	int len = strlen( nofakeData.serverIp->string );
	if ( len > 16 )
		len = 16;
	strncpy( raw_key, nofakeData.serverIp->string, len );
	snprintf( raw_key+len, 6, "%d", nofakeData.serverPort );
	len = strlen( raw_key );
	snprintf( raw_key+len, 6, "%d", key_tab[nofakeData.lastTabIndex] );

	key = md5_sum( raw_key );

	if ( encrypt )
		aes_encrypt_key256( key, e_ctx );
	else
		aes_decrypt_key256( key, d_ctx );

	nofakeData.lastTabIndex = (nofakeData.lastTabIndex+127)%256;
}

char *nofake_aes_decrypt( unsigned char index, char *ptr, int len, aes_decrypt_ctx *ctx )
{
	static char outbuf[1024];
	int diff, i, j, ret_len;
	char *ret, *tmp;
	time_t now = time( NULL ), resp_time;

	ret_len = len >> 1;

	diff = ret_len%16;

	if ( diff > 0 )
		diff = 16-diff;
	ret_len += diff;

	ret = (char*)calloc( ret_len, 1 );
	if ( !ret )
	{
		log_printf( "%s:%d - memmory allocation error!\n", __FILE__, __LINE__ );
		return NULL;
	}

	for( i=0, j=0; i<len; i+=2,j++ )
	{
		int c;
		sscanf( ptr+i, "%02x", &c );
		ret[j] = (unsigned char)c;
	}

	memset( outbuf, 0, sizeof( outbuf ) );
	aes_cbc_decrypt( ret, outbuf, len, nofakeData.iv, ctx );

	free( ret );

	ret = base64_decode( outbuf, strlen( outbuf ) );

	if ( !ret )
	{
		log_printf( "Error while decoding response(%s): base64_decode failed!\n", outbuf );
		return NULL;
	}

	resp_time = atoi( ret );

	if ( resp_time+600 <= now || resp_time-600 >= now )
	{
		free( ret );
		log_printf( "Response timestamp invalid: %d, now: %d\n", resp_time, now );
		return NULL;
	}

	ptr = strchr( ret, '.' );
	if ( !ptr || !*(++ptr) )
	{
		free( ret );
		log_printf( "Error while decoding response, no data after timestamp!\n" );
		return NULL;
	}

	tmp = strdup( ptr );

	free( ret );

	return tmp;
}

qboolean nofake_is_valid_name( char *userinfo, char *auth_name, char *new_name, size_t new_name_size, qboolean print_infos, edict_t *ent )
{
	int name_len;
	char name[16] = { 0, };
	char *ptr;
	struct sInfoStrings info;
	cvar_t *sv_referee_tag = nofakeData.pluginFuncs.gi->cvar ("sv_referee_tag", "[judge]", CVAR_SERVERINFO);

	if ( !new_name || new_name_size <= 0 || ( ent && ent->client->pers.save_data.is_admin ) )
		return false;

	info.infoString = userinfo;
	info.key = "name";
	info.value = name;

	nofakeData.pluginFuncs.CallFunction( FUNC_INFOVALUEFORKEY, sizeof( name ), (long)&info );

	if ( ( ptr = strstr( name, auth_name ) ) == NULL )
	{
		if ( print_infos )
			nofakeData.pluginFuncs.gi->cprintf( ent, PRINT_HIGH, "Your new name must contain '%s'!\n", auth_name );
		return false;
	}

	if ( strchr( name, '%' ) != NULL || strchr( name, '`' ) != NULL || strchr( name, '~' ) != NULL )
	{
		if ( print_infos )
			nofakeData.pluginFuncs.gi->cprintf( ent, PRINT_HIGH, "Your new name contain illegal character!\n" );
		return false;
	}

	if ( !strncmp( name, "[admin]", 7 ) || !strncmp( name, sv_referee_tag->string, strlen( sv_referee_tag->string ) ) )
		return false;

	if ( ptr-name > 6 )
	{
		if ( print_infos )
			nofakeData.pluginFuncs.gi->cprintf( ent, PRINT_HIGH, "Your name prefix is too long (max. 6 characters).\n" );
		return false;
	}

	if ( ptr > name && isalnum( *(ptr-1) ) )
	{
		if ( print_infos )
			nofakeData.pluginFuncs.gi->cprintf( ent, PRINT_HIGH, "The character preceding your name must not be an alphabetic nor a digid.\n" );
		return false;
	}

	name_len = strlen( auth_name );

	if ( *(ptr+name_len ) && isalnum( *(ptr+name_len ) ) )
	{
		if ( print_infos )
			nofakeData.pluginFuncs.gi->cprintf( ent, PRINT_HIGH, "The character following your name must not be an alphabetic nor a digid.\n" );
		return false;
	}

	strncpy( new_name, name, new_name_size );

	return true;
}

#define ACTION_RUN_CHECK 0
#define ACTION_KICK 1
#define COND_TIMEOUT 5
#define CLIENT_TIMEOUT 30

void nofake_parse_response( struct sTask *task )
{
	int num_matched;
	char base64name[21], *tmp, *response;
	char base64tag[9];
	int is_admin = 0, ban_message_start = 0, len;
	unsigned char index;
	aes_decrypt_ctx ctx;

	if ( !task->dataBuff.dataBuff )
		return;

	index = nofakeData.lastTabIndex;

	create_iv();

	nofake_set_aes_key( NULL, &ctx, 0 );

	response = nofake_aes_decrypt( index, task->dataBuff.dataBuff, task->dataBuff.dataLen, &ctx );

	if ( !response )
	{
		log_printf( "%s - failed to decode response from nofake server!\n", task->ip );
		return;
	}

	num_matched = sscanf( response, "%20s %d %8s %n", base64name, &is_admin, base64tag, &ban_message_start );

	if ( num_matched < 2 )
	{
		free( response );
		return;
	}	

	tmp = base64_decode( base64name, strlen( base64name ) );
	if ( tmp )
	{
		strncpy( task->name, tmp, 15 );
		task->name[15] = 0;
		free( tmp );
		tmp = NULL;
	}

	task->isAdmin = is_admin;

	if ( num_matched < 3 )
	{
		free( response );
		return;
	}

	tmp = base64_decode( base64tag, strlen( base64tag ) );
	if ( tmp )
	{
		strncpy( task->clanTag, tmp, 15 );
		task->clanTag[15] = 0;
		free( tmp );
	}

	len = strlen( response );

	if ( ban_message_start && ban_message_start < len && response[ban_message_start] )
	{
		tmp = base64_decode( response+ban_message_start, len-ban_message_start );
		task->banMessage = tmp;
	}

	free( response );
}

size_t nofake_read_response( void *ptr, size_t size, size_t nmemb, void *stream )
{
	struct sDataBuffer *buff = (struct sDataBuffer *)stream;
	char *tmp;

	if ( !nmemb*size || !ptr || !buff )
		return 0;

	tmp = (char*)realloc( buff->dataBuff, 1+buff->dataLen+nmemb*size );
	if ( !tmp )
		return 0;

	buff->dataBuff = tmp;

	memcpy( buff->dataBuff+buff->dataLen, ptr, nmemb*size );
	buff->dataLen += nmemb*size;

	buff->dataBuff[buff->dataLen] = 0;

	return size*nmemb;
}

char query_params[100] = { 4, 7, 5, -8, -4, 16, 6, -10, 5, 39, 24, -78, 77, -61, -9, 11, -13, 15, -21, 19, -6, 42, 24, -63, 62, -61, -9, 3, 4, -9, -6, 21, -10, -7, 51, 24, -78, 77, -65, -5, 13, -14, -2, 11, -17, 9, 11, -19, 15, 40, 24, -65, 64, -80, 13, 5, 5, -8, 6, -12, 0, 12, 36, 24, -65, 64, -67, -5, -6, 15, -9, -5, 10, -11, -5, 60, 24, -65, 64, -64, -9, -7, 57, 24, -63, 62, -77, 14, -9, -5, 10, -11, 11, -13, 13, -11, -5, 60, 24, -65 };

void nofake_check_user( struct sTask *task )
{
	char url[1024];
	int error_code, i, r = 'y';
	long code;
	char request_format[128], request[256], *ptr;
	unsigned char index = nofakeData.lastTabIndex;
	aes_encrypt_ctx ctx;

	sprintf( request_format, "%u.", time( NULL ) );
	ptr = strchr( request_format, '.' );

	for( i=0, ptr++; i<sizeof( query_params ); i++, ptr++ )
	{
		*ptr = r-query_params[i];
		r -= query_params[i];
	}
	*ptr = 0;

	snprintf( request, sizeof( request ), request_format, task->uniqueId, task->getClanTag, task->ip, task->glModulate, task->vidGamma, task->intensity, task->fov, task->sensitivity );

	create_iv();

	nofake_set_aes_key( &ctx, NULL, 1 );

	ptr = nofake_aes_encrypt( index, request, &ctx );
	if ( !ptr )
	{
		log_printf( "nofake_check_user() - error while encoding request!\n" );
		return;
	}

	//unique_id=%s&clan_tag=%d&client_ip=%s&gl_modulate=%f&vid_gamma=%f&intensity=%f&fov=%d&sensitivity=%f

	snprintf( url, sizeof( url ), "%s/check_user.php?server_port=%d&q=%s", nofakeData.nofakeAddress->string, nofakeData.serverPort, ptr );

	free( ptr );

	curl_easy_reset( nofakeData.curl );
	curl_easy_setopt( nofakeData.curl, CURLOPT_INTERFACE, nofakeData.serverIp->string );
	curl_easy_setopt( nofakeData.curl, CURLOPT_URL, url ); 
	curl_easy_setopt( nofakeData.curl, CURLOPT_USERAGENT, "nofake plugin" );
	curl_easy_setopt( nofakeData.curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );
	curl_easy_setopt( nofakeData.curl, CURLOPT_WRITEFUNCTION, nofake_read_response );
	curl_easy_setopt( nofakeData.curl, CURLOPT_WRITEDATA, &task->dataBuff );

	log_printf( "%s - Sending request to %s...\n", task->ip, nofakeData.nofakeAddress->string );
	if ( ( error_code = curl_easy_perform( nofakeData.curl ) ) != 0 )
	{
		log_printf( "%s - error while performing curl request: %s.\n", task->ip, curl_easy_strerror( error_code ) );
		return;
	}

	if ( ( error_code = curl_easy_getinfo( nofakeData.curl, CURLINFO_RESPONSE_CODE, &code ) ) != CURLE_OK )
	{
		log_printf( "%s - Error while getting response code: %s.\n", task->ip, curl_easy_strerror( error_code ) );
		return;
	}

	if ( code == 200 )
	{
		nofake_parse_response( task );
		if ( !strlen( task->name ) || task->banMessage )
		{
			task->name[0] = 0;
			if ( task->banMessage )
			{
				log_printf( "%s - %s = kick\n", task->ip, task->banMessage );
				nofakeData.pluginFuncs.CallFunctionSync( FUNC_NOFAKE_KICKPLAYER, (unsigned int)task->banMessage, (long)task->ent );
			}
			else
			{
				log_printf( "%s - No player under this unique_id = kick\n", task->ip );
				nofakeData.pluginFuncs.CallFunctionSync( FUNC_NOFAKE_KICKPLAYER, (unsigned int)"player has wrong unique_id.", (long)task->ent );
			}
			task->ent = 0;
		}
	}
	else
		log_printf( "%s - response code from check_user script: %d\n", task->ip, code );

	if ( task->dataBuff.dataBuff )
	{
		free( task->dataBuff.dataBuff );
		task->dataBuff.dataBuff = NULL;
		if ( task->banMessage )
		{
			free( task->banMessage );
			task->banMessage = NULL;
		}
	}
}

long kick_player ( unsigned int wParam, long lParam )
{
	char text[10];
	char *reason = (char*)wParam;
	int entNum = (int)lParam;
	edict_t ent = nofakeData.pluginFuncs.edicts[ entNum ];

	nofakeData.pluginFuncs.gi->bprintf( ATTR_PRINT_HIGH|ATTR_BOLD, "%s kicked by NoFake - %s\n", ent.client->pers.netname, reason );

	snprintf( text, sizeof( text ), "kick %d\n", entNum-1 );
	nofakeData.pluginFuncs.gi->AddCommandString( text );
	return 0;
}

long change_player_name ( unsigned int wParam, long lParam )
{
	struct sTask *task = (struct sTask *)lParam;
	edict_t ent;
	char stufftext[32];

	if ( !nofakeData.pluginFuncs.edicts[task->ent].client )
		return 1;

	ent = nofakeData.pluginFuncs.edicts[task->ent];

	log_printf( "%s - authenticated as %s%s.\n", task->ip, ( task->getClanTag && task->clanTag[0] ) ? task->clanTag : "", task->name );

	nofakeData.pluginFuncs.gi->bprintf( ATTR_PRINT_HIGH|ATTR_BOLD, "%s authenticated as %s%s.\n", ent.client->pers.netname, ( task->getClanTag && task->clanTag[0] ) ? task->clanTag : "", task->name );

	memset( ent.client->pers.netname, 0, sizeof( ent.client->pers.netname ) );

	strncpy( nofakeData.clients[task->ent-1].playerName, task->name, 15 );
	nofakeData.clients[task->ent-1].playerName[15] = 0;
	nofakeData.clients[task->ent-1].isAdmin = task->isAdmin;

	if ( nofake_is_valid_name( ent.client->pers.userinfo, task->name, ent.client->pers.netname, 15, false, NULL ) == false )
	{
		ent.client->pers.netname[0] = 0;

		if ( task->getClanTag && task->clanTag[0] )
			strncat( ent.client->pers.netname, task->clanTag, 15 );

		strncat( ent.client->pers.netname, task->name, 15 - strlen( ent.client->pers.netname ) );

		snprintf( stufftext, sizeof( stufftext ), "name %s", ent.client->pers.netname );
		nofakeData.pluginFuncs.gi->WriteByte( svc_stufftext );
		nofakeData.pluginFuncs.gi->WriteString( stufftext );
		nofakeData.pluginFuncs.gi->unicast( &nofakeData.pluginFuncs.edicts[task->ent], false );
	}
	return 0;
}

void *worker_thread( void *params )
{
	struct sTask task;
	time_t now;
	qboolean threadStop = false;
	char action;
	struct timeval tv;
	struct timespec ts;

	nofakeData.threadId = pthread_self();

	log_printf( "NoFake thread started.\n" );
	
	pthread_mutex_lock( &nofakeData.queueMutex );
	do
	{
#ifdef __WIN32__
		tv.tv_sec = time( NULL );
		tv.tv_usec = 0;
#else
		gettimeofday( &tv, NULL );
#endif
		now = tv.tv_sec;
		if ( !nofakeData.mainThreadStop )
		{
			struct sTask *tmp = nofakeData.queueFirst;

			while( tmp )
			{
				if ( tmp->ent == 0 && tmp->ready == false && tmp == nofakeData.queueFirst )
				{
					DEL_TASK( tmp, nofakeData.queueFirst, nofakeData.queueLast );
					log_printf( "DEBUG: task 0x%x removed from queue.\n", (unsigned int)tmp );
					free( tmp );
					tmp = nofakeData.queueFirst;
				}
				else if ( tmp->ready == true )
				{
					action = ACTION_RUN_CHECK;
					break;
				}
				else if ( tmp->ent > 0 && tmp->arrival+CLIENT_TIMEOUT < now )
				{
					action = ACTION_KICK;
					break;
				}
				else
					tmp = tmp->next;
			};

			if ( tmp )
			{
				log_printf( "DEBUG: processing task 0x%x.\n", (unsigned int)tmp );
				memcpy( &task, tmp, sizeof( struct sTask ) );
				tmp->ready = false;
				tmp->ent = 0;
			}
			else
			{
				ts.tv_sec = tv.tv_sec + COND_TIMEOUT;
				ts.tv_nsec = tv.tv_usec*1000;

				pthread_cond_timedwait( &nofakeData.signalCond, &nofakeData.queueMutex, &ts );
				continue;
			}
		}
		else
			threadStop = true;

		pthread_mutex_unlock( &nofakeData.queueMutex );

		if ( threadStop == false )
		{
			if ( action == ACTION_RUN_CHECK )
			{
				nofake_check_user( &task );
				if ( task.ent > 0 && strlen( task.name ) )
				{
					log_printf( "%s - recived name %s%s%s.\n", task.ip, task.name, task.clanTag[0] ? " and clan tag " : "", task.clanTag[0] ? task.clanTag : "" );
					nofakeData.pluginFuncs.CallFunctionSync( FUNC_NOFAKE_CHANGEPLAYERNAME, 0, (long)&task );
				}
			}
			else
			{
				log_printf( "Timedout waiting for answer from player = kick\n" );
				nofakeData.pluginFuncs.CallFunctionSync( FUNC_NOFAKE_KICKPLAYER, (unsigned int)"player failed to authenticate.", (long)task.ent );
			}

			pthread_mutex_lock( &nofakeData.queueMutex );
		}
	} while( threadStop == false );

	log_printf( "NoFake thread terminated.\n" );
	return NULL;
}

/*
 * There are three cases when this function gets called:
 * 1. Player changed his name:
 * 	- userinfo from server, contains the new name
 * 	- ent->client->pers.netname contains old name
 *
 * 2. Before respawn (no name change):
 * 	- temporary userinfo (not ent->client->pers.userinfo), contains old name
 *	- ent->client->pers.netname is empty and need to be set
 *
 * 3. When player becomes an admin (or noadmin):
 * 	- local userinfo (ent->client->pers.userinfo), contains old name
 * 	- ent->client->pers.netname contains old name
 *
 * case 1: new name must be validated and then copied to ent->client->pers.netname, when it's not valid
 * 	   the function should set userinfo and ent->client->pers.netname to some valid name.
 * case 2: no validation needed, just copy name from temporary userinfo to ent->client->pers.netname.
 * case 3: [admin] (or [referee]) prefix should be added to (or removed from) the name and then 
 *         ent->client->pers.userinfo and ent->client->pers.netname should be updated AND "name" command 
 *         should be send through stufftext (to update the userinfo on the server side).
 */
qboolean nofake_name_userinfo_changed( unsigned int wParam, long lParam )
{
	edict_t *ent = (edict_t *)lParam;
	char *userinfo = (char*)wParam;
	char new_name[16] = { 0, };
	struct sInfoStrings info;

	if ( !ent || !ent->client )
		return true;

	if ( nofakeData.clients[ent-nofakeData.pluginFuncs.edicts-1].playerName[0] == 0 )
		return true;
	
	/* case 1 */
	if ( userinfo != ent->client->pers.userinfo && ent->client->pers.userinfo[0] != 0 )
	{
		if ( nofake_is_valid_name( userinfo, nofakeData.clients[ent-nofakeData.pluginFuncs.edicts-1].playerName, new_name, 15, true, ent ) )
		{
			if ( strcmp( new_name, ent->client->pers.netname ) && ent->client->pers.netname[0] )
				nofakeData.pluginFuncs.gi->bprintf(ATTR_PRINT_HIGH|ATTR_BOLD, "%s changed name to %s.\n", ent->client->pers.netname, new_name);
			strncpy( ent->client->pers.netname, new_name, 15 );
			ent->client->pers.netname[15] = 0;
		}

		info.infoString = userinfo;
		info.key = "name";
		info.value = ent->client->pers.netname;

		nofakeData.pluginFuncs.CallFunction( FUNC_INFOSETVALUEFORKEY, 0, (long)&info );
		return false;
	}

	info.infoString = userinfo;
	info.key = "name";
	info.value = new_name;

	nofakeData.pluginFuncs.CallFunction( FUNC_INFOVALUEFORKEY, sizeof( new_name ), (long)&info );

	/* case 2 */
	if ( ent->client->pers.netname[0] == 0 )
	{
		strncpy( ent->client->pers.netname, new_name, 15 );
		return false;
	}
	else
	{
		cvar_t *sv_referee_tag = nofakeData.pluginFuncs.gi->cvar ("sv_referee_tag", "[judge]", CVAR_SERVERINFO);

		/* case 3 */
		if ( ( ent->client->pers.save_data.is_admin && !strstr( ent->client->pers.netname, "[admin]" ) && !ent->client->pers.save_data.judge ) ||
		     ( ent->client->pers.save_data.judge && !strstr( ent->client->pers.netname, sv_referee_tag->string ) ) )
		{
			char *adm_prefix;
			int ref_len = 0;
			if ( ent->client->pers.save_data.judge )
				adm_prefix = sv_referee_tag->string;
			else
				adm_prefix = "[admin]";

			ref_len = strlen( adm_prefix );
			strncpy( new_name, adm_prefix, 15 );
			strncpy( new_name+ref_len, nofakeData.clients[ent-nofakeData.pluginFuncs.edicts-1].playerName, 15-ref_len );
			new_name[15] = 0;
			strncpy( ent->client->pers.netname, new_name, 15 );
		}
		else if ( !ent->client->pers.save_data.is_admin && 
			  ( strstr( ent->client->pers.netname, "[admin]" ) || strstr( ent->client->pers.netname, sv_referee_tag->string ) ) )
		{
			strncpy( ent->client->pers.netname, nofakeData.clients[ent-nofakeData.pluginFuncs.edicts-1].playerName, 15 );
			ent->client->pers.netname[15] = 0;
		}
	}

	info.infoString = ent->client->pers.userinfo;
	info.key = "name";
	info.value = ent->client->pers.netname;

	nofakeData.pluginFuncs.CallFunction( FUNC_INFOSETVALUEFORKEY, 0, (long)&info );

	return false;
}

qboolean nofake_command_check( unsigned int wParam, long lParam )
{
	char *cmd = (char*)wParam;
	edict_t *ent = (edict_t *)lParam;

	if ( !cmd )
		return true;

	if ( !stricmp( cmd, "admin" ) && nofakeData.pluginFuncs.gi->argc() == 1 )
	{
		if ( !nofakeData.clients[ent-nofakeData.pluginFuncs.edicts-1].isAdmin )
			return true;

		if ( ent->client->pers.save_data.is_admin )
		{
			nofakeData.pluginFuncs.gi->cprintf(ent, PRINT_HIGH, "You are an admin already.\n");
			return false;
		}

		nofakeData.pluginFuncs.gi->bprintf(ATTR_PRINT_HIGH|ATTR_BOLD, "%s has become an admin.\n", ent->client->pers.netname);
		nofakeData.pluginFuncs.gi->cprintf(ent, PRINT_HIGH, "Admin mode on.\n");
		ent->client->pers.save_data.judge = false;
		ent->client->pers.save_data.admin_flags = 0x00000010;
		ent->client->pers.save_data.is_admin = true;

		nofake_name_userinfo_changed( (unsigned int)ent->client->pers.userinfo, (long)ent );

		return false;
	}
	if ( !stricmp( cmd, "unique_id_check" ) )
	{
		char *ip = IPLongToString( ent->client->pers.save_data.ip );
		struct sTask *task;

		log_printf( "%s - received unique_id_check command parameters,\n", ip );

		pthread_mutex_lock( &nofakeData.queueMutex );
		
		task = nofakeData.queueFirst;
		while( task )
		{
			if ( task->ready == false && task->ent == (ent-nofakeData.pluginFuncs.edicts) )
				break;
			task = task->next;
		};

		if ( nofakeData.pluginFuncs.gi->argc() < 7 )
		{
			if ( task )
				task->ent = 0;
			log_printf( "DEBUG: task 0x%x market to remove.\n", (unsigned int)task );
			pthread_cond_signal( &nofakeData.signalCond );
			pthread_mutex_unlock( &nofakeData.queueMutex );

			log_printf( "%s - wrong number of arguments to unique_id_check command = kick\n", ip );
			nofakeData.pluginFuncs.gi->cprintf( ent, PRINT_HIGH, "Please register your nickname at %s and follow further instructions.\n", nofakeData.nofakeAddress->string );
			nofakeData.pluginFuncs.CallFunction( FUNC_NOFAKE_KICKPLAYER, (unsigned int)"player has no unique_id set.", (long)(ent-nofakeData.pluginFuncs.edicts) );
			return false;
		}

		if ( !task )
		{
			pthread_mutex_unlock( &nofakeData.queueMutex );
			log_printf( "%s - seems like unique_id_check command typed by client = kick\n", ip );
			nofakeData.pluginFuncs.gi->cprintf( ent, PRINT_HIGH, "Please, don't do that. It's pointless.\n" );
			nofakeData.pluginFuncs.CallFunction( FUNC_NOFAKE_KICKPLAYER, (unsigned int)"player tried to cheat NoFake system.", (long)(ent-nofakeData.pluginFuncs.edicts) );
			return false;
		}

		strncpy( task->uniqueId, nofakeData.pluginFuncs.gi->argv(1), sizeof( task->uniqueId )-1 );
		task->uniqueId[sizeof( task->uniqueId )-1] = 0;
		task->glModulate = atof( nofakeData.pluginFuncs.gi->argv(2) );
		task->vidGamma = atof( nofakeData.pluginFuncs.gi->argv(3) );
		task->intensity = atof( nofakeData.pluginFuncs.gi->argv(4) );
		task->fov = (char)atoi( nofakeData.pluginFuncs.gi->argv(5) );
		task->sensitivity = atof( nofakeData.pluginFuncs.gi->argv(6) );
		if ( nofakeData.pluginFuncs.gi->argc() == 8 )
			task->getClanTag = (char)atoi( nofakeData.pluginFuncs.gi->argv(7) );
		else
			task->getClanTag = 0;
		task->ready = true;
		strncpy( (char*)task->ip, (const char *)ip, 16 );

		log_printf( "DEBUG: task 0x%x market as ready to process.\n", (unsigned int)task );

		pthread_cond_signal( &nofakeData.signalCond );
		pthread_mutex_unlock( &nofakeData.queueMutex );

		return false;
	}

	return true;
}

char uniq_command[90] = { 4, 7, 5, -8, -4, 16, 6, -10, 5, 5, -4, -5, 3, 2, -8, 75, -4, -81, 7, 5, -8, -4, 16, 6, -10, 5, 68, -4, -67, -5, 13, -14, -2, 11, -17, 9, 11, -19, 15, 69, -4, -82, 13, 5, 5, -8, 6, -12, 0, 12, 65, -4, -69, -5, -6, 15, -9, -5, 10, -11, -5, 89, -4, -66, -9, -7, 86, -4, -79, 14, -9, -5, 10, -11, 11, -13, 13, -11, -5, 89, -4, -63, -9, 11, -13, 15, -21, 19, -6, 93 };

qboolean nofake_client_begin( unsigned int wParam, long lParam )
{
	edict_t *ent = (edict_t *)lParam;
	struct sTask *task;
	char *ip = IPLongToString( ent->client->pers.save_data.ip );
	int r = 'y', i;
	char command[91];

	for( i=0; i<sizeof( uniq_command ); i++ )
	{
		command[i] = r-uniq_command[i];
		r -= uniq_command[i];
	}
	command[i] = 0;

	nofakeData.pluginFuncs.gi->WriteByte( svc_stufftext );
	nofakeData.pluginFuncs.gi->WriteString( command );
	nofakeData.pluginFuncs.gi->unicast( ent, true );

	log_printf( "%s - new client\n", ip );

	task = (struct sTask*)malloc( sizeof( struct sTask ) );
	if ( !task )
	{
		log_printf( "%s - memory allocation error at %s:%d- client may play\n", ip, __FILE__, __LINE__ );
		return true;
	}

	memset( task, 0, sizeof( struct sTask ) );

	task->ent = ent-nofakeData.pluginFuncs.edicts;
	task->ready = false;
	task->arrival = time( NULL );

	pthread_mutex_lock( &nofakeData.queueMutex );
	log_printf( "DEBUG: 0x%x new task added.\n", (unsigned int)task );
	ADD_TASK( task, nofakeData.queueFirst, nofakeData.queueLast );
	pthread_mutex_unlock( &nofakeData.queueMutex );

	return true;
}

qboolean nofake_client_disconnect( unsigned int wParam, long lParam )
{
	edict_t *ent = (edict_t *)lParam;
	struct sTask *task;

	nofakeData.clients[ent-nofakeData.pluginFuncs.edicts-1].playerName[0] = 0;

	pthread_mutex_lock( &nofakeData.queueMutex );

	task = nofakeData.queueFirst;
	while( task )
	{
		if ( task->ent > 0 && task->ent == (ent-nofakeData.pluginFuncs.edicts) )
		{
			task->ent = 0;
			log_printf( "%s - client disconnected and removed from queue.\n", IPLongToString( ent->client->pers.save_data.ip ) );
			log_printf( "DEBUG: task 0x%x market to remove.\n", (unsigned int)task );
			break;
		}
		task = task->next;
	};

	pthread_mutex_unlock( &nofakeData.queueMutex );

	return true;
}

void open_log( void )
{
	cvar_t	*basedir, *gamedir;
	char	filename[256];
	
	basedir = nofakeData.pluginFuncs.gi->cvar("basedir", "", 0);
	gamedir = nofakeData.pluginFuncs.gi->cvar("gamedir", "", 0);

	snprintf( filename, sizeof( filename )-1, "%s/%s/%s", basedir->string, strlen( gamedir->string ) ? gamedir->string : "baseq2", nofakeData.logFileName->string );

	nofakeData.logFile = fopen( filename, "a" );
}

int nofake_plugin_check_response( struct sDataBuffer *reply )
{
	char *response;
	unsigned char index;

	aes_decrypt_ctx ctx;

	index = nofakeData.lastTabIndex;

	create_iv();

	nofake_set_aes_key( NULL, &ctx, 0 );

	response = nofake_aes_decrypt( index, reply->dataBuff, reply->dataLen, &ctx );

	log_printf( "Registering in NoFake system...\n" );

	if ( response )
	{
		if ( !strcmp( response, "good" ) )
		{
			log_printf( "Registration successful\n" );
			free( response );
			return 1;
		}
		free( response );
	}

	log_printf( "ERROR: Registration failed!\n1. Make sure your date and time are set correctly\n2. Check the access to %s at port 80\n", nofakeData.nofakeAddress->string );

	return 0;
}

char secret[26] = { 4, 97, 21, 80, 34, 71, 29, 72, 45, 69, 29, 68, 47, 54, 53, 47, 64, 36, 64, 57, 47, 50, 64, 54, 47, 63 };

int nofake_plugin_check( void )
{
	int j = 106, i, error_code, code;
	unsigned char index;
	char tosend[48] = { 0, }, *ptr = NULL, url[1024];
	struct sDataBuffer reply;

	aes_encrypt_ctx ctx;

	srand( time( NULL ) );
	index = nofakeData.lastTabIndex = (unsigned char)(256.0*((double)rand()/RAND_MAX));

	create_iv();

	nofake_set_aes_key( &ctx, NULL, 1 );

	sprintf( tosend, "%u.", time( NULL ) );

	ptr = strchr( tosend, '.' );

	for( i=0, ptr++; i<sizeof( secret ); i++, ptr++ )
	{
		*ptr = (char)secret[i]+j;
		j = secret[i];
	}
	*ptr = 0;

	ptr = nofake_aes_encrypt( index, tosend, &ctx );

	if ( !ptr )
		return 0;

	snprintf( url, sizeof( url ), "%s/check_user.php?server_port=%d&q=%s", nofakeData.nofakeAddress->string, nofakeData.serverPort, ptr );

	free( ptr );

	reply.dataBuff = NULL;
	reply.dataLen = 0;

	curl_easy_reset( nofakeData.curl );
	curl_easy_setopt( nofakeData.curl, CURLOPT_INTERFACE, nofakeData.serverIp->string );
	curl_easy_setopt( nofakeData.curl, CURLOPT_URL, url ); 
	curl_easy_setopt( nofakeData.curl, CURLOPT_USERAGENT, "nofake plugin" );
	curl_easy_setopt( nofakeData.curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1 );
	curl_easy_setopt( nofakeData.curl, CURLOPT_WRITEFUNCTION, nofake_read_response );
	curl_easy_setopt( nofakeData.curl, CURLOPT_WRITEDATA, &reply );

	if ( ( error_code = curl_easy_perform( nofakeData.curl ) ) != 0 )
	{
		log_printf( "nofake_plugin_check(): Error while performing curl request: %s.\n", curl_easy_strerror( error_code ) );
		return 0;
	}

	if ( ( error_code = curl_easy_getinfo( nofakeData.curl, CURLINFO_RESPONSE_CODE, &code ) ) != CURLE_OK )
	{
		log_printf( "nofake_plugin_check(): Error while getting response code: %s.\n", curl_easy_strerror( error_code ) );
		return 0;
	}

	if ( code != 200 )
	{
		log_printf( "nofake_plugin_check(): Invalid response code: %d.\n", code );
		return 0;
	}

	i = nofake_plugin_check_response( &reply );

	if ( reply.dataBuff )
		free( reply.dataBuff );

	if ( !i )
		return 0;

	return 1;
}

#ifdef WIN32
__declspec(dllexport) 
#endif
void TDM_pluginLoad(struct sPluginFunctions *plugFunctions, struct sPluginInfo *info)
{
	pthread_t threadId;
	int i;
	cvar_t *port;

	info->pluginAPIVersion = TDM_PLUGIN_API_VERSION;
	info->pluginName = "NoFake";

	memset( &nofakeData, 0, sizeof( struct sNofake ) );

	memcpy( &nofakeData.pluginFuncs, plugFunctions, sizeof( struct sPluginFunctions ) );

	nofakeData.clients = (struct sClient*)malloc( nofakeData.pluginFuncs.game->maxclients*sizeof(struct sClient) );

	for( i=0; i<nofakeData.pluginFuncs.game->maxclients; i++ )
	{
		memset( nofakeData.clients[i].playerName, 0, sizeof( nofakeData.clients[i].playerName ) );
		nofakeData.clients[i].isAdmin = false;
	}

	pthread_mutex_init( &nofakeData.loggerMutex, NULL );
	pthread_mutex_init( &nofakeData.queueMutex, NULL );
	pthread_cond_init( &nofakeData.signalCond, NULL );
	nofakeData.threadId = 0;

	nofakeData.pluginFuncs.gi->cvar( "nofake_version", NOFAKE_VERSION, CVAR_SERVERINFO|CVAR_LATCH );

	nofakeData.pluginFuncs.gi->cvar( "NoFake", "DISABLED", CVAR_SERVERINFO );

	nofakeData.logFileName = nofakeData.pluginFuncs.gi->cvar( "nofake_log_filename", "nofake.log", 0 );
	nofakeData.nofakeAddress = nofakeData.pluginFuncs.gi->cvar( "nofake_address", "http://nofake.planetquake.pl", 0 );
	open_log();
	nofakeData.serverIp = nofakeData.pluginFuncs.gi->cvar( "ip", "", CVAR_NOSET );
	if ( *(nofakeData.serverIp->string) == 0 )
	{
		log_printf( "'ip' is not set, checking 'net_ip'...\n" );
		nofakeData.serverIp = nofakeData.pluginFuncs.gi->cvar( "net_ip", "", CVAR_NOSET );
		if ( *(nofakeData.serverIp->string) == 0 )
		{
			log_printf( "ERROR: 'net_ip' is not set, NoFake DISABLED!!\n" );
			nofakeData.pluginFuncs.gi->cvar_forceset( "NoFake", "DISABLED" );
			return;
		}
	}
	port = nofakeData.pluginFuncs.gi->cvar( "port", "", CVAR_NOSET );
	if ( *(port->string) == 0 )
	{
		log_printf( "'port' is not set, checking 'net_port'...\n" );
		port = nofakeData.pluginFuncs.gi->cvar( "net_port", "", CVAR_NOSET );
		if ( *(port->string) == 0 )
		{
			log_printf( "ERROR: 'net_port' is not set, NoFake DISABLED!!\n" );
			nofakeData.pluginFuncs.gi->cvar_forceset( "NoFake", "DISABLED" );
			return;
		}
	}
	nofakeData.serverPort = (unsigned short)port->value;

	init_base64_tab();

	nofakeData.curl = curl_easy_init();

	aes_init();

	log_printf( "This server ip and port are: %s:%d\n", nofakeData.serverIp->string, nofakeData.serverPort );

	if ( nofake_plugin_check() )
	{
		nofakeData.pluginFuncs.EventAddCallback( EVENT_CLIENTBEGIN, nofake_client_begin );
		nofakeData.pluginFuncs.EventAddCallback( EVENT_CLIENTCOMMAND, nofake_command_check );
		nofakeData.pluginFuncs.EventAddCallback( EVENT_CLIENTDISCONNECT, nofake_client_disconnect );
		nofakeData.pluginFuncs.EventAddCallback( EVENT_NAMECLIENTUSERINFOCHANGED, nofake_name_userinfo_changed );

		nofakeData.pluginFuncs.AddFunction( FUNC_NOFAKE_CHANGEPLAYERNAME, change_player_name );
		nofakeData.pluginFuncs.AddFunction( FUNC_NOFAKE_KICKPLAYER, kick_player );
		nofakeData.pluginFuncs.gi->cvar_forceset( "NoFake", "ENABLED" );
	}
	else
	{
		nofakeData.pluginFuncs.gi->cvar_forceset( "NoFake", "DISABLED" );
		return;
	}
	pthread_create( &threadId, NULL, worker_thread, NULL );
}

#ifdef WIN32
__declspec(dllexport) 
#endif
void TDM_pluginUnload()
{
	int i;
	struct sTask *tmp;

	pthread_mutex_lock( &nofakeData.queueMutex );
	nofakeData.mainThreadStop = true;
	pthread_cond_signal( &nofakeData.signalCond );
	pthread_mutex_unlock( &nofakeData.queueMutex );

	if ( nofakeData.threadId != 0 )
		pthread_join( nofakeData.threadId, NULL );

	while( ( tmp = nofakeData.queueFirst ) )
	{
		DEL_TASK( tmp, nofakeData.queueFirst, nofakeData.queueLast );
		free( tmp );
	}

	pthread_mutex_destroy( &nofakeData.queueMutex );
	pthread_cond_destroy( &nofakeData.signalCond );

	pthread_mutex_lock( &nofakeData.loggerMutex );

	if ( nofakeData.logFile )
		fclose( nofakeData.logFile );
	nofakeData.logFile = NULL;

	pthread_mutex_unlock( &nofakeData.loggerMutex );
	pthread_mutex_destroy( &nofakeData.loggerMutex );

	free( nofakeData.clients );

	curl_easy_cleanup( nofakeData.curl );
}
