/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

// DJB's libtai was modified for the tai code

#include "OS_portable.h"

#define DISABLE_LEAPS
#define TAI_PACK 8
#define TAI_UTC_DIFF ((uint64_t)4611686018427387914ULL)

//#define UTC_ADJUST -37
#define tai_approx(t) ((double) ((t)->x))
#define tai_less(t,u) ((t)->x < (u)->x)

int32_t leapsecs_sub(struct tai *);
static struct tai First_TAI;
uint32_t First_utc;
int32_t UTC_ADJUST;

#ifdef _WIN32


struct tm *gmtime_r(const time_t *timep,struct tm *result)
{
	struct tm *p = gmtime(timep);
	memset(result,0,sizeof(*result));
	if ( p != 0 )
    {
        *result = *p;
        p = result;
	}
	return(p);
}

//struct tm *_gmtime32(const time_t *timep,struct tm *result) { return(gmtime_r(timep,result)); }
//time_t _time32(struct tm *tm) { return(time(NULL)); }
//time_t _localtime32(struct tm *tm) { return(time(NULL)); }

#include <windows.h>
#include <stdint.h> // portable: uint64_t   MSVC: __int64

// MSVC defines this in winsock2.h!?
/*typedef struct timeval {
    long tv_sec;
    long tv_usec;
} timeval;*/

int gettimeofday(struct timeval * tp, struct timezone * tzp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);
    
    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;
    
    GetSystemTime( &system_time );
    SystemTimeToFileTime( &system_time, &file_time );
    time =  ((uint64_t)file_time.dwLowDateTime )      ;
    time += ((uint64_t)file_time.dwHighDateTime) << 32;
    
    tp->tv_sec  = (long) ((time - EPOCH) / 10000000L);
    tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
    return 0;
}
#endif

double OS_portable_milliseconds()
{
    struct timeval tv; double millis;
    gettimeofday(&tv,NULL);
    millis = ((double)tv.tv_sec * 1000. + (double)tv.tv_usec / 1000.);
    //printf("tv_sec.%ld usec.%d %f\n",tv.tv_sec,tv.tv_usec,millis);
    return(millis);
}

// portable time functions

int32_t is_DST(int32_t datenum)
{
    int32_t year,month,day;
    year = datenum / 10000, month = (datenum / 100) % 100, day = (datenum % 100);
    if ( month >= 4 && month <= 9 )
        return(1);
    else if ( month == 3 && day >= 29 )
        return(1);
    else if ( month == 10 && day < 25 )
        return(1);
    return(0);
}

struct taidate taidate_set(int32_t year,int32_t month,int32_t day)
{
    struct taidate cd;
    memset(&cd,0,sizeof(cd));
    cd.year = year, cd.month = month, cd.day = day;
    return(cd);
}

struct taidate taidate_frommjd(int32_t day,int32_t *pwday,int32_t *pyday)
{
    int32_t year,month,yday; struct taidate cd;
    year = day / 146097L;
    day %= 146097L;
    day += 678881L;
    while (day >= 146097L) { day -= 146097L; ++year; }
    // year * 146097 + day - 678881 is MJD; 0 <= day < 146097
    // 2000-03-01, MJD 51604, is year 5, day 0
    if ( pwday != 0 )
        *pwday = (day + 3) % 7;
        year *= 4;
        if (day == 146096L) { year += 3; day = 36524L; }
        else { year += day / 36524L; day %= 36524L; }
    year *= 25;
    year += day / 1461;
    day %= 1461;
    year *= 4;
    yday = (day < 306);
    if (day == 1460) { year += 3; day = 365; }
    else { year += day / 365; day %= 365; }
    yday += day;
    day *= 10;
    month = (day + 5) / 306;
    day = (day + 5) % 306;
    day /= 10;
    if (month >= 10) { yday -= 306; ++year; month -= 10; }
    else { yday += 59; month += 2; }
    cd.year = year;
    cd.month = month + 1;
    cd.day = day + 1;
    if ( pyday != 0 )
        *pyday = yday;
        return(cd);
}

struct taitime tai2time(struct tai t,int32_t *pwday,int32_t *pyday)
{
    uint64_t u; int32_t leap,s; struct taitime ct;
    memset(&ct,0,sizeof(ct));
    ct.millis = fmod(t.millis,999.999999);
    //if ( First_TAI.x != 0 && t.x > First_TAI.x )
    //    t.x = (t.millis / 1000.) + First_TAI.x;
    leap = leapsecs_sub(&t);
    u = t.x;
    u += 58486; // was off by a minute (or 3?)
    s = u % 86400ULL;
    ct.second = (s % 60) + leap; s /= 60;
    ct.minute = s % 60; s /= 60;
    ct.hour = s;
    u /= 86400ULL;
    ct.date = taidate_frommjd((int32_t)(u - 53375995543064ULL),pwday,pyday);
    ct.offset = 0;
    // printf("origt.x %llu t.x %llu %3.3f -> %02d:%02d:%02d %3.3f\n",(long long)origt.x,(long long)t.x,t.millis,ct.second,ct.minute,ct.second,ct.millis);
    //printf("TAI millis: %lld -1st.%lld %f - %f -> %f | %f\n",(long long)t.x,(long long)First_TAI.x,t.millis,First_TAI.millis,t.millis-First_TAI.millis,ct.millis);
    return(ct);
}

struct taidate tai2date(struct tai t)
{
    struct taitime ct = tai2time(t,0,0);
    return(ct.date);
}

struct taitime taitime_set(struct taidate cd,int32_t hour,int32_t minute,int32_t seconds)
{
    struct taitime ct;
    memset(&ct,0,sizeof(ct));
    ct.date = cd;
    ct.hour = hour, ct.minute = minute, ct.second = seconds;
    return(ct);
}

/*int32_t taitime_scan(char *s,struct taitime *ct)
 {
 int32_t z,c,sign; char *t = s;
 t += taidate_scan(t,&ct->date);
 while ((*t == ' ') || (*t == '\t') || (*t == 'T')) ++t;
 z = 0; while ((c = (uint8_t) (*t - '0')) <= 9) { z = z * 10 + c; ++t; }
 ct->hour = z;
 if (*t++ != ':') return 0;
 z = 0; while ((c = (uint8_t) (*t - '0')) <= 9) { z = z * 10 + c; ++t; }
 ct->minute = z;
 if (*t != ':')
 ct->second = 0;
 else
 {
 ++t;
 z = 0; while ((c = (uint8_t) (*t - '0')) <= 9) { z = z * 10 + c; ++t; }
 ct->second = z;
 }
 while ((*t == ' ') || (*t == '\t')) ++t;
 if (*t == '+') sign = 1; else if (*t == '-') sign = -1; else return 0;
 ++t;
 c = (uint8_t) (*t++ - '0'); if (c > 9) return 0; z = c;
 c = (uint8_t) (*t++ - '0'); if (c > 9) return 0; z = z * 10 + c;
 c = (uint8_t) (*t++ - '0'); if (c > 9) return 0; z = z * 6 + c;
 c = (uint8_t) (*t++ - '0'); if (c > 9) return 0; z = z * 10 + c;
 ct->offset = z * sign;
 printf("t.%p s.%p\n",t,s);
 return((int32_t)((long)t - (long)s));
 }*/

int32_t taidate_str(char *s,struct taidate cd)
{
    int32_t x,len,i = 0;
    x = cd.year; if (x < 0) x = -x; do { ++i; x /= 10; } while(x);
    len = (cd.year < 0) + i + 6;
    if ( s != 0 )
    {
        x = cd.year;
        if (x < 0) { x = -x; *s++ = '-'; }
        s += i; do { *--s = '0' + (x % 10); x /= 10; } while(x); s += i;
        x = cd.month;
        s[0] = '-'; s[2] = '0' + (x % 10); x /= 10; s[1] = '0' + (x % 10);
        x = cd.day;
        s[3] = '-'; s[5] = '0' + (x % 10); x /= 10; s[4] = '0' + (x % 10);
        s[len] = 0;
    }
    return(len);
}

char *taitime_str(char *s,struct taitime ct)
{
    int32_t result,x,len;
    result = taidate_str(s,ct.date);
    len = result + 15;
    if ( s != 0 )
    {
        s += result;
        x = ct.hour;
        s[0] = ' ';
        s[2] = '0' + (x % 10); x /= 10;
        s[1] = '0' + (x % 10);
        s += 3;
        x = ct.minute;
        s[0] = ':';
        s[2] = '0' + (x % 10); x /= 10;
        s[1] = '0' + (x % 10);
        s += 3;
        x = ct.second;
        s[0] = ':';
        s[2] = '0' + (x % 10); x /= 10;
        s[1] = '0' + (x % 10);
        s += 3;
        s[0] = ' ';
        x = ct.offset;
        if (x < 0) { s[1] = '-'; x = -x; } else s[1] = '+';
        s[5] = '0' + (x % 10); x /= 10;
        s[4] = '0' + (x % 6); x /= 6;
        s[3] = '0' + (x % 10); x /= 10;
        s[2] = '0' + (x % 10);
        s[6] = 0;
    }
    return(s);
}

void tai_pack(char *s,struct tai *t)
{
    uint64_t x;
    x = t->x;
    s[7] = x & 255; x >>= 8;
    s[6] = x & 255; x >>= 8;
    s[5] = x & 255; x >>= 8;
    s[4] = x & 255; x >>= 8;
    s[3] = x & 255; x >>= 8;
    s[2] = x & 255; x >>= 8;
    s[1] = x & 255; x >>= 8;
    s[0] = x;
}

void tai_unpack(char *s,struct tai *t)
{
    uint64_t x;
    x = (uint8_t) s[0];
    x <<= 8; x += (uint8_t) s[1];
    x <<= 8; x += (uint8_t) s[2];
    x <<= 8; x += (uint8_t) s[3];
    x <<= 8; x += (uint8_t) s[4];
    x <<= 8; x += (uint8_t) s[5];
    x <<= 8; x += (uint8_t) s[6];
    x <<= 8; x += (uint8_t) s[7];
    t->x = x;
}

void tai_add(struct tai *t,struct tai *u,struct tai *v) { t->x = u->x + v->x; }

void tai_sub(struct tai *t,struct tai *u,struct tai *v) { t->x = u->x - v->x; }

// {"leapseconds":["+1972-06-30", "+1972-12-31", "+1973-12-31", "+1974-12-31", "+1975-12-31", "+1976-12-31", "+1977-12-31", "+1982-06-30", "+1983-06-30", "+1985-06-30", "+1987-12-31", "+1989-12-31", "+1990-12-31", "+1992-06-30", "+1993-06-30", "+1994-06-30", "+1995-12-31", "+1997-06-30", "+1998-12-31", "+2005-12-31", "+2008-12-31", "+2012-06-30", "+2015-06-30"]}
char *leapseconds[] = { "+1972-06-30", "+1972-12-31", "+1973-12-31", "+1974-12-31", "+1975-12-31", "+1976-12-31", "+1977-12-31", "+1982-06-30", "+1983-06-30", "+1985-06-30", "+1987-12-31", "+1989-12-31", "+1990-12-31", "+1992-06-30", "+1993-06-30", "+1994-06-30", "+1995-12-31", "+1997-06-30", "+1998-12-31", "+2005-12-31", "+2008-12-31", "+2012-06-30", "+2015-06-30",  "+2016-12-31" };
struct tai leaptais[sizeof(leapseconds)/sizeof(*leapseconds)];

char *dayname[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" } ;

static int32_t times365[4] = { 0, 365, 730, 1095 } ;
static int32_t times36524[4] = { 0, 36524, 73048, 109572 } ;
static int32_t montab[12] = { 0, 31, 61, 92, 122, 153, 184, 214, 245, 275, 306, 337 } ;
// month length after february is (306 * m + 5) / 10

int32_t taidate_mjd(struct taidate cd)
{
    int32_t y,m,d;
    d = cd.day - 678882L;
    m = cd.month - 1;
    y = cd.year;
    d += 146097L * (y / 400);
    y %= 400;
    if (m >= 2) m -= 2; else { m += 10; --y; }
    y += (m / 12);
    m %= 12;
    if (m < 0) { m += 12; --y; }
    d += montab[m];
    d += 146097L * (y / 400);
    y %= 400;
    if (y < 0) { y += 400; d -= 146097L; }
    d += times365[y & 3];
    y >>= 2;
    d += 1461L * (y % 25);
    y /= 25;
    d += times36524[y & 3];
    return d;
}

struct tai utc2tai(uint32_t timestamp) { struct tai t; memset(&t,0,sizeof(t)); t.x = (timestamp + TAI_UTC_DIFF); return(t); }

uint32_t tai2utc(struct tai t) { t.x -= TAI_UTC_DIFF; return((uint32_t)t.x); }

uint64_t tai2utime(struct tai t)
{
    uint64_t mjd; uint64_t timestamp; struct taitime ct = tai2time(t,0,0);
    mjd = taidate_mjd(ct.date);
    timestamp = ((uint64_t)(mjd * 24*3600 + ct.hour*3600 + ct.minute*60 + ct.second));
    return(timestamp);
}

struct tai tai_now()
{
    struct tai t; uint64_t now = time(NULL);
    t.x = TAI_UTC_DIFF + now;
    t.millis = OS_milliseconds() - First_TAI.millis;
    if ( First_TAI.x == 0 )
    {
        First_TAI = t, First_utc = (uint32_t)now;
#ifndef DISABLE_LEAPS
        UTC_ADJUST = -37;
#endif
        //printf("TAINOW.%llu %03.3f UTC.%u vs %u [diff %d]\n",(long long)t.x,t.millis,First_utc,tai2utc(t),UTC_ADJUST);
    }
    return(t);
}

struct tai leapsecs_add(struct tai t,int32_t hit)
{
#ifndef DISABLE_LEAPS
    int32_t i; uint64_t u;
    u = t.x;
    if ( t.x > leaptais[(sizeof(leaptais)/sizeof(*leaptais)) - 1].x )
        u += (sizeof(leaptais)/sizeof(*leaptais));//, printf("add leap.%ld\n",(sizeof(leaptais)/sizeof(*leaptais)));
    else
    {
        for (i=0; i<sizeof(leaptais)/sizeof(*leaptais); i++)
        {
            if ( u < leaptais[i].x )
                break;
            if ( hit == 0 || u > leaptais[i].x )
                u++;
        }
    }
    t.x = u;
#endif
    return(t);
}

struct tai taitime2tai(struct taitime ct)
{
    int32_t day,s; struct tai t;
    day = taidate_mjd(ct.date);
    s = ct.hour * 60 + ct.minute;
    s = (s - ct.offset) * 60 + ct.second;
    t.x = day * 86400ULL + 4611686014920671114ULL + (uint64_t)s;
    t.millis = ct.millis;
    return(leapsecs_add(t,ct.second == 60));
}

double tai_diff(struct tai reftai,struct tai cmptai)
{
    double diff;
    //char str[111],str2[111]; printf("start [%f %f] %s vs %s\n",reftai.millis,cmptai.millis,tai_str(str,reftai),tai_str(str2,cmptai));
    reftai = taitime2tai(tai2time(reftai,0,0));
    cmptai = taitime2tai(tai2time(cmptai,0,0));
    diff = (cmptai.x - reftai.x) * 1000. + (cmptai.millis - reftai.millis);
    //printf("%s vs %s -> diff [%d] %f [%llu - %llu]\n\n",tai_str(str,reftai),tai_str(str2,cmptai),(int32_t)(cmptai.x - reftai.x),diff,(long long)cmptai.x,(long long)reftai.x);
    return(diff);
}

struct tai taidate_scan(char *s,int32_t numleaps)
{
    int32_t z,c,sign = 1; char *t = s; struct taidate cd; struct tai st;
    st.x = 0;
    if (*t == '-') { ++t; sign = -1; }
    else if ( *t == '+' )
        t++;
    z = 0; while ((c = (uint8_t) (*t - '0')) <= 9) { z = z * 10 + c; ++t; }
    cd.year = z * sign;
    if (*t++ != '-') return(st);
    z = 0; while ((c = (uint8_t) (*t - '0')) <= 9) { z = z * 10 + c; ++t; }
    cd.month = z;
    if (*t++ != '-') return(st);
    z = 0; while ((c = (uint8_t) (*t - '0')) <= 9) { z = z * 10 + c; ++t; }
    cd.day = z;
    //printf("year.%d month.%d day.%d numleaps.%d\n",cd.year,cd.month,cd.day,numleaps);
    st.x = (taidate_mjd(cd) + 1) * 86400ULL + 4611686014920671114ULL + numleaps;
    return(st);
}

int32_t leapsecs_sub(struct tai *lt)
{
#ifndef DISABLE_LEAPS
    char out[101],x[TAI_PACK]; double packerr;
    int32_t weekday,yearday,i,j,s; uint64_t u; struct tai t,t2; struct taitime ct2;
    if ( leaptais[0].x == 0 )
    {
        for (i=0; i<sizeof(leapseconds)/sizeof(*leapseconds); i++)
        {
            t = taidate_scan(leapseconds[i],i);
            if ( t.x == 0 )
                printf("unable to parse.(%s)\n",leapseconds[i]);
            else
            {
                //t = taitime2tai(ct);
                leaptais[i] = t;
                ct2 = tai2time(t,&weekday,&yearday);
                tai_pack(x,&t);
                tai_unpack(x,&t2);
                tai_sub(&t2,&t2,&t);
                packerr = tai_approx(&t2);
                for (j=0; j<TAI_PACK; j++)
                    printf("%2.2x",(uint32_t)(uint8_t)x[j]);
                if ( packerr != 0 )
                    printf(" packerr=%f",packerr);
                taitime_str(out,ct2);
                printf(" %03d  %s %s",yearday,dayname[weekday],out);
                printf("\n");
            }
        }
    }
    u = lt->x;
    if ( u > leaptais[sizeof(leaptais)/sizeof(*leaptais)-1].x )
        lt->x -= (sizeof(leaptais)/sizeof(*leaptais) - 1);
    else
    {
        s = 0;
        for (i=0; i<sizeof(leaptais)/sizeof(*leaptais); i++)
        {
            if ( u < leaptais[i].x )
                break;
            ++s;
            if ( u == leaptais[i].x )
            {
                lt->x = u - s;
                return(1);
            }
        }
        lt->x = u - s;
    }
#endif
    return(0);
}

char *tai_str(char *str,struct tai t)
{
    struct taitime ct;
    ct = tai2time(t,0,0);
    sprintf(str,"%d-%02d-%02d %02d:%02d:%02d %03.3f",ct.date.year,ct.date.month,ct.date.day,ct.hour,ct.minute,ct.second,ct.millis);
    return(str);
}

/*char *utc_str(char *str,struct tai t)
{
    t.x += UTC_ADJUST;
    return(tai_str(str,t));
}*/

char *utc_str(char *str,uint32_t utc)
{
    struct taitime ct; struct tai t;
    t = utc2tai(utc);
    t.x += UTC_ADJUST;
    ct = tai2time(t,0,0);
    sprintf(str,"%d-%02d-%02dT%02d:%02d:%02dZ",ct.date.year,ct.date.month,ct.date.day,ct.hour,ct.minute,ct.second);
    return(str);
}

double OS_milliseconds()
{
    return(OS_portable_milliseconds());
}

int32_t calc_datenum(int32_t year,int32_t month,int32_t day)
{
    return((year * 10000) + (month * 100) + day);
}

int32_t extract_datenum(int32_t *yearp,int32_t *monthp,int32_t *dayp,int32_t datenum)
{
    *yearp = datenum / 10000, *monthp = (datenum / 100) % 100, *dayp = (datenum % 100);
    if ( *yearp >= 2000 && *yearp <= 2038 && *monthp >= 1 && *monthp <= 12 && *dayp >= 1 && *dayp <= 31 )
        return(datenum);
    else return(-1);
}

uint32_t OS_conv_datenum(int32_t datenum,int32_t hour,int32_t minute,int32_t second) // datenum+H:M:S -> unix time
{
    int32_t year,month,day; struct tai t; struct taitime ct;
    if ( 1 )
    {
        if ( extract_datenum(&year,&month,&day,datenum) > 0 )
        {
            ct = taitime_set(taidate_set(year,month,day),hour,minute,second);
            t = taitime2tai(ct);
            //char str[65]; printf("conv.(y%d m%d d%d %d:%d:%d) %s\n",year,month,day,hour,minute,second,tai_str(str,t));
            return((uint32_t)tai2utc(t));//tai2utime(t)+788250398LL - 4294967296LL);
        }
        return(0);
    }
    /*else
    {
#ifdef __PNACL
        return(0);
#else
        struct tm t;
        memset(&t,0,sizeof(t));
        t.tm_year = (datenum / 10000) - 1900, t.tm_mon = ((datenum / 100) % 100) - 1, t.tm_mday = (datenum % 100);
        t.tm_hour = hour, t.tm_min = minute, t.tm_sec = second;
        return((uint32_t)timegm(&t));
#endif
    }*/
}

int32_t OS_conv_unixtime(struct tai *tp,int32_t *secondsp,time_t timestamp) // gmtime -> datenum + number of seconds
{
    struct tai t; struct taitime ct;
    if ( 1 )
    {
        *tp = t = utc2tai((uint32_t)timestamp);
        ct = tai2time(t,0,0);
        *secondsp = (ct.hour*3600 + ct.minute*60 + ct.second);
        return(calc_datenum(ct.date.year,ct.date.month,ct.date.day));
    }
    /*else
    {
        struct tm tm,*ptr; int32_t datenum; uint32_t checktime; char buf[64];
        if ( (ptr= gmtime(&timestamp)) != 0 )
            tm = *ptr;;
        strftime(buf,sizeof(buf), "%Y-%m-%dT%H:%M:%SZ",&tm); //printf("%s\n",buf);
        datenum = conv_date(secondsp,buf);
        if ( (checktime= OS_conv_datenum(datenum,*secondsp/3600,(*secondsp%3600)/60,*secondsp%60)) != timestamp )
        {
            printf("error: timestamp.%u -> (%d + %d) -> %u\n",(uint32_t)timestamp,datenum,*secondsp,checktime);
            return(-1);
        }
        return(datenum);
    }*/
}

int32_t conv_date(int32_t *secondsp,char *date)
{
    char origdate[512],tmpdate[512]; int32_t year,month,day,hour,min,sec,len;
    safecopy(origdate,date,sizeof(origdate)), safecopy(tmpdate,date,sizeof(tmpdate)), tmpdate[8 + 2] = 0;
    year = atoi(tmpdate), month = atoi(tmpdate+5), day = atoi(tmpdate+8);
    *secondsp = 0;
    if ( (len= (int32_t)strlen(date)) <= 10 )
        hour = min = sec = 0;
    if ( len >= 18 )
    {
        tmpdate[11 + 2] = 0, tmpdate[14 + 2] = 0, tmpdate[17 + 2] = 0;
        hour = atoi(tmpdate+11), min = atoi(tmpdate + 14), sec = atoi(tmpdate+17);
        if ( hour >= 0 && hour < 24 && min >= 0 && min < 60 && sec >= 0 && sec < 60 )
            *secondsp = (3600*hour + 60*min + sec);
        else printf("ERROR: seconds.%d %d %d %d, len.%d\n",*secondsp,hour,min,sec,len);
        //printf("(%s) -> Y.%d M.%d D.%d %d:%d:%d\n",date,year,month,day,hour,min,sec);
    } //else printf("short len.(%s) from (%s)\n",date,origdate);
    sprintf(origdate,"%d-%02d-%02d",year,month,day); //2015-07-25T22:34:31Z
    if ( strcmp(tmpdate,origdate) != 0 )
    {
        printf("conv_date date conversion error (%s) -> (%s)\n",origdate,date);
        return(-1);
    }
    return((year * 10000) + (month * 100) + day);
}

uint32_t OS_conv_utime(char *utime)
{
    int32_t datenum,seconds;
    datenum = conv_date(&seconds,utime);
    return((uint32_t)OS_conv_datenum(datenum,seconds/3600,(seconds%3600)/60,seconds%60));
}

int32_t expand_datenum(char *date,int32_t datenum)
{
    int32_t year,month,day; date[0] = 0;
    if ( extract_datenum(&year,&month,&day,datenum) != datenum)
        return(-1);
    sprintf(date,"%d-%02d-%02d",year,month,day);
    return(0);
}

int32_t ecb_decrdate(int32_t *yearp,int32_t *monthp,int32_t *dayp,char *date,int32_t datenum)
{
    static int lastday[13] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    int32_t year,month,day;
    year = datenum / 10000, month = (datenum / 100) % 100, day = (datenum % 100);
    //printf("%d -> %d %d %d\n",datenum,year,month,day);
    if ( --day <= 0 )
    {
        if ( --month <= 0 )
        {
            if ( --year < 2000 )
            {
                printf("reached epoch start\n");
                return(-1);
            }
            month = 12;
        }
        day = lastday[month];
        if ( month == 2 && (year % 4) == 0 )
            day++;
    }
    sprintf(date,"%d-%02d-%02d",year,month,day);
    //printf("%d -> %d %d %d (%s)\n",datenum,year,month,day,date);
    *yearp = year, *monthp = month, *dayp = day;
    return((year * 10000) + (month * 100) + day);
}

#ifdef ENABLE_TEST
#include <unistd.h>
int main(int argc, const char * argv[])
{
    int i; char str[111],str2[111],str3[111],str4[111]; struct taitime ct;
    struct tai t,start = tai_now();
    for (i=0; i<100; i++)
    {
        sleep(1);
        t = tai_now();
        taidate_str(str2,tai2date(t));
        printf("(%s) time.%s date.%s %ld start.%ld %s %u %u\n",tai_str(str3,t),taitime_str(str,ct),str2,(long)tai2utime(t),(long)tai2utime(start),utime_str(str4,t),tai2utc(t),(uint32_t)time(NULL));
    }
    // insert code here...
    {
        char str[65]; struct tai t; double startmillis; int32_t datenum,seconds; uint64_t i,checkval,timestamp,now = (uint32_t)time(NULL);
        startmillis = OS_milliseconds();
        for (i=0; i<1000000; i++)
        {
            timestamp = now - (rand() % 100000000LL); // range -100000000LL to +500000000LL
            datenum = OS_conv_unixtime(&t,&seconds,timestamp); // gmtime -> datenum + number of seconds
            checkval = OS_conv_datenum(datenum,seconds/3600,(seconds/60)%60,seconds%60); // datenum+H:M:S -> unix time
            if ( checkval != timestamp )
                printf("%s i.%lld timestamp.%-12llu -> (%d:%06d) -> checkval.%-12llu diff.[%lld]\n",tai_str(str,t),(long long)i,(long long)timestamp,datenum,seconds,(long long)checkval,(long long)(timestamp-checkval));
        }
        printf("million tai compares in %.3f microseconds per encode/decode\n",1000. * (OS_milliseconds()-startmillis)/i);
    }
   /* struct tai t = tai_now(); double diff,lastdiff = 0.;
    for (i=0; i<1000000; i++)
    {
        diff = tai_diff(t,tai_now());
        if ( diff < lastdiff )
            printf("embargo.x %f %llu.%3.3f %llu.%3.3f\n",tai_diff(t,tai_now()),(long long)t.x,t.millis,(long long)tai_now().x,tai_now().millis);
        lastdiff = diff;
        //usleep(100000);
    } getchar();
*/
    return 0;
}
#endif
